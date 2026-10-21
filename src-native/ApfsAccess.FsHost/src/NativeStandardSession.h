#pragma once
#include "NativeStandardCallbacks.h"

namespace native_standard
{
class Pipe
{
    HANDLE reader_ = GetStdHandle(STD_INPUT_HANDLE), writer_ = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE parent_ = nullptr, thread_ = nullptr;
    const Arguments& arguments_;
    std::atomic<bool> stop_{false}, expired_{false};
    std::atomic<ULONGLONG> write_deadline_{0};
    std::thread watchdog_;
public:
    Pipe(const Arguments& arguments, HANDLE parent) : parent_(parent), arguments_(arguments)
    {
        if (GetFileType(reader_) != FILE_TYPE_PIPE || GetFileType(writer_) != FILE_TYPE_PIPE ||
            !DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &thread_, THREAD_TERMINATE, FALSE, 0))
            throw std::runtime_error("StandardTransportBytePipesRequired");
        try
        {
            watchdog_ = std::thread([this] {
                while (!stop_.load(std::memory_order_acquire))
                {
                    const auto deadline = write_deadline_.load(std::memory_order_acquire);
                    if (deadline && GetTickCount64() >= deadline)
                    {
                        expired_.store(true, std::memory_order_release);
                        (void)CancelSynchronousIo(thread_);
                    }
                    Sleep(20);
                }
            });
        }
        catch (...) { CloseHandle(thread_); thread_ = nullptr; throw; }
    }
    ~Pipe()
    {
        stop_.store(true, std::memory_order_release);
        if (watchdog_.joinable()) watchdog_.join();
        if (thread_) CloseHandle(thread_);
    }
    bool Read(std::span<std::byte> bytes, bool idle = false)
    {
        auto deadline = idle ? 0ull : GetTickCount64() + 5000;
        std::size_t offset = 0;
        while (offset < bytes.size())
        {
            if (expired_.load(std::memory_order_acquire) || g_exit.load() || !OwningParentIsAlive(parent_) ||
                !LifetimeFileExists(arguments_) || (deadline && GetTickCount64() >= deadline)) return false;
            DWORD available = 0;
            if (!PeekNamedPipe(reader_, nullptr, 0, nullptr, &available, nullptr)) return false;
            if (!available) { Sleep(10); continue; }
            if (!deadline) deadline = GetTickCount64() + 5000;
            const auto count = static_cast<DWORD>((std::min)(bytes.size() - offset, std::size_t(available)));
            DWORD done = 0;
            if (!ReadFile(reader_, bytes.data() + offset, count, &done, nullptr) || !done) return false;
            offset += done;
        }
        return true;
    }
    bool Write(const wire::Header& header, std::span<const std::byte> payload)
    {
        if (payload.size() != header.payload_bytes || payload.size() > wire::MaximumFrameBytes - wire::HeaderBytes ||
            expired_.load(std::memory_order_acquire)) return false;
        const auto encoded = wire::EncodeHeader(header);
        write_deadline_.store(GetTickCount64() + 5000, std::memory_order_release);
        ScopeExit clear_deadline{[&] { write_deadline_.store(0, std::memory_order_release); }};
        for (const auto part : {std::span<const std::byte>(encoded), payload})
        {
            std::size_t offset = 0;
            while (offset < part.size())
            {
                if (expired_.load(std::memory_order_acquire)) return false;
                const auto count = static_cast<DWORD>((std::min)(part.size() - offset, wire::MaximumIoBytes));
                DWORD done = 0;
                if (!WriteFile(writer_, part.data() + offset, count, &done, nullptr) || !done) return false;
                offset += done;
            }
        }
        return !expired_.load(std::memory_order_acquire);
    }
};

HANDLE ParentToken(const Arguments& arguments, HANDLE parent)
{
    if (!OwningParentIsAlive(parent)) return nullptr;
    const auto process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, arguments.parent_pid);
    if (!process) return nullptr;
    ScopeExit release_process{[&] { CloseHandle(process); }};
    HANDLE primary = nullptr, impersonation = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &primary)) return nullptr;
    ScopeExit release_token{[&] { CloseHandle(primary); }};
    if (!OwningParentIsAlive(parent) ||
        !DuplicateTokenEx(primary, TOKEN_QUERY | TOKEN_IMPERSONATE, nullptr, SecurityImpersonation, TokenImpersonation, &impersonation))
        return nullptr;
    return impersonation;
}

int Run(std::unique_ptr<MountContext>& owner, HANDLE parent)
{
#ifndef APFSACCESS_HAS_RW_ENGINE
    (void)owner; (void)parent; return 6;
#else
    auto& context = *owner;
    bool drained = false;
    ScopeExit ensure_drain{[&] { if (!drained) { drained = true; (void)RunFsHostShutdownDrain(owner); } }};
    if (context.fs || !context.metadata_store || !context.tx_manager || !context.payload_spool ||
        !context.metadata_store->AuthoritativeAppleCheckpointView() ||
        !context.metadata_store->Device().IsRegularFile() || !IsNativeWriteEnabled(&context) ||
        !IsMutationWriteEnabled(&context) || !PrepareLifetimeFile(context.args)) return 28;
    auto* const device = &context.metadata_store->Device();
    const auto source = device->CaptureExclusiveWriteSourceObservation();
    std::string file_identity;
    if (!source || !context.metadata_store->Device().QueryRegularImageIdentity(file_identity)) return 28;
    const auto* checkpoint = context.metadata_store->AuthoritativeAppleCheckpointView();
    const auto selected = std::find_if(checkpoint->volumes.begin(), checkpoint->volumes.end(), [&](const auto& volume) {
        return volume.superblock.object_id == context.args.volume_object_id;
    });
    if (selected == checkpoint->volumes.end()) return 28;
    const auto volume_identity = L"apfs-vol:" + Utf8ToWide(checkpoint->container.superblock.uuid_hex) + L":" +
        std::to_wstring(selected->superblock.object_id) + L":" + Utf8ToWide(selected->superblock.uuid_hex);
    const auto token = ParentToken(context.args, parent);
    if (!token) return 28;
    ScopeExit release_token{[&] { CloseHandle(token); }};
    GUID guid{};
    if (FAILED(CoCreateGuid(&guid))) return 28;
    wire::Epoch epoch{}; memcpy(epoch.data(), &guid, epoch.size());
    bool stop_requested = false, broken = false;
    wire::Header last{};
    NTSTATUS close_status = STATUS_SUCCESS;
    try
    {
        Pipe pipe(context.args, parent);
        Callbacks callbacks(context, epoch, token);
        Bytes hello;
        Text(hello, Utf8ToWide(file_identity)); Text(hello, volume_identity);
        Number(hello, checkpoint->container.superblock.xid, 8);
        Number(hello, Features(context), 8);
        if (!pipe.Write({wire::Operation::Hello, static_cast<std::uint32_t>(hello.size()), 0, epoch}, hello)) return 28;
        std::uint64_t previous = 0;
        while (!g_exit.load())
        {
            std::array<std::byte, wire::HeaderBytes> encoded{};
            if (!pipe.Read(encoded, true)) break;
            if (!wire::DecodeHeader(encoded, last) || !last.request_id || last.request_id != previous + 1 ||
                last.operation == wire::Operation::Hello) { broken = true; break; }
            previous = last.request_id;
            if (last.operation == wire::Operation::Stop)
            {
                if (last.payload_bytes || last.epoch != epoch) broken = true;
                else stop_requested = true;
                break;
            }
            Bytes payload(last.payload_bytes);
            if (!pipe.Read(payload)) { broken = true; break; }
            bool current_source = false;
            {
                // Write observations end at the next admission. Each callback obtains
                // its own transaction authority against this unchanged exclusive image.
                std::lock_guard commit(context.commit_mutex);
                std::string current_identity;
                current_source = &context.metadata_store->Device() == device &&
                    device->CaptureExclusiveWriteSourceObservation().has_value() &&
                    device->QueryRegularImageIdentity(current_identity) && current_identity == file_identity;
            }
            if (!current_source)
            {
                std::wcerr << L"[FsHost] Standard transport source ownership changed at request " << last.request_id << std::endl;
                broken = true; break;
            }
            auto reply = callbacks.Invoke(last, payload);
            if (reply.bytes.size() > wire::MaximumFrameBytes - wire::HeaderBytes - 32) { broken = true; break; }
            Bytes response;
            response.reserve(32 + reply.bytes.size());
            Number(response, static_cast<std::uint32_t>(reply.status), 4); Number(response, reply.file_status, 4);
            Number(response, reply.granted, 4); Number(response, reply.count, 4); Number(response, reply.handle, 8);
            Number(response, reply.bytes.size(), 4); Number(response, 0, 4);
            response.insert(response.end(), reply.bytes.begin(), reply.bytes.end());
            if (!pipe.Write({last.operation, static_cast<std::uint32_t>(response.size()), last.request_id, epoch}, response))
            { broken = true; break; }
        }
        close_status = callbacks.CloseAll();
        if (!WriteHostStatusFile(context, context.recovery_active, context.metadata_store->LastCommittedXid()))
            broken = true;
        drained = true;
        const auto shutdown = RunFsHostShutdownDrain(owner);
        const auto marks = context.tx_manager->Watermarks();
        const bool clean = shutdown == 0 && NT_SUCCESS(close_status) && !callbacks.Failed() &&
            context.tx_manager->RecoveryStateValid() && marks.accepted_sequence == marks.apfs_durable_sequence &&
            marks.apfs_durable_sequence == marks.cleanup_sequence && !context.metadata_store->PendingMutationCount();
        if (stop_requested)
        {
            Bytes terminal;
            Number(terminal, marks.accepted_sequence, 8); Number(terminal, marks.apfs_durable_sequence, 8);
            Number(terminal, marks.cleanup_sequence, 8); Number(terminal, clean ? 1 : 0, 4);
            Number(terminal, clean ? 0u : static_cast<std::uint32_t>(STATUS_IO_DEVICE_ERROR), 4);
            if (!pipe.Write({wire::Operation::Stop, static_cast<std::uint32_t>(terminal.size()), last.request_id, epoch}, terminal)) broken = true;
        }
        return shutdown ? shutdown : !clean || broken ? 28 : 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "[FsHost] Standard transport request " << last.request_id << " failed: " << error.what() << std::endl;
        return 28;
    }
    catch (...)
    {
        std::wcerr << L"[FsHost] Standard transport request " << last.request_id << L" failed unexpectedly" << std::endl;
        return 28;
    }
#endif
}
}
