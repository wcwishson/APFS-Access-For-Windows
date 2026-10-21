#pragma once
#include "EncryptedImageRuntime.h"
#include <tlhelp32.h>
#include <thread>
#include <mutex>

namespace apfsaccess::transport
{
class KeyManagementProcessLease final
{
    struct Handle {
        HANDLE value = INVALID_HANDLE_VALUE;
        explicit Handle(HANDLE v) : value(v) {}
        Handle(Handle&& v) noexcept : value(std::exchange(v.value, INVALID_HANDLE_VALUE)) {}
        ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    };
public:
    KeyManagementProcessLease(DWORD parent, const std::filesystem::path& lifetime,
        const std::filesystem::path& gate, const std::string& token,
        const std::filesystem::path& receipt)
        : parent_(OpenProcess(SYNCHRONIZE, FALSE, parent))
    {
        if (!parent || parent == GetCurrentProcessId() || ActualParent() != parent ||
            token.size() != 32 || token.find_first_not_of("0123456789abcdef") != token.npos ||
            lifetime.parent_path() != gate.parent_path() || lifetime.parent_path() != receipt.parent_path() ||
            lifetime.filename() != L"lifetime" || receipt.filename() != L"receipt.json" ||
            !GateName(gate.filename().wstring()))
            throw std::runtime_error("KeyManagementSupervisionInvalid");
        PinDirectory(lifetime.parent_path());
        lifetime_.value = CreateFileW(lifetime.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (!Alive()) throw std::runtime_error("KeyManagementOwnerAbsent");
        const auto deadline = GetTickCount64() + 10000;
        bool authorized = false;
        while (Alive() && GetTickCount64() < deadline) {
            {
                Handle file{CreateFileW(gate.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
                if (!Regular(file.value)) throw std::runtime_error("KeyManagementStartupGateInvalid");
                std::array<char, 33> bytes{}; DWORD count = 0;
                if (ReadFile(file.value, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) &&
                    count == token.size() && std::equal(token.begin(), token.end(), bytes.begin())) authorized = true;
            }
            if (authorized) break;
            Sleep(5);
        }
        if (!authorized || !Alive() || !DeleteFileW(gate.c_str())) throw std::runtime_error("KeyManagementStartupNotAuthorized");
        receipt_.value = CreateFileW(receipt.c_str(), GENERIC_WRITE | FILE_READ_ATTRIBUTES, 0, nullptr, CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr);
        if (!Regular(receipt_.value)) throw std::runtime_error("KeyManagementReceiptUnavailable");
        deadline_ = GetTickCount64() + 300000;
        monitor_ = std::jthread([this](std::stop_token stop) {
            while (!stop.stop_requested()) {
                if (!Alive() || GetTickCount64() >= deadline_) cancelled.store(true);
                if (cancelled.load()) { std::lock_guard lock(runtime_gate_); if (runtime_) runtime_->Cancel(); }
                Sleep(5);
            }
        });
    }
    void Attach(catalog::EncryptedImageRuntime* runtime)
    {
        std::lock_guard lock(runtime_gate_); runtime_ = runtime;
        if (runtime_ && cancelled.load()) runtime_->Cancel();
    }
    void Receipt(const std::string& bytes)
    {
        if (cancelled.load() || bytes.empty() || bytes.size() > 16384) throw std::runtime_error("KeyManagementReceiptRefused");
        DWORD done = 0;
        if (!WriteFile(receipt_.value, bytes.data(), static_cast<DWORD>(bytes.size()), &done, nullptr) ||
            done != bytes.size() || !FlushFileBuffers(receipt_.value)) throw std::runtime_error("KeyManagementReceiptFlushFailed");
    }
    std::atomic<bool> cancelled{false};
private:
    static bool GateName(const std::wstring& name)
    {
        return name.size() == 45 && name.starts_with(L"startup_") && name.ends_with(L".gate") &&
            name.substr(8, 32).find_first_not_of(L"0123456789abcdef") == name.npos;
    }
    static DWORD ActualParent()
    {
        Handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
        PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry);
        if (snapshot.value != INVALID_HANDLE_VALUE && Process32FirstW(snapshot.value, &entry)) do {
            if (entry.th32ProcessID == GetCurrentProcessId()) return entry.th32ParentProcessID;
        } while (Process32NextW(snapshot.value, &entry));
        return 0;
    }
    static bool Regular(HANDLE file)
    {
        FILE_ATTRIBUTE_TAG_INFO tag{}; FILE_STANDARD_INFO standard{};
        return file && file != INVALID_HANDLE_VALUE && GetFileType(file) == FILE_TYPE_DISK &&
            GetFileInformationByHandleEx(file, FileAttributeTagInfo, &tag, sizeof(tag)) &&
            !(tag.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE)) &&
            GetFileInformationByHandleEx(file, FileStandardInfo, &standard, sizeof(standard)) &&
            !standard.DeletePending && !standard.Directory && standard.NumberOfLinks == 1;
    }
    bool Alive() const { return parent_.value && WaitForSingleObject(parent_.value, 0) == WAIT_TIMEOUT && Regular(lifetime_.value); }
    void PinDirectory(const std::filesystem::path& path)
    {
        const auto text = path.wstring();
        if (text.size() < 4 || text.size() > 220 || text[1] != L':' || text[2] != L'\\' ||
            !((text[0] >= L'A' && text[0] <= L'Z') || (text[0] >= L'a' && text[0] <= L'z')) ||
            text.find_first_of(L":/<>|\"?*", 3) != text.npos ||
            std::any_of(text.begin(), text.end(), [](wchar_t c) { return c < 32; }))
            throw std::runtime_error("KeyManagementDirectoryInvalid");
        for (std::size_t end = 2;;) {
            const auto prefix = text.substr(0, end == 2 ? 3 : end);
            if (end != 2) {
                const auto part = std::filesystem::path(prefix).filename().wstring();
                if (part.empty() || part == L"." || part == L".." || part.back() == L'.' || part.back() == L' ')
                    throw std::runtime_error("KeyManagementDirectoryInvalid");
            }
            Handle held{CreateFileW(prefix.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
            FILE_ATTRIBUTE_TAG_INFO info{};
            if (held.value == INVALID_HANDLE_VALUE || GetDriveTypeW(text.substr(0, 3).c_str()) != DRIVE_FIXED ||
                !GetFileInformationByHandleEx(held.value, FileAttributeTagInfo, &info, sizeof(info)) ||
                (info.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != FILE_ATTRIBUTE_DIRECTORY)
                throw std::runtime_error("KeyManagementDirectoryInvalid");
            directories_.push_back(std::move(held));
            if (end == text.size()) break;
            end = text.find(L'\\', end == 2 ? 3 : end + 1);
            if (end == text.npos) end = text.size();
        }
    }
    std::vector<Handle> directories_;
    Handle parent_{INVALID_HANDLE_VALUE}, lifetime_{INVALID_HANDLE_VALUE}, receipt_{INVALID_HANDLE_VALUE};
    ULONGLONG deadline_ = 0;
    std::mutex runtime_gate_;
    catalog::EncryptedImageRuntime* runtime_ = nullptr;
    std::jthread monitor_;
};
}
