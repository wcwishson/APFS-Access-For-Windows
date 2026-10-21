#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include "EncryptedImageRuntime.h"
#include "EncryptedReadTransport.h"
#include "InodeMetadataPatch.h"
#include <algorithm>
#include <iostream>
#include <stdexcept>

namespace c = apfsaccess::catalog;
namespace r = apfsaccess::rw;
namespace t = apfsaccess::transport;
unsigned checks = 0;
struct InputBytes : std::vector<std::byte>
{
    ~InputBytes() { SecureZeroMemory(data(), size()); }
    std::span<std::byte> Bytes() { return *this; }
    std::size_t Size() const { return size(); }
    void Clear() { SecureZeroMemory(data(), size()); clear(); }
};
void Require(bool ok, const std::string& message)
{ ++checks; if (!ok) throw std::runtime_error(message); }

int wmain(int argc, wchar_t** argv)
{
    std::string error;
    try {
        Require(argc >= 3 && argc <= 5, "image, recovery root, optional cut or reopen mode");
        const std::wstring mode = argc >= 4 ? argv[3] : L"";
        std::string cut;
        if (argc == 5) for (const auto ch : std::wstring_view(argv[4])) {
            Require(ch >= 32 && ch <= 126, "ASCII hook name"); cut.push_back(static_cast<char>(ch));
        }
        c::EncryptedImageRuntime::Options options;
        options.image = {std::filesystem::absolute(argv[1]).wstring(), 20480, 4153344, 1026};
        options.recovery_directory = std::filesystem::absolute(argv[2]);
        auto runtime = c::EncryptedImageRuntime::Open(options, error);
        Require(static_cast<bool>(runtime), "Open:" + error);
        std::atomic<bool> cancelled = false;
        auto credential = t::ReceiveCredential(GetStdHandle(STD_INPUT_HANDLE), std::chrono::seconds(5), cancelled);
        SetStdHandle(STD_INPUT_HANDLE, nullptr);
        Require(static_cast<bool>(credential), "credential transport");
        c::PasswordUnlockBudget budget;
        Require(runtime->Unlock(credential.bytes, budget, error), "Unlock:" + error);
        const auto initial = runtime->CachedStatus();
        Require(initial.image.phase == c::EncryptedImageWritePhase::Ready, "ready owner");
        constexpr std::string_view name = "continuation-runtime-canary.bin";
        std::uint64_t inode = 0;
        c::EncryptedReadError read_error{};
        const auto find = [&] {
            auto view = runtime->OpenReadView(read_error); Require(static_cast<bool>(view), "read view");
            c::EncryptedDirectoryEntry entry;
            Require(view->Lookup(2, name, entry) == c::EncryptedReadError::None, "exact canary lookup");
            inode = entry.inode_id;
            view->Close();
        };
        // Caller input is not an additional locked persistence buffer. The
        // production spool and replay consumer own their locked staging.
        InputBytes payload; payload.resize(65536);
        for (std::size_t n = 0; n < payload.Size(); ++n) payload.Bytes()[n] = std::byte((n * 19 + n / 4096 + 37) % 251);
        const auto clean = [&] {
            const auto s = runtime->CachedStatus();
            Require(runtime->CachedPersistenceStateValid() && s.accepted && s.accepted == s.durable && s.durable == s.cleaned && !s.recovery_required,
                "complete original/witness/spool clean state");
            return s;
        };
        const auto metadata = [&](unsigned n, const r::AppleCheckpointStageHook& hook = {}) {
            r::InodeMetadataPatch patch; patch.mask = r::InodeMetadataPatch::Mode; patch.mode = n % 2 ? 0640 : 0600;
            std::vector<std::byte> bytes; Require(r::EncodeInodeMetadataPatch(patch, bytes), "canonical metadata");
            c::EncryptedMutationRequest request; request.kind = c::EncryptedMutationKind::SetInodeMetadata; request.inode = inode; request.data = bytes;
            std::uint64_t result = 0; const auto ok = runtime->Apply(request, result, error, hook);
            SecureZeroMemory(bytes.data(), bytes.size());
            return ok;
        };
        if (mode != L"--reopen") {
            c::EncryptedMutationRequest request; request.kind = c::EncryptedMutationKind::Create; request.parent = 2; request.name = name;
            const std::array one{std::byte{0x43}}; request.data = one;
            Require(runtime->Apply(request, inode, error), "nonempty Create:" + error); clean();
            request = {}; request.kind = c::EncryptedMutationKind::Write; request.inode = inode; request.data = payload.Bytes();
            std::uint64_t result = 0;
            Require(runtime->Apply(request, result, error), "64KiB spool Write:" + error); clean();
            for (unsigned n = 0; n < 6; ++n) { Require(metadata(n), "seed metadata:" + error); clean(); }
            const auto before = clean();
            bool saw = false;
            const auto hook = [&](std::string_view stage) {
                if (stage.starts_with("continuation-")) std::cout << "STAGE " << stage << '\n' << std::flush;
                if (!cut.empty() && stage == cut) { saw = true; return false; }
                return true;
            };
            const auto ok = metadata(6, hook);
            if (!cut.empty()) {
                Require(!ok && saw, "requested continuation cut reached:" + error);
                const auto after = runtime->CachedStatus();
                Require(after.accepted == before.accepted && after.cleaned == before.cleaned &&
                    after.image.checkpoint_xid == before.image.checkpoint_xid, "cut preserves APFS endpoint and original acceptance identity");
                runtime->Close(); std::cout << "PASS cut " << cut << " checks=" << checks << '\n'; return 0;
            }
            Require(ok, "first continuation and next actual mutation:" + error); clean();
            for (unsigned n = 7; n < 16; ++n) { Require(metadata(n), "second generation mutation:" + error); clean(); }
            Require(std::filesystem::exists(options.recovery_directory / L"original.wal.jcont.ready"), "durable finite frontier exists");
            runtime->Close(); runtime.reset();
            runtime = c::EncryptedImageRuntime::Open(options, error); Require(static_cast<bool>(runtime), "fresh keyless continuation Open:" + error);
            c::PasswordUnlockBudget reopened_budget;
            Require(runtime->Unlock(credential.bytes, reopened_budget, error), "fresh unlock:" + error);
        }
        find(); Require(inode != 0, "exact canary file retained");
        auto view = runtime->OpenReadView(read_error); Require(static_cast<bool>(view), "reopened view");
        std::vector<std::byte> actual;
        Require(view->ReadFile(inode, 0, payload.Size(), actual) == c::EncryptedReadError::None &&
            std::equal(actual.begin(), actual.end(), payload.Bytes().begin(), payload.Bytes().end()), "exact payload after reset/reopen");
        SecureZeroMemory(actual.data(), actual.size()); view->Close();
        const auto before = clean();
        Require(metadata(18), "actual reuse after fresh reopen:" + error);
        const auto after = clean(); Require(after.accepted > before.accepted && after.cleaned > before.cleaned &&
            after.image.checkpoint_xid == before.image.checkpoint_xid + 1, "monotonic IDs and endpoint after reuse");
        runtime->Close(); credential.bytes.Clear(); payload.Clear();
        std::cout << "PASS actual protected continuation, spool reclaim, fresh owner and reuse checks=" << checks << '\n'; return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << " detail=" << error << '\n'; return 1; }
}
