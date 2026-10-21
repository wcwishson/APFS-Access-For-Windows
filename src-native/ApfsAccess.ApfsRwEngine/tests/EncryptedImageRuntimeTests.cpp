#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#undef CreateFile
#include "EncryptedImageRuntime.h"
#include "EncryptedReadTransport.h"
#include <algorithm>
#include <atomic>
#include <filesystem>
#include <iostream>
#include <map>
#include <stdexcept>
#include <thread>

namespace c = apfsaccess::catalog;
namespace r = apfsaccess::rw;
namespace t = apfsaccess::transport;
using Runtime = c::EncryptedImageRuntime;
unsigned checks = 0;
void Check(bool value, const std::string& reason)
{ ++checks; if (!value) throw std::runtime_error(reason); }
struct Bytes : std::vector<std::byte>
{ ~Bytes() { if (!empty()) SecureZeroMemory(data(), size()); } };
std::array<std::uint8_t, 32> Digest(std::span<const std::byte> data)
{
    std::array<std::uint8_t, 32> result{};
    Check(data.size() <= ULONG_MAX && BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(data.data())), static_cast<ULONG>(data.size()),
        result.data(), static_cast<ULONG>(result.size())) >= 0, "Hash");
    return result;
}
struct Fact { std::uint64_t size; std::uint16_t mode; std::array<std::uint8_t, 32> hash; };
std::map<std::uint64_t, Fact> Inventory(Runtime& runtime)
{
    c::EncryptedReadError error{}; auto view = runtime.OpenReadView(error);
    Check(static_cast<bool>(view), "InventoryView");
    std::vector<c::EncryptedFileInfo> files;
    Check(view->ListFiles(files) == c::EncryptedReadError::None, "InventoryFiles");
    std::map<std::uint64_t, Fact> result;
    for (const auto& file : files) {
        Check(file.size <= (2ull << 20), "FixtureFileBound");
        Bytes bytes;
        for (std::uint64_t at = 0; at < file.size;) {
            Bytes chunk;
            const auto n = static_cast<std::size_t>((std::min)(file.size - at, 65536ull));
            Check(view->ReadFile(file.inode_id, at, n, chunk) == c::EncryptedReadError::None && chunk.size() == n, "InventoryRead");
            bytes.insert(bytes.end(), chunk.begin(), chunk.end()); at += n;
        }
        c::EncryptedNodeInfo metadata;
        Check(view->GetMetadata(file.inode_id, metadata) == c::EncryptedReadError::None, "InventoryMetadata");
        result.emplace(file.inode_id, Fact{file.size, metadata.mode, Digest(bytes)});
    }
    view->Close();
    return result;
}
#include "EncryptedImageRuntimeNamespaceCases.h"
int wmain(int argc, wchar_t** argv)
{
    std::string error;
    try {
        Check(argc == 3 || argc == 4, "Arguments:image,recovery-directory,[cut-mode]");
        const auto mode = argc == 4 ? std::wstring_view(argv[3]) : std::wstring_view{};
        Check(mode.empty() || mode == L"--spool-cut" || mode == L"--recover-spool-cut" ||
            mode == L"--spool-64k-cut" || mode == L"--recover-spool-64k-cut" ||
            mode == L"--durable-cut" || mode == L"--recover-durable-cut" ||
            mode == L"--namespace" || mode == L"--namespace-cut" || mode == L"--recover-namespace-cut" ||
            mode == L"--metadata-cut" || mode == L"--recover-metadata-cut", "KnownCutMode");
        Runtime::Options options;
        options.image = {std::filesystem::absolute(argv[1]).wstring(), 20480, 4153344, 1026};
        options.recovery_directory = std::filesystem::absolute(argv[2]);
        auto runtime = Runtime::Open(options, error);
        Check(static_cast<bool>(runtime), "RuntimeOpen:" + error);
        Check(runtime->CachedStatus().image.phase == c::EncryptedImageWritePhase::Locked &&
            (mode.starts_with(L"--recover-") || !runtime->CachedStatus().accepted), "InitialLocked");
        c::EncryptedReadError read_error{};
        Check(!runtime->OpenReadView(read_error), "LockedReadRefused");
        std::atomic<bool> cancelled{false};
        auto credential = t::ReceiveCredential(GetStdHandle(STD_INPUT_HANDLE), std::chrono::seconds(5), cancelled);
        SetStdHandle(STD_INPUT_HANDLE, nullptr);
        Check(static_cast<bool>(credential), "Credential");
        c::PasswordUnlockBudget budget;
        Check(runtime->Unlock(credential.bytes, budget, error), "RuntimeUnlock:" + error);
        if (mode == L"--durable-cut" || mode == L"--recover-durable-cut") {
            const std::array payload{std::byte{0x41},std::byte{0x52},std::byte{0x63}};
            if (mode == L"--durable-cut") {
                c::EncryptedMutationRequest request;request.kind=c::EncryptedMutationKind::Write;
                request.inode=21;request.data=payload;
                std::uint64_t inode=999;bool cut=false;
                Check(!runtime->Apply(request,inode,error,[&](std::string_view stage) {
                    if(stage=="before-encrypted-cleanup"){cut=true;return false;}return true;
                }) && cut && !inode,"DurableCleanupCut");
                const auto status=runtime->CachedStatus();
                Check(status.accepted && status.accepted==status.durable && status.cleaned<status.durable &&
                    status.recovery_required && runtime->CachedPersistenceStateValid() &&
                    status.image.checkpoint_xid==8,"TruthfulDurableCutCounters");
            } else {
                auto view=runtime->OpenReadView(read_error);Check(static_cast<bool>(view),"DurableRecoveryView");
                Bytes actual;Check(view->ReadFile(21,0,payload.size(),actual)==c::EncryptedReadError::None &&
                    std::equal(actual.begin(),actual.end(),payload.begin(),payload.end()),"DurableRecoveredBytes");
                view->Close();const auto status=runtime->CachedStatus();
                Check(status.accepted && status.accepted==status.durable && status.durable==status.cleaned &&
                    !status.recovery_required && status.image.checkpoint_xid==8,"DurableRecoveryClean");
            }
            const auto status=runtime->CachedStatus();credential.bytes.Clear();runtime->Close();
            std::cout<<"{\"status\":\"PASS\",\"checks\":"<<checks<<",\"accepted\":"<<status.accepted
                <<",\"durable\":"<<status.durable<<",\"cleaned\":"<<status.cleaned<<"}\n";
            return 0;
        }
        if (mode == L"--namespace-cut" || mode == L"--recover-namespace-cut" ||
            mode == L"--metadata-cut" || mode == L"--recover-metadata-cut") {
            const bool metadata = mode.find(L"metadata") != std::wstring_view::npos;
            if (mode.starts_with(L"--recover-")) {
                const auto status = runtime->CachedStatus();
                Check(status.image.checkpoint_xid == 8 && status.accepted == status.durable &&
                    status.durable == status.cleaned && !status.recovery_required, "FreshNamespaceRecoveryBoundary");
                if (metadata) {
                    const auto node = RuntimeMetadata(*runtime, 21);
                    Check(node.uid == 501 && node.gid == 20 && node.mode == 0100640, "FreshMetadataRecovery");
                } else {
                    auto view = runtime->OpenReadView(read_error);
                    Check(static_cast<bool>(view), "FreshDirectoryView");
                    c::EncryptedDirectoryEntry entry; c::EncryptedNodeInfo node;
                    Check(view->Lookup(2, "runtime-recovery-dir", entry) == c::EncryptedReadError::None &&
                        view->GetMetadata(entry.inode_id, node) == c::EncryptedReadError::None &&
                        node.mode == 0040700 && node.parent_id == 2, "FreshDirectoryRecovery");
                    view->Close();
                }
            } else {
                c::EncryptedMutationRequest request;
                Bytes encoded;
                if (metadata) {
                    r::InodeMetadataPatch patch;
                    patch.mask = r::InodeMetadataPatch::Owner | r::InodeMetadataPatch::Group | r::InodeMetadataPatch::Mode;
                    patch.owner = 501; patch.group = 20; patch.mode = 0640;
                    Check(r::EncodeInodeMetadataPatch(patch, encoded), "CutMetadataCanonical");
                    request.kind = c::EncryptedMutationKind::SetInodeMetadata; request.inode = 21; request.data = encoded;
                } else {
                    request.kind = c::EncryptedMutationKind::MakeDirectory; request.parent = 2;
                    request.name = "runtime-recovery-dir"; request.permissions = 0700;
                }
                std::uint64_t result = 999; bool cut = false;
                const auto applied = runtime->Apply(request, result, error, [&](std::string_view stage) {
                    if (stage == "after-encrypted-original-accept") { cut = true; return false; }
                    return true;
                });
                const auto status = runtime->CachedStatus();
                Check(!applied && !result && cut && status.recovery_required && status.accepted > status.durable &&
                    status.image.checkpoint_xid == 7 && error == "EncryptedRuntimeInterruptedBeforeStage",
                    "NamespaceCutAcceptedBeforePublication");
            }
            const auto status = runtime->CachedStatus();
            credential.bytes.Clear(); runtime->Close();
            std::cout << "{\"status\":\"PASS\",\"checks\":" << checks << ",\"finalXid\":"
                << status.image.checkpoint_xid << ",\"accepted\":" << status.accepted << ",\"cleaned\":" << status.cleaned << "}\n";
            return 0;
        }
        if (mode == L"--namespace") {
            NamespaceWorkflow(*runtime, error);
            const auto status = runtime->CachedStatus();
            credential.bytes.Clear(); runtime->Close();
            std::cout << "{\"status\":\"PASS\",\"mode\":\"namespace\",\"checks\":" << checks
                << ",\"finalXid\":" << status.image.checkpoint_xid << ",\"accepted\":" << status.accepted
                << ",\"cleaned\":" << status.cleaned << "}\n";
            return 0;
        }
        if (!mode.empty()) {
            Bytes payload; payload.resize(mode.find(L"64k") != std::wstring_view::npos ? Runtime::MaxWriteBytes : 4097);
            for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = std::byte((i * 29 + i / 97 + 61) % 251);
            if (mode == L"--spool-cut" || mode == L"--spool-64k-cut") {
                const auto xid = runtime->CachedStatus().image.checkpoint_xid;
                c::EncryptedMutationRequest write;
                write.kind = c::EncryptedMutationKind::Write; write.inode = 21; write.data = payload;
                std::uint64_t result = 0; bool cut = false;
                const auto applied = runtime->Apply(write, result, error, [&](std::string_view stage) {
                    if (stage == "after-encrypted-original-accept") { cut = true; return false; }
                    return true;
                });
                const auto status = runtime->CachedStatus();
                Check(!applied && !result && cut && status.recovery_required && status.accepted > status.durable &&
                    status.image.checkpoint_xid == xid && error == "EncryptedRuntimeInterruptedBeforeStage", "AcceptedUnstagedSpoolCut");
                credential.bytes.Clear(); runtime->Close();
                std::cout << "{\"status\":\"PASS\",\"mode\":\"accepted-before-stage\",\"checks\":" << checks
                    << ",\"checkpointXid\":" << xid << ",\"accepted\":" << status.accepted << "}\n";
            } else {
                const auto facts = Inventory(*runtime); const auto status = runtime->CachedStatus();
                Check(facts.size() == 6 && facts.contains(21) && facts.at(21).size == payload.size() &&
                    facts.at(21).hash == Digest(payload) && status.accepted && status.accepted == status.cleaned &&
                    status.durable == status.cleaned && !status.recovery_required && status.image.checkpoint_xid == 8,
                    "FreshProcessAcceptedSpoolRecovery");
                credential.bytes.Clear(); runtime->Close();
                std::cout << "{\"status\":\"PASS\",\"mode\":\"fresh-spool-recovery\",\"checks\":" << checks
                    << ",\"finalXid\":" << status.image.checkpoint_xid << ",\"accepted\":" << status.accepted
                    << ",\"cleaned\":" << status.cleaned << "}\n";
            }
            return 0;
        }
        const auto original = Inventory(*runtime);
        const auto initial_xid = runtime->CachedStatus().image.checkpoint_xid;
        c::EncryptedMutationRequest request;
        request.kind = c::EncryptedMutationKind::Create; request.parent = 2;
        request.name = "runtime-roundtrip.bin"; request.permissions = 0600;
        const std::array initial_payload{std::byte{0x79}}; request.data = initial_payload;
        std::uint64_t inode = 0;
        Check(runtime->Apply(request, inode, error) && inode >= 16, "Create:" + error);
        const auto created = inode;
        const auto check_clean = [&] {
            const auto status = runtime->CachedStatus();
            Check(status.accepted && status.accepted == status.durable && status.durable == status.cleaned &&
                !status.recovery_required && status.image.phase == c::EncryptedImageWritePhase::Ready, "CleanAcceptedDurableBoundary");
        };
        check_clean();
        const auto before_refusal = runtime->CachedStatus().accepted;
        request.name = ".";
        Check(!runtime->Apply(request, inode, error) && !inode && !runtime->CachedStatus().recovery_required &&
            runtime->CachedStatus().accepted == before_refusal, "InvalidNameUnaccepted");
        Bytes expected; expected.resize(131072);
        for (std::size_t i = 0; i < expected.size(); ++i) expected[i] = std::byte((i * 17 + i / 4096 + 37) % 251);
        std::size_t completed = 0;
        Check(runtime->Write(created, 0, expected, completed, error) && completed == expected.size(), "ProtectedSpoolChunkedWrite:" + error);
        check_clean();
        const auto matches = [&] {
            const auto facts = Inventory(*runtime);
            Check(facts.size() == original.size() + 1 && facts.contains(created) && facts.at(created).size == expected.size() &&
                facts.at(created).mode == 0100600 && facts.at(created).hash == Digest(expected), "ExactRuntimePayloadAndMode");
            for (const auto& [id, fact] : original)
                Check(facts.contains(id) && facts.at(id).size == fact.size && facts.at(id).mode == fact.mode &&
                    facts.at(id).hash == fact.hash, "OriginalPayloadPreserved");
        };
        matches();
        Bytes patch; patch.assign({std::byte{0xD3}, std::byte{0xE4}, std::byte{0xF5}});
        request = {}; request.kind = c::EncryptedMutationKind::Write; request.inode = created;
        request.offset = 65535; request.data = patch;
        bool interrupted = false;
        Check(!runtime->Apply(request, inode, error, [&](std::string_view stage) {
            if (stage == "before-apple-prepublication-flush") { interrupted = true; return false; }
            return true;
        }) && interrupted && !inode && runtime->CachedStatus().recovery_required, "InterruptedRuntimePublication:" + error);
        Check(!runtime->OpenReadView(read_error), "InterruptedReadRefused");
        runtime->Close(); runtime.reset();
        runtime = Runtime::Open(options, error);
        Check(runtime && runtime->CachedStatus().recovery_required && !runtime->CachedStatus().image.key_present, "PendingReopenLocked");
        Check(runtime->Recover(error) && !runtime->CachedStatus().image.key_present &&
            !runtime->CachedStatus().recovery_required, "KeylessRuntimeRecovery:" + error);
        c::PasswordUnlockBudget reopen_budget;
        Check(runtime->Unlock(credential.bytes, reopen_budget, error), "ReopenUnlock:" + error);
        std::copy(patch.begin(), patch.end(), expected.begin() + 65535); matches(); check_clean();
        request = {}; request.kind = c::EncryptedMutationKind::Resize; request.inode = created; request.size = expected.size() - 17;
        Check(runtime->Apply(request, inode, error), "RuntimeShrink:" + error); expected.resize(expected.size() - 17); matches();
        request.size += 25;
        Check(runtime->Apply(request, inode, error), "RuntimeZeroGrow:" + error); expected.resize(expected.size() + 25, std::byte{}); matches();
        request = {}; request.kind = c::EncryptedMutationKind::Rename; request.inode = created;
        request.parent = request.destination_parent = 2; request.name = "runtime-roundtrip.bin"; request.destination_name = "runtime-renamed.bin";
        Check(runtime->Apply(request, inode, error), "RuntimeRename:" + error); matches();
        request = {}; request.kind = c::EncryptedMutationKind::Unlink; request.inode = created;
        request.parent = 2; request.name = "runtime-renamed.bin";
        Check(runtime->Apply(request, inode, error), "RuntimeUnlink:" + error); check_clean();
        const auto final = Inventory(*runtime);
        Check(final.size() == original.size(), "FinalNamespace");
        for (const auto& [id, fact] : original)
            Check(final.contains(id) && final.at(id).size == fact.size && final.at(id).hash == fact.hash &&
                final.at(id).mode == fact.mode, "FinalOriginalIntegrity");
        const auto final_status = runtime->CachedStatus();
        Check(final_status.image.checkpoint_xid == initial_xid + 8, "EightActualCanonicalPublications");
        credential.bytes.Clear(); runtime->Lock();
        Check(!runtime->CachedStatus().image.key_present && !runtime->OpenReadView(read_error), "LockRevokes");
        runtime->Close();
        Check(runtime->CachedStatus().closed && !runtime->CachedStatus().image.key_present, "ClosedWithoutKey");
        std::cout << "{\"status\":\"PASS\",\"checks\":" << checks << ",\"initialXid\":" << initial_xid
            << ",\"finalXid\":" << final_status.image.checkpoint_xid << ",\"accepted\":" << final_status.accepted
            << ",\"cleaned\":" << final_status.cleaned << ",\"physicalDevices\":false}\n";
        return 0;
    } catch (const std::exception& ex) { std::cerr << "RuntimeGateFailure:" << ex.what() << ':' << error << '\n'; return 1; }
}
