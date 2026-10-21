#include "VolumeManagement.h"
#include "VolumeResizeCli.h"
#include <Windows.h>
#include <charconv>
#include <iostream>
#include <map>
#include <set>

using namespace apfsaccess::rw;
namespace
{
std::string Utf8(std::wstring_view s)
{
    if (s.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) throw std::runtime_error("invalid Unicode argument");
    std::string out(n, ' '); WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), n, nullptr, nullptr); return out;
}
std::uint64_t Number(std::wstring_view w)
{
    const auto s = Utf8(w); std::uint64_t n = 0;
    const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), n);
    if (ec != std::errc{} || end != s.data() + s.size() || std::to_string(n) != s)
        throw std::runtime_error("expected canonical decimal uint64");
    return n;
}
}
// Contract: every invocation emits exactly one JSON document on stdout.
// Exit 0 prepared/committed/cancelled; 1 refusal; 2 argument error; 3 recovery debt.
using PhysicalManagementSourceFactory = std::function<std::shared_ptr<VolumePhysicalSource>(
    const RawSnapshotBinding&, std::wstring_view, std::wstring_view, std::string&)>;
int VolumeManagementImageMain(int argc, wchar_t** argv, const PhysicalManagementSourceFactory& physical_factory =
    [](const RawSnapshotBinding& binding, std::wstring_view instance, std::wstring_view selected, std::string& error) {
        return VolumePhysicalSource::OpenExclusiveRaw(binding, instance, error, selected);
    })
{
    VolumeManagementRequest r; VolumeManagementResult result;
    VolumeManagementObservationRequest observation_request;
    bool observing = false;
    try {
        std::map<std::wstring, std::wstring> args;
        std::set<std::wstring> names = {L"--operation", L"--mode", L"--image", L"--journal-directory", L"--offset",
            L"--container", L"--volume", L"--oid", L"--xid", L"--name", L"--quota-blocks", L"--reserve-blocks", L"--case-sensitive", L"--confirm", L"--spool-root",
            L"--history-spool-root", L"--history-recovery-root", L"--source-kind", L"--physical-binding-hex", L"--physical-device"};
#ifdef APFS_VOLUME_MANAGEMENT_FAULT_INJECTION
        names.insert(L"--interrupt-at");
#endif
        for (int i = 1; i < argc; ++i) {
            const std::wstring key = argv[i];
            if (++i >= argc) throw std::runtime_error("missing argument value");
            const std::wstring value = argv[i];
            (void)Utf8(key); (void)Utf8(value);
            if (key == L"--mode" && value == L"observe") observing = true;
            if (key == L"--wal") {
                const auto split = value.find(L'=');
                if (split == std::wstring::npos || !r.sibling_wals.emplace(Number(value.substr(0, split)), value.substr(split + 1)).second)
                    throw std::runtime_error("WAL requires a distinct OID=absolute-path");
            } else if (!names.contains(key) || !args.emplace(key, value).second) throw std::runtime_error("unknown or duplicate option");
        }
        observing = args.contains(L"--mode") && args.at(L"--mode") == L"observe";
        if (args.contains(L"--mode") && args.at(L"--mode") == L"history") {
            for (auto key : {L"--mode", L"--image", L"--offset", L"--journal-directory", L"--history-spool-root", L"--history-recovery-root"})
                if (!args.contains(key)) throw std::runtime_error("history requires exact source and stable roots");
            if (args.size() != 6 || !r.sibling_wals.empty() || args.at(L"--offset") != L"0") throw std::runtime_error("invalid history observation options");
            bool admitted = false;
            std::cout << ObserveVolumeKeeperHistoryJson(args.at(L"--image"), args.at(L"--journal-directory"),
                {args.at(L"--history-spool-root"), args.at(L"--history-recovery-root")}, admitted) << '\n';
            return admitted ? 0 : 1;
        }
        if (observing) {
            for (auto key : {L"--mode", L"--image", L"--offset"})
                if (!args.contains(key)) throw std::runtime_error("observe requires image/offset");
            if (args.size() != 3 + args.contains(L"--spool-root") || !r.sibling_wals.empty())
                throw std::runtime_error("observe accepts only mode/image/offset and optional spool-root");
            observation_request.image = args.at(L"--image");
            observation_request.offset_bytes = Number(args.at(L"--offset"));
            const auto observed = ObserveVolumeManagement(observation_request);
            std::cout << VolumeManagementObservationJson(observation_request, observed) << '\n';
            return observed.complete ? 0 : 1;
        }
        if (args.contains(L"--spool-root")) throw std::runtime_error("spool-root is valid only for observe");
        if (args.contains(L"--history-spool-root") != args.contains(L"--history-recovery-root")) throw std::runtime_error("both history roots required");
        if (args.contains(L"--history-spool-root")) r.history_context = {args.at(L"--history-spool-root"), args.at(L"--history-recovery-root")};
        for (auto key : {L"--operation", L"--mode", L"--image", L"--journal-directory", L"--offset", L"--container", L"--volume", L"--oid", L"--xid"})
            if (!args.contains(key)) throw std::runtime_error("missing required identity/mode option");
        const auto operation = args.at(L"--operation"), mode = args.at(L"--mode");
        const auto kind = args.contains(L"--source-kind") ? args.at(L"--source-kind") : L"image";
        if (kind != L"image" && kind != L"physical") throw std::runtime_error("invalid source kind");
        const bool physical = kind == L"physical";
        if (args.contains(L"--physical-binding-hex") != physical ||
            args.contains(L"--physical-device") != (physical && (mode == L"dry-run" || mode == L"apply")))
            throw std::runtime_error("physical binding/selected-device mode mismatch");
        if (args.contains(L"--physical-device") && args.at(L"--physical-device").empty()) throw std::runtime_error("selected device required");
        if (operation != L"create" && operation != L"delete") throw std::runtime_error("operation must be create or delete");
        r.operation = operation == L"create" ? VolumeManagementOperation::Create : VolumeManagementOperation::Delete;
        if (mode != L"dry-run" && mode != L"apply" && mode != L"recover" && mode != L"cancel") throw std::runtime_error("invalid mode");
        if (args.contains(L"--confirm") != (mode == L"apply" || mode == L"cancel")) throw std::runtime_error("confirmation is required only for apply/cancel");
        r.image = args.at(L"--image"); r.journal_directory = args.at(L"--journal-directory"); r.offset_bytes = Number(args.at(L"--offset"));
        r.container_uuid = Utf8(args.at(L"--container")); r.volume_uuid = Utf8(args.at(L"--volume"));
        r.volume_oid = Number(args.at(L"--oid")); r.checkpoint_xid = Number(args.at(L"--xid"));
        if (r.operation == VolumeManagementOperation::Create) {
            for (auto key : {L"--name", L"--quota-blocks", L"--reserve-blocks", L"--case-sensitive"})
                if (!args.contains(key)) throw std::runtime_error("create requires explicit name/quota/reserve/case mode");
            r.name_utf8 = Utf8(args.at(L"--name")); r.quota_blocks = Number(args.at(L"--quota-blocks")); r.reserve_blocks = Number(args.at(L"--reserve-blocks"));
            const auto cs = args.at(L"--case-sensitive"); if (cs != L"true" && cs != L"false") throw std::runtime_error("case mode must be true or false");
            r.case_sensitive = cs == L"true";
        } else for (auto key : {L"--name", L"--quota-blocks", L"--reserve-blocks", L"--case-sensitive"})
            if (args.contains(key)) throw std::runtime_error("create options are invalid for delete");
        AppleCheckpointStageHook hook;
#ifdef APFS_VOLUME_MANAGEMENT_FAULT_INJECTION
        if (args.contains(L"--interrupt-at")) { const auto stop = Utf8(args.at(L"--interrupt-at")); hook = [stop](auto stage) { return stage != stop; }; }
#endif
        if (physical) {
            const auto envelope = volume_physical::Decode(volume_image_cli::PhysicalBinding(args.at(L"--physical-binding-hex")));
            if (r.image.wstring() != envelope.instance || r.offset_bytes != envelope.binding.media.base_offset_bytes ||
                r.history_context.spool_root.empty() || r.history_context.recovery_root.empty()) throw std::runtime_error("physical held scope/history mismatch");
            std::string error; const auto source = physical_factory(envelope.binding, envelope.instance,
                args.contains(L"--physical-device") ? std::wstring_view(args.at(L"--physical-device")) : std::wstring_view{}, error);
            if (!source) result.error = error;
            else if (source->Binding() != envelope.binding || source->InstanceId() != envelope.instance || !source->Revalidate())
                result.error = "VolumeManagementPhysicalFactoryAuthorityMismatch";
            else if (mode == L"dry-run") result = r.operation == VolumeManagementOperation::Create ?
                PrepareVolumePhysicalCreate(source, r) : PrepareVolumePhysicalDelete(source, r);
            else if (mode == L"apply") result = ApplyVolumePhysicalManagement(source, r, Utf8(args.at(L"--confirm")), hook);
            else if (mode == L"cancel") result = CancelVolumePhysicalManagement(source, r, Utf8(args.at(L"--confirm")));
            else result = RecoverVolumePhysicalManagement(source, r, hook);
        }
        else if (mode == L"dry-run") result = r.operation == VolumeManagementOperation::Create ? PrepareVolumeCreate(r) : PrepareVolumeDelete(r);
        else if (mode == L"apply") result = ApplyVolumeManagement(r, Utf8(args.at(L"--confirm")), hook);
        else if (mode == L"cancel") result = CancelVolumeManagement(r, Utf8(args.at(L"--confirm")));
        else result = RecoverVolumeManagement(r, hook);
    } catch (const std::exception& ex) {
        if (observing) {
            VolumeManagementObservation observed; observed.error = std::string("invalid-arguments:") + ex.what();
            std::cout << VolumeManagementObservationJson(observation_request, observed) << '\n'; return 2;
        }
        result.error = std::string("invalid-arguments:") + ex.what(); std::cout << VolumeManagementJson(r, result) << '\n'; return 2;
    }
    std::cout << VolumeManagementJson(r, result) << '\n';
    return result.outcome == VolumeManagementOutcome::RecoveryRequired ? 3 : result.outcome == VolumeManagementOutcome::Refused ? 1 : 0;
}
#ifndef APFS_VOLUME_MANAGEMENT_TOOL_TESTING
int wmain(int argc, wchar_t** argv) { return VolumeManagementImageMain(argc, argv); }
#endif
