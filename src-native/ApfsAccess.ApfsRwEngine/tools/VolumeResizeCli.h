#pragma once
#include "VolumeFormat.h"
#include "VolumePhysicalKeeper.h"
#include "../src/VolumePhysicalBindingCodec.h"
#include <Windows.h>
#include <charconv>
#include <iostream>
#include <set>
namespace apfsaccess::rw::volume_image_cli
{
inline std::string Utf8(std::wstring_view s)
{
    if (s.empty()) return {};
    const auto n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) throw std::runtime_error("invalid Unicode"); std::string out(n, ' ');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), n, nullptr, nullptr); return out;
}
inline std::uint64_t Number(std::wstring_view s)
{
    const auto text = Utf8(s); std::uint64_t n{}; const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), n);
    if (error != std::errc{} || end != text.data() + text.size() || std::to_string(n) != text) throw std::runtime_error("canonical decimal uint64 required");
    return n;
}
inline std::vector<std::byte> PhysicalBinding(std::wstring_view text)
{
    if (text.empty() || text.size() > 8192 || text.size() % 2) throw std::runtime_error("bounded physical binding hex required");
    std::vector<std::byte> bytes; bytes.reserve(text.size() / 2);
    const auto digit = [](wchar_t c) -> unsigned {
        if (c >= L'0' && c <= L'9') return static_cast<unsigned>(c - L'0');
        if (c >= L'a' && c <= L'f') return static_cast<unsigned>(c - L'a' + 10);
        throw std::runtime_error("canonical lower hex physical binding required");
    };
    for (std::size_t at = 0; at < text.size(); at += 2) bytes.push_back(std::byte((digit(text[at]) << 4) | digit(text[at + 1])));
    return bytes;
}
inline VolumeImageResult PhysicalCommand(const std::shared_ptr<VolumePhysicalSource>& source,
    const VolumeImageRequest& request, std::wstring_view mode, std::string_view confirmation,
    const AppleCheckpointStageHook& hook = {})
{
    if (mode == L"dry-run") return PrepareVolumePhysicalFormat(source, request);
    if (mode == L"apply") return ApplyVolumePhysicalFormat(source, request, confirmation, hook);
    if (mode == L"cancel") return CancelVolumePhysicalFormat(source, request, confirmation);
    if (mode == L"recover") return RecoverVolumePhysicalFormat(source, request, hook);
    throw std::runtime_error("invalid physical keeper mode");
}
using PhysicalSourceFactory = std::function<std::shared_ptr<VolumePhysicalSource>(const RawSnapshotBinding&,
    std::wstring_view, std::wstring_view, std::string&)>;
using PhysicalGeometryFactory = std::function<std::shared_ptr<VolumePhysicalGeometrySource>(const RawSnapshotBinding&,
    std::wstring_view,std::wstring_view,std::string&)>;
inline int Run(int argc, wchar_t** argv, bool format, const PhysicalSourceFactory& open_physical =
    [](const RawSnapshotBinding& binding, std::wstring_view instance, std::wstring_view selected, std::string& error) {
        return VolumePhysicalSource::OpenExclusiveRaw(binding, instance, error, selected);
    },const PhysicalGeometryFactory& open_geometry=[](const RawSnapshotBinding& binding,std::wstring_view instance,std::wstring_view selected,std::string& error){
        return VolumePhysicalGeometrySource::OpenExclusiveRaw(binding,instance,error,selected);
    })
{
    VolumeImageRequest r; VolumeImageResult result;
    try {
        std::map<std::wstring, std::wstring> args;
        std::set<std::wstring> allowed = {L"--operation",L"--mode",L"--image",L"--journal-directory",L"--container",L"--volume",L"--oid",L"--xid",
            L"--expected-bytes",L"--target-bytes",L"--confirm",L"--history-spool-root",L"--history-recovery-root",
            L"--source-kind",L"--physical-binding-hex",L"--physical-device"};
        if (format) for (auto key : {L"--new-container",L"--new-volume",L"--new-wal",L"--name",L"--case-sensitive"}) allowed.insert(key);
#ifdef APFS_VOLUME_IMAGE_FAULT_INJECTION
        allowed.insert(L"--interrupt-at");
#endif
        for (int i = 1; i < argc; ++i) {
            const std::wstring key = argv[i]; if (++i >= argc) throw std::runtime_error("missing option value");
            const std::wstring value = argv[i]; (void)Utf8(key); (void)Utf8(value);
            if (key == L"--wal") {
                const auto at = value.find(L'=');
                if (at == std::wstring::npos || !r.sibling_wals.emplace(Number(value.substr(0, at)), value.substr(at + 1)).second)
                    throw std::runtime_error("distinct WAL OID=absolute-path required");
            } else if (!allowed.contains(key) || !args.emplace(key, value).second) throw std::runtime_error("unknown or duplicate option");
        }
        for (auto key : {L"--operation",L"--mode",L"--image",L"--journal-directory",L"--container",L"--volume",L"--oid",L"--xid",L"--expected-bytes",L"--target-bytes"})
            if (!args.contains(key)) throw std::runtime_error("missing identity/capacity/mode option");
        const auto op = args.at(L"--operation"), mode = args.at(L"--mode");
        const auto kind = args.contains(L"--source-kind") ? args.at(L"--source-kind") : L"image";
        if (kind != L"image" && kind != L"physical") throw std::runtime_error("invalid source kind");
        const bool physical = kind == L"physical";
        if (args.contains(L"--physical-binding-hex") != physical)
            throw std::runtime_error("physical binding is required only for an explicit physical source");
        if (args.contains(L"--physical-device") != (physical && (mode == L"dry-run" || mode == L"apply")))
            throw std::runtime_error("selected device is required only for physical prepare/apply");
        if (args.contains(L"--physical-device") && args.at(L"--physical-device").empty())
            throw std::runtime_error("selected physical device cannot be empty");
        if (args.contains(L"--history-spool-root") != args.contains(L"--history-recovery-root")) throw std::runtime_error("both history roots required");
        if (args.contains(L"--history-spool-root")) r.history_context = {args.at(L"--history-spool-root"), args.at(L"--history-recovery-root")};
        if ((!format && op != L"grow" && op != L"shrink") || (format && op != L"format" && op != L"erase")) throw std::runtime_error("operation not allowed by this tool");
        r.operation = op == L"grow" ? VolumeImageOperation::Grow : op == L"shrink" ? VolumeImageOperation::Shrink :
            op == L"format" ? VolumeImageOperation::Format : VolumeImageOperation::Erase;
        if (mode != L"dry-run" && mode != L"apply" && mode != L"recover" && mode != L"cancel") throw std::runtime_error("invalid mode");
        if (args.contains(L"--confirm") != (mode == L"apply" || mode == L"cancel")) throw std::runtime_error("confirmation only required for apply/cancel");
        r.image = args.at(L"--image"); r.journal_directory = args.at(L"--journal-directory"); r.container_uuid = Utf8(args.at(L"--container"));
        r.volume_uuid = Utf8(args.at(L"--volume")); r.volume_oid = Number(args.at(L"--oid")); r.checkpoint_xid = Number(args.at(L"--xid"));
        r.expected_bytes = Number(args.at(L"--expected-bytes")); r.target_bytes = Number(args.at(L"--target-bytes"));
        if (format) {
            for (auto key : {L"--new-container",L"--new-volume",L"--new-wal",L"--name",L"--case-sensitive"})
                if (!args.contains(key)) throw std::runtime_error("missing format destination option");
            r.new_container_uuid = Utf8(args.at(L"--new-container")); r.new_volume_uuid = Utf8(args.at(L"--new-volume"));
            r.new_volume_wal = args.at(L"--new-wal"); r.name_utf8 = Utf8(args.at(L"--name"));
            const auto cs = args.at(L"--case-sensitive"); if (cs != L"true" && cs != L"false") throw std::runtime_error("case mode must be true or false"); r.case_sensitive = cs == L"true";
        }
        AppleCheckpointStageHook hook;
#ifdef APFS_VOLUME_IMAGE_FAULT_INJECTION
        if (args.contains(L"--interrupt-at")) {
            const auto stop = Utf8(args.at(L"--interrupt-at")); hook = [stop](auto stage) { return stage != stop; };
        }
#endif
        if (physical) {
            const auto envelope = volume_physical::Decode(PhysicalBinding(args.at(L"--physical-binding-hex")));
            if (r.image.wstring() != envelope.instance || r.expected_bytes != envelope.binding.media.limit_bytes ||
                (format && r.target_bytes != r.expected_bytes)) throw std::runtime_error("physical source/window mismatch");
            std::string error;
            if(!format){
                const auto source=open_geometry(envelope.binding,envelope.instance,
                    args.contains(L"--physical-device")?std::wstring_view(args.at(L"--physical-device")):std::wstring_view{},error);
                if(!source)result.error=error;
                else if(source->OriginalBinding()!=envelope.binding || source->InstanceId()!=envelope.instance || !source->Revalidate())
                    result.error="VolumeGeometryFactoryAuthorityMismatch";
                else if(mode==L"dry-run")result=PrepareVolumePhysicalResize(source,r);
                else if(mode==L"apply")result=ApplyVolumePhysicalResize(source,r,Utf8(args.at(L"--confirm")),hook);
                else if(mode==L"cancel")result=CancelVolumePhysicalResize(source,r,Utf8(args.at(L"--confirm")));
                else result=RecoverVolumePhysicalResize(source,r,hook);
            }else{
            const auto source = open_physical(envelope.binding, envelope.instance,
                args.contains(L"--physical-device") ? std::wstring_view(args.at(L"--physical-device")) : std::wstring_view{}, error);
            if (!source) result.error = error;
            else if (source->Binding() != envelope.binding || source->InstanceId() != envelope.instance || !source->Revalidate())
                result.error = "VolumePhysicalFactoryAuthorityMismatch";
            else result = PhysicalCommand(source, r, mode, args.contains(L"--confirm") ? Utf8(args.at(L"--confirm")) : std::string{}, hook);
            }
        }
        else if (mode == L"dry-run") result = format ? PrepareVolumeFormat(r) : PrepareVolumeResize(r);
        else if (mode == L"apply") result = format ? ApplyVolumeFormat(r, Utf8(args.at(L"--confirm")), hook) : ApplyVolumeResize(r, Utf8(args.at(L"--confirm")), hook);
        else if (mode == L"cancel") result = format ? CancelVolumeFormat(r, Utf8(args.at(L"--confirm"))) : CancelVolumeResize(r, Utf8(args.at(L"--confirm")));
        else result = format ? RecoverVolumeFormat(r, hook) : RecoverVolumeResize(r, hook);
    } catch (const std::exception& ex) {
        result.error = std::string("invalid-arguments:") + ex.what(); std::cout << VolumeImageJson(r, result) << '\n'; return 2;
    }
    std::cout << VolumeImageJson(r, result) << '\n';
    return result.outcome == VolumeImageOutcome::RecoveryRequired ? 3 : result.outcome == VolumeImageOutcome::Refused ? 1 : 0;
}
}
