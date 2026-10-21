#include "BackupRetainedSource.h"
#include "VolumePhysicalBindingCodec.h"

namespace apfsaccess::rw
{
bool BackupRetainedSource::DecodePhysicalBinding(std::span<const std::byte> bytes, RawSnapshotBinding& binding,
    std::wstring& instance, std::string& error)
{
    binding = {}; instance.clear(); error.clear();
    try {
        auto decoded = volume_physical::Decode(bytes);
        if (volume_physical::Encode(decoded.binding, decoded.instance) != std::vector<std::byte>(bytes.begin(), bytes.end()))
        { error = "BackupPhysicalBindingNonCanonical"; return false; }
        binding = std::move(decoded.binding); instance = std::move(decoded.instance); return true;
    } catch (...) { error = "BackupPhysicalBindingInvalid"; return false; }
}
std::array<std::byte, 32> BackupRetainedSource::PhysicalJournalBinding(const RawSnapshotBinding& binding,
    std::wstring_view instance, std::string_view container_uuid, std::string_view volume_uuid, std::uint64_t oid)
{
    // Full original source binding is separate from the stable debt locator.
    // XIDs belong to authenticated accepted records and may advance on this owner.
    auto encoded = volume_physical::Encode(binding, instance);
    const auto text = [&](std::string_view value) {
        format_evidence::Number(encoded, value.size());
        for (const auto c : value) encoded.push_back(std::byte(c));
    };
    text("backup-held-original-v1");
    text(container_uuid); text(volume_uuid); format_evidence::Number(encoded, oid);
    return format_evidence::Hash(encoded);
}
}
