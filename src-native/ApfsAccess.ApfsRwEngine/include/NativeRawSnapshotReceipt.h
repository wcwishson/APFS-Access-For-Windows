#pragma once
#include "RawSnapshotBinding.h"
#include "NativeVolumeRename.h"

namespace apfsaccess::rw {
struct NativeRawSnapshotPeer {
    std::uint64_t volume_oid = 0;
    std::string volume_uuid_hex;
    std::string journal_identity;
    bool operator==(const NativeRawSnapshotPeer&) const = default;
};

// Serialized evidence only. Admission must compare it with the held source
// and the original complete owner cohort before accepting or replaying work.
struct NativeRawSnapshotReceipt {
    RawSnapshotBinding binding;
    std::string selected_journal_identity;
    std::vector<NativeRawSnapshotPeer> peers;
    bool operator==(const NativeRawSnapshotReceipt&) const = default;
};

inline bool ValidRawSnapshotJournalIdentity(std::string_view value) {
    return !value.empty() && value.size() <= 255 &&
        std::all_of(value.begin(), value.end(), [](unsigned char c) { return c >= 0x21 && c <= 0x7e; });
}

inline bool ValidateNativeRawSnapshotReceiptShape(
    const NativeRawSnapshotReceipt& receipt, std::uint64_t oid,
    std::string_view volume_uuid, std::uint64_t store_size) {
    const auto& binding = receipt.binding;
    const auto& hardware = binding.hardware;
    if (binding.version != 1 || receipt.peers.empty() || receipt.peers.size() > 100 ||
        !ValidRawSnapshotJournalIdentity(receipt.selected_journal_identity) ||
        binding.media.limit_bytes != store_size ||
        hardware.vendor.size() > kRawSnapshotTextMaxBytes || hardware.product.size() > kRawSnapshotTextMaxBytes ||
        hardware.revision.size() > kRawSnapshotTextMaxBytes || hardware.serial.size() > kRawSnapshotTextMaxBytes ||
        !std::all_of(hardware.revision.begin(), hardware.revision.end(),
            [](unsigned char c) { return c >= 0x20 && c <= 0x7e; })) return false;

    // This checks canonical wire shape, not the provenance of these values.
    RawSnapshotDescriptors descriptors;
    descriptors.media = binding.media;
    descriptors.device = {hardware.bus_type, hardware.vendor, hardware.product, hardware.revision, hardware.serial};
    RawHardwareQualification shape;
    shape.kind = hardware.kind; shape.bus_type = hardware.bus_type;
    shape.vendor = hardware.vendor; shape.product = hardware.product;
    if (hardware.kind == RawHardwareIdentityKind::QualifiedSerialTuple) shape.qualified_serial = hardware.serial;
    else if (hardware.kind == RawHardwareIdentityKind::QualifiedDeviceVpd) {
        descriptors.device_id_available = true;
        descriptors.identifiers.push_back({hardware.vpd_code_set, hardware.vpd_type,
            StorageIdAssocDevice, hardware.vpd_identifier});
        shape.qualified_vpd_type = hardware.vpd_type;
    } else return false;
    RawSnapshotBinding canonical; std::string error;
    if (!QualifyRawSnapshotBinding(descriptors, shape, canonical, error) || canonical != binding) return false;

    std::uint64_t previous = 0;
    bool selected = false;
    for (std::size_t i = 0; i < receipt.peers.size(); ++i) {
        const auto& peer = receipt.peers[i];
        if (peer.volume_oid <= previous || !ValidRenameUuid(peer.volume_uuid_hex) ||
            !ValidRawSnapshotJournalIdentity(peer.journal_identity)) return false;
        previous = peer.volume_oid;
        for (std::size_t j = 0; j < i; ++j)
            if (receipt.peers[j].volume_uuid_hex == peer.volume_uuid_hex ||
                receipt.peers[j].journal_identity == peer.journal_identity) return false;
        if (peer.volume_oid == oid) {
            if (peer.volume_uuid_hex != volume_uuid || peer.journal_identity != receipt.selected_journal_identity) return false;
            selected = true;
        }
    }
    return selected;
}
}
