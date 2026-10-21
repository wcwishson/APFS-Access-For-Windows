#pragma once
bool ParseBackupHeldOption(std::wstring_view option, const std::wstring& value, backup_held_mount::Options& b)
{
    if (option == L"--backup-held-binding") b.binding_hex = value;
    else if (option == L"--backup-held-volume-uuid") b.volume_uuid = value;
    else if (option == L"--backup-held-checkpoint-xid") {
        if (!IsCanonicalNonzeroDecimal(value)) return false;
        try { b.checkpoint_xid = std::stoull(value); } catch (...) { return false; }
    } else return false;
    return true;
}
bool DecodeBackupHeldOption(const backup_held_mount::Options& b, apfsaccess::rw::RawSnapshotBinding& binding,
    std::wstring& instance, std::string& error)
{
    if (b.binding_hex.empty() || b.binding_hex.size() > 8192 || b.binding_hex.size() % 2 ||
        !BackupLowerHex(b.binding_hex, b.binding_hex.size())) return false;
    std::vector<std::byte> bytes; bytes.reserve(b.binding_hex.size() / 2);
    const auto digit = [](wchar_t c) { return c <= L'9' ? c - L'0' : c - L'a' + 10; };
    for (std::size_t i = 0; i < b.binding_hex.size(); i += 2)
        bytes.push_back(std::byte(digit(b.binding_hex[i]) * 16 + digit(b.binding_hex[i + 1])));
    return apfsaccess::rw::BackupRetainedSource::DecodePhysicalBinding(bytes, binding, instance, error);
}
bool ValidateBackupHeldArguments(const Arguments& a)
{
    apfsaccess::rw::RawSnapshotBinding binding; std::wstring instance; std::string error;
    return a.readwrite && !a.readonly && a.allow_raw_physical_write && IsRawPhysicalDevicePath(a.device) &&
        a.container_manifest.empty() && !a.encrypted.enabled && !a.fusion.enabled && !a.system_data.enabled &&
        !a.backup_image.enabled && !a.standard_stdio && !a.enable_raw_snapshots && !a.enable_image_snapshots &&
        !a.enable_retained_physical_snapshot_inventory && !a.snapshot_xid && a.snapshot_name.empty() &&
        IsValidContainerId(a.container_id) && a.volume_object_id && a.backup_held.checkpoint_xid &&
        BackupLowerHex(a.backup_held.volume_uuid, 32) && IsWriteBackendMode(a.write_backend, L"Native") &&
        a.write_safety_level == L"Strict" && a.write_max_dirty_transactions == 1 &&
        IsRecoveryPolicyFailClosed(a.write_recovery_policy) && IsCrashReplayModeReplayIfSafe(a.write_crash_replay_mode) &&
        a.write_require_canonical_commit && a.write_integrity_check_on_mount && !a.allow_legacy_scaffold_for_fixtures &&
        !a.management_journal_directory.empty() && std::filesystem::path(a.management_journal_directory).is_absolute() &&
        !a.recovery_identity.empty() && !a.status_file.empty() &&
        DecodeBackupHeldOption(a.backup_held, binding, instance, error) &&
        binding.media.base_offset_bytes == a.device_offset_bytes && binding.media.limit_bytes <= (256ull << 20);
}
