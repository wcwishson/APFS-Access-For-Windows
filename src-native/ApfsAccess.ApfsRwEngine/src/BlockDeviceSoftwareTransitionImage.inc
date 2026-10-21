std::shared_ptr<BlockDevice> BlockDevice::AdoptSoftwareTransitionImage(
    std::wstring path, HANDLE handle, std::uint64_t offset,
    std::uint64_t container_bytes, std::uint64_t carrier_bytes, std::string& error)
{
    error.clear();
    struct Transfer {
        HANDLE value;
        ~Transfer() { if (value != INVALID_HANDLE_VALUE && value) CloseHandle(value); }
    } transfer{handle};
    auto device = std::make_shared<BlockDevice>(std::move(path), offset);
    device->read_handle_.store(handle); transfer.value = INVALID_HANDLE_VALUE;
    FILE_ID_INFO identity{}; FILE_STANDARD_INFO standard{};
    if (!container_bytes || container_bytes % 4096 || offset % 4096 ||
        offset > 256ull * 1024 * 1024 || container_bytes > 256ull * 1024 * 1024 - offset ||
        carrier_bytes < offset + container_bytes || carrier_bytes > 256ull * 1024 * 1024 ||
        !QueryRegularFileIdentity(handle, identity) ||
        !GetFileInformationByHandleEx(handle, FileStandardInfo, &standard, sizeof(standard)) ||
        standard.Directory || standard.DeletePending || standard.NumberOfLinks != 1 ||
        standard.EndOfFile.QuadPart <= 0 ||
        static_cast<std::uint64_t>(standard.EndOfFile.QuadPart) != carrier_bytes ||
        !QueryHeldReadWriteHandle(handle, 2)) {
        error = "SoftwareTransitionHeldBoundedExclusiveImageRequired"; return {};
    }
    for (const DWORD access : std::array<DWORD, 3>{FILE_READ_DATA, FILE_WRITE_DATA, DELETE}) {
        const auto probe = ReOpenFile(handle, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_FLAG_OVERLAPPED);
        if (probe != INVALID_HANDLE_VALUE) { CloseHandle(probe); error = "SoftwareTransitionHeldImageNotExclusive"; return {}; }
        if (GetLastError() != ERROR_SHARING_VIOLATION) { error = "SoftwareTransitionHeldImageSharingProofFailed"; return {}; }
    }
    HANDLE writer = INVALID_HANDLE_VALUE;
    if (!DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(), &writer,
            0, FALSE, DUPLICATE_SAME_ACCESS)) {
        error = "SoftwareTransitionHeldImageDuplicateFailed"; return {};
    }
    device->write_handle_.store(writer);
    device->regular_file_.store(true); device->writable_.store(true);
    device->AdvanceWriteSourceGenerationLocked();
    device->exclusive_write_image_identity_ = identity;
    device->exclusive_write_image_size_bytes_ = carrier_bytes;
    device->exclusive_write_image_ = true;
    return device;
}
