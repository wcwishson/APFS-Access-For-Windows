// Included in EncryptedReadTransport.cpp to share its private parent/ACL proof.
CredentialSetResult ReceiveCredentials(HANDLE owned_input, std::size_t expected_count,
    std::chrono::milliseconds timeout, const std::atomic<bool>& cancellation) noexcept
{
    Handle input{owned_input};
    const auto fail = [](CredentialError error) { return CredentialSetResult{error, {}, 0}; };
    if (!input.value || input.value == INVALID_HANDLE_VALUE || GetFileType(input.value) != FILE_TYPE_PIPE)
        return fail(CredentialError::PipeRequired);
    ULONG server = 0; DWORD flags = 0;
    if (!GetNamedPipeServerProcessId(input.value, &server) || !server || server != ParentPid() ||
        !GetNamedPipeInfo(input.value, &flags, nullptr, nullptr, nullptr) || (flags & PIPE_TYPE_MESSAGE) ||
        !SetHandleInformation(input.value, HANDLE_FLAG_INHERIT, 0))
        return fail(CredentialError::ParentPipeRequired);
    if (!ProtectedPipe(input.value)) return fail(CredentialError::UnprotectedPipe);
    if ((expected_count != 1 && expected_count != 2) || timeout < std::chrono::milliseconds(100) ||
        timeout > std::chrono::seconds(30)) return fail(CredentialError::InvalidFrame);
    auto frame = crypto::SecureBytes::Allocate(8 + 1024);
    if (!frame) return fail(CredentialError::SecureAllocationFailed);
    CredentialSetResult result;
    std::size_t received = 0, expected = 8, checked = 8;
    bool header = false;
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        if (cancellation.load()) return fail(CredentialError::Cancelled);
        if (std::chrono::steady_clock::now() >= deadline) return fail(CredentialError::Timeout);
        DWORD available = 0;
        if (!PeekNamedPipe(input.value, nullptr, 0, nullptr, &available, nullptr)) {
            if (GetLastError() != ERROR_BROKEN_PIPE) return fail(CredentialError::ReadFailure);
            if (result.count != expected_count || received) return fail(CredentialError::TruncatedFrame);
            result.error = CredentialError::None;
            return result;
        }
        if (!available) { Sleep(5); continue; }
        if (result.count == expected_count) return fail(CredentialError::InvalidFrame);
        DWORD got = 0;
        const auto count = static_cast<DWORD>((std::min)(std::size_t(available), expected - received));
        if (!::ReadFile(input.value, frame.bytes.Bytes().data() + received, count, &got, nullptr) || !got)
            return fail(CredentialError::TruncatedFrame);
        received += got;
        if (!header && received == 8) {
            const auto bytes = frame.bytes.Bytes();
            if (bytes[0] != std::byte{'A'} || bytes[1] != std::byte{'P'} || bytes[2] != std::byte{'C'} || bytes[3] != std::byte{'1'})
                return fail(CredentialError::InvalidFrame);
            std::uint32_t length = 0;
            for (unsigned i = 0; i < 4; ++i) length |= std::to_integer<std::uint32_t>(bytes[4 + i]) << (8 * i);
            if (length > 1024) return fail(CredentialError::OversizedFrame);
            if (!length) return fail(CredentialError::InvalidFrame);
            expected = 8 + length; header = true;
        }
        if (!header) continue;
        for (; checked < received; ++checked)
            if (frame.bytes.Bytes()[checked] == std::byte{}) return fail(CredentialError::InvalidFrame);
        if (received != expected) continue;
        auto secret = crypto::SecureBytes::Allocate(expected - 8);
        if (!secret) return fail(CredentialError::SecureAllocationFailed);
        std::copy_n(frame.bytes.Bytes().begin() + 8, expected - 8, secret.bytes.Bytes().begin());
        result.credentials[result.count++] = std::move(secret.bytes);
        SecureZeroMemory(frame.bytes.Bytes().data(), frame.bytes.Size());
        received = 0; expected = checked = 8; header = false;
    }
}
