#include "EncryptedReadTransport.h"
#include "MaintenanceCredentialTransport.h"
#include <tlhelp32.h>
#include <bcrypt.h>
#include <aclapi.h>
#include <algorithm>

namespace apfsaccess::transport
{
namespace
{
struct Handle
{
    HANDLE value;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
DWORD ParentPid() noexcept
{
    Handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
    if (snapshot.value == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot.value, &entry)) do
    {
        if (entry.th32ProcessID == GetCurrentProcessId()) return entry.th32ParentProcessID;
    } while (Process32NextW(snapshot.value, &entry));
    return 0;
}
bool ProtectedPipe(HANDLE pipe) noexcept
{
    try
    {
        Handle token{nullptr};
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value)) return false;
        const auto info = [&](TOKEN_INFORMATION_CLASS kind) {
            DWORD size = 0;
            GetTokenInformation(token.value, kind, nullptr, 0, &size);
            if (!size || size > 65536) return std::vector<std::byte>{};
            std::vector<std::byte> bytes(size);
            if (!GetTokenInformation(token.value, kind, bytes.data(), size, &size)) bytes.clear();
            return bytes;
        };
        const auto user_bytes = info(TokenUser), logon_bytes = info(TokenLogonSid);
        if (user_bytes.empty() || logon_bytes.empty()) return false;
        const auto user = reinterpret_cast<const TOKEN_USER*>(user_bytes.data())->User.Sid;
        const auto groups = reinterpret_cast<const TOKEN_GROUPS*>(logon_bytes.data());
        if (groups->GroupCount != 1) return false;
        const auto logon = groups->Groups[0].Sid;
        BYTE system[SECURITY_MAX_SID_SIZE]{}; DWORD system_size = sizeof(system);
        if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &system_size)) return false;
        PACL dacl = nullptr; PSID owner = nullptr; PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (GetSecurityInfo(pipe, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &owner, nullptr, &dacl, nullptr, &descriptor) != ERROR_SUCCESS) return false;
        struct Free { void* p; ~Free() { LocalFree(p); } } free{descriptor};
        if (!owner || !EqualSid(owner,user) || !dacl || !IsValidAcl(dacl)) return false;
        for (DWORD i=0; i<dacl->AceCount; ++i)
        {
            void* raw = nullptr;
            if (!GetAce(dacl,i,&raw)) return false;
            const auto ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
            // Unknown/object/callback ACE semantics are deliberately unsupported.
            if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || (ace->Header.AceFlags & INHERIT_ONLY_ACE)) return false;
            const auto sid = const_cast<DWORD*>(&ace->SidStart);
            if (!IsValidSid(sid) || (!EqualSid(sid,user) && !EqualSid(sid,logon) && !EqualSid(sid,system))) return false;
        }
        return true;
    }
    catch (...) { return false; }
}
}
const char* CredentialErrorName(CredentialError error) noexcept
{
    switch (error)
    {
#define NAME(x) case CredentialError::x: return #x
    NAME(None); NAME(PipeRequired); NAME(ParentPipeRequired); NAME(UnprotectedPipe); NAME(InvalidFrame);
    NAME(TruncatedFrame); NAME(OversizedFrame); NAME(Timeout); NAME(Cancelled);
    NAME(ReadFailure); NAME(SecureAllocationFailed);
#undef NAME
    }
    return "CredentialFailure";
}
CredentialResult ReceiveCredential(HANDLE owned_input, std::chrono::milliseconds timeout,
    const std::atomic<bool>& cancellation) noexcept
{
    Handle input{owned_input};
    const auto fail = [](CredentialError error) { return CredentialResult{error, {}}; };
    if (!input.value || input.value == INVALID_HANDLE_VALUE || GetFileType(input.value) != FILE_TYPE_PIPE)
        return fail(CredentialError::PipeRequired);
    ULONG server = 0; DWORD flags = 0;
    if (!GetNamedPipeServerProcessId(input.value, &server) || !server || server != ParentPid() ||
        !GetNamedPipeInfo(input.value, &flags, nullptr, nullptr, nullptr) || (flags & PIPE_TYPE_MESSAGE) ||
        !SetHandleInformation(input.value, HANDLE_FLAG_INHERIT, 0))
        return fail(CredentialError::ParentPipeRequired);
    if (!ProtectedPipe(input.value)) return fail(CredentialError::UnprotectedPipe);
    if (timeout < std::chrono::milliseconds(100) || timeout > std::chrono::seconds(30))
        return fail(CredentialError::InvalidFrame);
    // Fixed bounded scratch is secure too, including malformed input and extra byte.
    auto frame = crypto::SecureBytes::Allocate(8 + 1024 + 1);
    if (!frame) return fail(CredentialError::SecureAllocationFailed);
    std::size_t received = 0, expected = 8;
    bool header = false;
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;)
    {
        if (cancellation.load()) return fail(CredentialError::Cancelled);
        if (std::chrono::steady_clock::now() >= deadline) return fail(CredentialError::Timeout);
        DWORD available = 0;
        if (!PeekNamedPipe(input.value, nullptr, 0, nullptr, &available, nullptr))
        {
            if (GetLastError() != ERROR_BROKEN_PIPE) return fail(CredentialError::ReadFailure);
            if (!header || received != expected) return fail(CredentialError::TruncatedFrame);
            auto secret = crypto::SecureBytes::Allocate(expected - 8);
            if (!secret) return fail(CredentialError::SecureAllocationFailed);
            std::copy_n(frame.bytes.Bytes().begin() + 8, expected - 8, secret.bytes.Bytes().begin());
            return CredentialResult{CredentialError::None, std::move(secret.bytes)};
        }
        if (!available) { Sleep(5); continue; }
        DWORD got = 0;
        const auto count = static_cast<DWORD>((std::min)(std::size_t(available), expected + (header ? 1 : 0) - received));
        if (!::ReadFile(input.value, frame.bytes.Bytes().data() + received, count, &got, nullptr) || !got)
            return fail(CredentialError::TruncatedFrame);
        received += got;
        if (!header && received == 8)
        {
            const auto b = frame.bytes.Bytes();
            if (b[0] != std::byte{'A'} || b[1] != std::byte{'P'} || b[2] != std::byte{'C'} || b[3] != std::byte{'1'})
                return fail(CredentialError::InvalidFrame);
            std::uint32_t length = 0;
            for (unsigned i = 0; i < 4; ++i) length |= std::to_integer<std::uint32_t>(b[4+i]) << (8*i);
            if (length > 1024) return fail(CredentialError::OversizedFrame);
            if (!length) return fail(CredentialError::InvalidFrame);
            expected = 8 + length; header = true;
        }
        else if (header)
        {
            if (received > expected) return fail(CredentialError::InvalidFrame);
            for (std::size_t i = 8; i < received; ++i)
                if (frame.bytes.Bytes()[i] == std::byte{}) return fail(CredentialError::InvalidFrame);
        }
    }
}

#include "MaintenanceCredentialFrames.inc"

OwnedEncryptedImageSource::OwnedEncryptedImageSource(std::shared_ptr<WindowsImageLease> lease,
    std::uint64_t offset, std::uint64_t size)
    : lease_(std::move(lease)), budget_(std::make_shared<catalog::ApfsReadBudget>(100000, 256ULL*1024*1024,
        1000000, 256ULL*1024*1024)), offset_(offset), size_(size)
{
    if (!lease_ || !size || offset > lease_->SizeBytes() || size > lease_->SizeBytes() - offset)
        throw std::runtime_error("InvalidSourceScope");
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&revision_), sizeof(revision_),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 || !revision_) throw std::runtime_error("SourceRevisionFailure");
    identity_ = lease_->Identity() + ":scope:" + std::to_string(offset) + ":" + std::to_string(size);
}
bool OwnedEncryptedImageSource::Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const
{
    out.clear();
    if (!budget_->Read(size) || offset > size_ || size > size_ - offset || !lease_->VerifyUnchanged()) return false;
    return lease_->Read(offset_ + offset, size, out);
}
bool OwnedEncryptedImageSource::ReadRuntime(const RuntimeRead& request, std::vector<std::byte>& out) const
{
    out.clear();
    if (!request.IsFor(*this) || budget_->Failed() ||
        request.Offset() > size_ || request.Size() > size_ - request.Offset() ||
        !lease_->VerifyUnchanged()) return false;
    // The session reserved this operation's I/O before invoking the held lease.
    if (!lease_->Read(offset_ + request.Offset(), request.Size(), out) ||
        out.size() != request.Size() || !lease_->VerifyUnchanged() || budget_->Failed())
    {
        out.clear();
        return false;
    }
    return true;
}
}
