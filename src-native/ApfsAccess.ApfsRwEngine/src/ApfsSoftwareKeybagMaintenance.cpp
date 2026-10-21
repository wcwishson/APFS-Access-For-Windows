#include "ApfsSoftwareKeybagMaintenance.h"
#include "ApfsEncryptedReadSession.h"
#include "ApfsFormat.h"
#include <new>

namespace apfsaccess::catalog
{
SoftwareKeybagRewrap::~SoftwareKeybagRewrap() = default;

std::unique_ptr<SoftwareKeybagRewrap> SoftwareKeybagRewrap::Prepare(
    std::shared_ptr<const ImmutableEncryptedReadSource> source,
    const std::string& expected_source_identity, std::uint64_t expected_revision,
    std::uint64_t volume_oid, KeybagLength length,
    const crypto::SecureBytes& old_password, const crypto::SecureBytes& new_password,
    PasswordUnlockBudget& budget, UnlockError& error)
{
    error = UnlockError::InvalidArgument;
    if (!source || expected_source_identity.empty() || expected_source_identity.size() > 8192 ||
        !volume_oid || !old_password.IsLocked() || !new_password.IsLocked()) return {};
    const auto bound = [&] {
        return source->SourceIdentity() == expected_source_identity &&
            source->Revision() == expected_revision;
    };
    if (!bound()) { error = UnlockError::IdentityMismatch; return {}; }
    try
    {
        source = ObserveSource(std::move(source));
        auto metadata = InspectPasswordKeybagMetadata(*source, volume_oid, length, error);
        if (!metadata) return {};
        if (metadata->users.size() != 1) { error = UnlockError::UnsupportedFormat; return {}; }
        auto request = metadata->selection;
        request.user_uuid = metadata->users.front();
        std::string detail;
        auto checkpoint = LoadContainerCheckpointView(*source, 0, source->SizeBytes(), detail,
            request.checkpoint_xid);
        if (!checkpoint) { error = UnlockError::IntegrityFailure; return {}; }
        if (checkpoint->superblock.fs_oids.size() != 1) {
            error = UnlockError::UnsupportedFormat; return {};
        }
        EncryptedReadError admission;
        auto session = ApfsEncryptedReadSession::Unlock(source, expected_source_identity,
            expected_revision, request, old_password.Bytes(), budget, admission, error);
        if (!session) {
            if (error == UnlockError::None) error = UnlockError::UnsupportedFormat;
            return {};
        }
        auto result = std::unique_ptr<SoftwareKeybagRewrap>(new SoftwareKeybagRewrap);
        error = TransformBags(*source, request, old_password, new_password, budget, *result);
        if (error != UnlockError::None) return {};
        if (!bound()) { error = UnlockError::IdentityMismatch; return {}; }
        result->identity_ = expected_source_identity;
        result->revision_ = expected_revision;
        result->selection_ = request;
        result->source_ = std::move(source);
        result->session_ = std::move(session);
        return result;
    }
    catch (const std::bad_alloc&) { error = UnlockError::ResourceLimit; return {}; }
}
} // namespace apfsaccess::catalog
