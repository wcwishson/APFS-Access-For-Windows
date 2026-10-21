#pragma once

#include "SoftwareTransitionPlainWriter.h"
#include "SoftwareTransitionVolumeTransaction.h"

namespace apfsaccess::rw
{
struct NativeApfsVolumeProjection;
class SoftwareTransitionMetadataScope final
{
public:
    static const SoftwareTransitionMetadataScope* Find(const MetadataStore*) noexcept;
    bool Plan(const catalog::AppleCheckpointView&, const AppleVolumeTransactionRequest&,
        AppleVolumeTransactionPlan&, std::string&) const;
    bool LoadProjection(NativeApfsVolumeProjection&, std::string&) const;
    bool VerifyOriginal(TransactionManager&, std::string&) const;
    bool WithVerificationCandidate(MetadataStore&, const std::function<bool()>&, std::string&) const;
    bool PlanCompletedVerification(const catalog::RandomAccessSource&, const catalog::AppleCheckpointView&,
        const AppleVolumeTransactionRequest&, AppleVolumeTransactionPlan&, std::string&) const;
    bool ProjectCompletedPreimage(const catalog::RandomAccessSource&, const catalog::AppleCheckpointView&,
        const std::shared_ptr<catalog::ApfsReadBudget>&, NativeApfsVolumeProjection&, std::string&) const;
private:
    friend bool WithSoftwareTransitionPlainWriter(MetadataStore&, TransactionManager&,
        std::shared_ptr<const catalog::SoftwareVolumeRetainedOwners>, const std::function<bool(std::string&)>&, std::string&);
    SoftwareTransitionMetadataScope(MetadataStore&, TransactionManager&,
        std::shared_ptr<const catalog::SoftwareVolumeRetainedOwners>);
    ~SoftwareTransitionMetadataScope();
    bool Verify(std::string&) const;
    inline static thread_local const SoftwareTransitionMetadataScope* current_ = nullptr;
    const SoftwareTransitionMetadataScope* previous_;
    MetadataStore& store_;
    TransactionManager& original_;
    std::shared_ptr<const catalog::SoftwareVolumeRetainedOwners> owners_;
};
}
