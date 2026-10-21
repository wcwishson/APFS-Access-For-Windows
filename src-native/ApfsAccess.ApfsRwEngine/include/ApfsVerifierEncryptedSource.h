#pragma once

#include "ApfsVerifier.h"
#include "ApfsEncryptedReadSession.h"
#include <stdexcept>

namespace apfsaccess::catalog
{
struct RetainedProfileHistoryReport;
// Wrap before observational Unlock. The session binds to this exact object and
// retains the same held source. Deliberately uses legacy cumulative reads, not
// the host's optional fresh runtime allowances. Single verification operation
// at a time, like the shared cumulative budget. No key or write surface escapes.
class ApfsVerifierEncryptedSource final : public ImmutableEncryptedReadSource
{
public:
    ApfsVerifierEncryptedSource(std::shared_ptr<const ImmutableEncryptedReadSource> source,
        const VerificationScope& scope, std::function<bool()> within_deadline)
        : source_(std::move(source)), deadline_(std::move(within_deadline))
    {
        if (!source_ || !source_->ReadBudget() || !deadline_)
            throw std::invalid_argument("VerifierEncryptedHeldBudgetSourceRequired");
        source_->ReadBudget()->LimitRemainingTo(scope.max_reads, scope.max_read_bytes,
            scope.max_records, scope.max_record_bytes);
    }
    std::uint64_t SizeBytes() const override { return source_->SizeBytes(); }
    std::string SourceIdentity() const override { return source_->SourceIdentity(); }
    std::uint64_t Revision() const override { return source_->Revision(); }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return source_->ReadBudget(); }
    bool CheckDeadline() const
    {
        if (ReadBudget()->Failed()) return false;
        try { if (deadline_()) return !ReadBudget()->Failed(); }
        catch (...) { return ReadBudget()->Refuse("VerifierEncryptedDeadlineCallbackFailed"); }
        return ReadBudget()->Refuse("VerifierEncryptedDeadlineExceeded");
    }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
    {
        out.clear();
        if (!CheckDeadline() || !source_->Read(offset, size, out) || out.size() != size || !CheckDeadline())
        { if (!out.empty()) SecureZeroMemory(out.data(), out.size()); out.clear(); return false; }
        if (metadata_block_size_)
        {
            if (offset % metadata_block_size_ || !size || size % metadata_block_size_)
            { out.clear(); return ReadBudget()->Refuse("VerifierEncryptedMetadataReadShapeUnsupported"); }
            const auto count = size / metadata_block_size_;
            if (!ReadBudget()->Materialize(count, count * sizeof(std::uint64_t))) { out.clear(); return false; }
            for (std::size_t i = 0; i < count; ++i) metadata_reads_.push_back(offset / metadata_block_size_ + i);
        }
        return true;
    }
private:
    friend class ApfsVerifier;
    friend RetainedProfileHistoryReport VerifyEncryptedRetainedHistory(
        const ApfsVerifierEncryptedSource&, ApfsEncryptedReadSession&,
        const VerificationScope&, std::uint64_t, const std::function<bool()>&);
    bool BeginMetadataReads(std::uint32_t block_size) const
    {
        if (metadata_block_size_ || !metadata_reads_.empty()) return ReadBudget()->Refuse("VerifierEncryptedConcurrentObservation");
        if (!CheckDeadline()) return false;
        metadata_block_size_ = block_size; return true;
    }
    void EndMetadataReads(std::vector<std::uint64_t>& blocks) const
    { metadata_block_size_ = 0; blocks = std::move(metadata_reads_); metadata_reads_.clear(); }
    const std::shared_ptr<const ImmutableEncryptedReadSource> source_;
    const std::function<bool()> deadline_;
    mutable std::uint32_t metadata_block_size_ = 0;
    mutable std::vector<std::uint64_t> metadata_reads_;
};
}
