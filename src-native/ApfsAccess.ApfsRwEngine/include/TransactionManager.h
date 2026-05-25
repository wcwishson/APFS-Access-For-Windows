#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace apfsaccess::rw
{
class TransactionManager
{
public:
    enum class MutationKind
    {
        CreateFile,
        CreateDirectory,
        Write,
        SetFileSize,
        Rename,
        Delete,
        SetBasicInfo,
    };

    struct MutationIntent
    {
        MutationKind kind = MutationKind::Write;
        std::wstring path;
        std::wstring secondary_path;
        std::uint64_t offset = 0;
        std::uint64_t length = 0;
        bool replace_if_exists = false;
    };

    enum class State
    {
        Idle,
        Active,
        Committing,
        Failed,
    };

    explicit TransactionManager(std::wstring safety_level);

    [[nodiscard]] State CurrentState() const noexcept;
    [[nodiscard]] bool Begin();
    [[nodiscard]] bool Commit();
    [[nodiscard]] bool Abort();
    [[nodiscard]] bool RecordMutation(const MutationIntent& mutation);
    void SetJournalPath(std::wstring journal_path);
    [[nodiscard]] std::uint64_t CurrentTransactionId() const noexcept;
    [[nodiscard]] std::size_t PendingMutationCount() const noexcept;
    [[nodiscard]] static std::string WideToUtf8(const std::wstring& value);

    // Fault-injection hook used by the planned deterministic crash harness.
    void SetFaultInjectionHook(std::function<void(const std::string& stage)> hook);
    void NotifyStage(const std::string& stage);

private:
    [[nodiscard]] bool PersistTransactionLocked(const wchar_t* outcome) const;
    [[nodiscard]] static std::string EscapeJsonUtf8(const std::wstring& value);
    [[nodiscard]] static const wchar_t* MutationKindToString(MutationKind kind);

    std::wstring safety_level_;
    State state_ = State::Idle;
    std::function<void(const std::string& stage)> fault_hook_;
    std::wstring journal_path_;
    std::uint64_t next_transaction_id_ = 1;
    std::uint64_t current_transaction_id_ = 0;
    std::vector<MutationIntent> pending_mutations_;
};
} // namespace apfsaccess::rw
