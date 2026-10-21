#pragma once

#include <cstdint>
#include <limits>

namespace encrypted_mount
{
struct State;
struct RuntimeProgressObserver;
#ifdef APFSACCESS_CALLBACK_PROGRESS_TESTING
struct DeadlineTestAccess;
#endif
#ifdef APFSACCESS_FSHOST_UNIT_TEST
struct DeadlineStateTestAccess;
#endif

// State serializes this per-operation policy with its short operations lock.
// Only the typed Runtime observer can provide completed barrier identities.
class OperationDeadline final
{
public:
    static constexpr std::uint64_t interval_ms = 30000;
    static constexpr std::uint64_t absolute_interval_ms = 240000;
    enum class Result { Renewed, Refused, Expired, AbsoluteExpired };

    OperationDeadline(std::uint64_t now, const void* owner, std::uint32_t thread,
        bool writable_callback) noexcept
        : owner_(owner), thread_(thread), writable_callback_(writable_callback),
          last_tick_(now), deadline_(After(now,interval_ms)),absolute_deadline_(After(now,absolute_interval_ms)) {}
    OperationDeadline(const OperationDeadline&) = delete;
    OperationDeadline& operator=(const OperationDeadline&) = delete;

    std::uint64_t Deadline() const noexcept { return deadline_; }
    std::uint64_t AbsoluteDeadline() const noexcept { return absolute_deadline_; }
    bool Cancelled() const noexcept { return cancelled_; }
    void Cancel() noexcept { cancelled_ = true; }
    bool Poll(std::uint64_t now) noexcept
    {
        if(!expired_ && now>=absolute_deadline_){expired_=true;absolute_expired_=true;}
        if (now >= deadline_) expired_ = true;
        return expired_;
    }

private:
    friend struct State;
    friend struct RuntimeProgressObserver;
#ifdef APFSACCESS_CALLBACK_PROGRESS_TESTING
    friend struct DeadlineTestAccess;
#endif
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    friend struct DeadlineStateTestAccess;
#endif
    enum class Boundary : std::uint8_t
    {
        OriginalSpool, Intent, Recovery,
        Control5, Control6, Control7, Control8, Certificate,
        Candidate0, Candidate1, Candidate2,
        OldRename0, OldRename1, OldRename2,
        NewRename0, NewRename1, NewRename2,
        Completion, Retirement, Ready, Publication,
        Count
    };
    static_assert(static_cast<unsigned>(Boundary::Count) == 21);

    static std::uint64_t After(std::uint64_t now,std::uint64_t interval) noexcept
    {
        constexpr auto maximum = (std::numeric_limits<std::uint64_t>::max)();
        return now > maximum - interval ? maximum : now + interval;
    }
    Result Complete(std::uint64_t now, const void* owner, std::uint32_t thread,
        std::uint64_t invocation, std::uint64_t ordinal, Boundary boundary) noexcept
    {
        if (cancelled_) return Result::Refused;
        if (Poll(now)) return absolute_expired_ ? Result::AbsoluteExpired : Result::Expired;
        const auto slot = static_cast<unsigned>(boundary);
        if (!writable_callback_ || !owner_ || owner != owner_ || !thread_ || thread != thread_ ||
            now < last_tick_ || !invocation || !ordinal ||
            slot >= static_cast<unsigned>(Boundary::Count) || invocation < invocation_)
            return Result::Refused;
        const bool next = invocation > invocation_;
        const auto prior_ordinal = next ? std::uint64_t{0} : ordinal_;
        const auto prior_slots = next ? std::uint32_t{0} : slots_;
        if (ordinal != prior_ordinal + 1 || (prior_slots & (std::uint32_t{1} << slot)))
            return Result::Refused;
        invocation_ = invocation;
        ordinal_ = ordinal;
        slots_ = prior_slots | (std::uint32_t{1} << slot);
        last_tick_ = now;
        const auto quiet_deadline=After(now,interval_ms);
        deadline_ = quiet_deadline<absolute_deadline_ ? quiet_deadline : absolute_deadline_;
        return Result::Renewed;
    }

    const void* owner_;
    std::uint32_t thread_;
    bool writable_callback_;
    bool cancelled_ = false, expired_ = false, absolute_expired_ = false;
    std::uint64_t last_tick_, deadline_, invocation_ = 0, ordinal_ = 0;
    const std::uint64_t absolute_deadline_;
    std::uint32_t slots_ = 0;
};
}
