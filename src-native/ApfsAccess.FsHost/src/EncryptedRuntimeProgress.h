#pragma once
#include "EncryptedMountState.h"

namespace encrypted_mount
{
struct RuntimeProgressObserver final
{
    explicit RuntimeProgressObserver(State& state) noexcept : state_(state),owner_(state.writer.get()) {}

    bool operator()(const apfsaccess::catalog::EncryptedImageRuntime::DurableProgress& event) const
    {
        if(state_.failed.load() || state_.cancelled->load())return false;
        auto* operation=State::Operation::current_;
        if(!owner_ || event.Owner()!=owner_ || state_.writer.get()!=owner_ ||
            !operation || &operation->state!=&state_ || !Matches(event)) {
            state_.Fail(State::Failure::InvalidCompletedProgress);return false;
        }
        const auto completed=operation->CompleteAt(*owner_,event.Invocation(),event.Ordinal(),
            static_cast<OperationDeadline::Boundary>(event.Slot()),GetTickCount64());
        if(!completed && !state_.cancelled->load())state_.Fail(State::Failure::InvalidCompletedProgress);
        return completed;
    }

private:
    static bool Matches(const apfsaccess::catalog::EncryptedImageRuntime::DurableProgress& event) noexcept
    {
        using Boundary=apfsaccess::catalog::EncryptedImageRuntime::DurableBoundary;
        const auto slot=event.Slot();
        switch(event.Boundary()) {
        case Boundary::OriginalSpoolBarrier:return slot==0;
        case Boundary::IntentFlushed:return slot==1;
        case Boundary::RecoveryBarrier:return slot==2;
        case Boundary::ControlRenamed:return slot>=3 && slot<=6;
        case Boundary::CertificatePromoted:return slot==7;
        case Boundary::CandidateFlushed:return slot>=8 && slot<=10;
        case Boundary::OldRenamed:return slot>=11 && slot<=13;
        case Boundary::NewRenamed:return slot>=14 && slot<=16;
        case Boundary::CompletionReceipt:return slot==17;
        case Boundary::RetirementReceipt:return slot==18;
        case Boundary::ReadyReceipt:return slot==19;
        case Boundary::PublicationReconciled:return slot==20;
        }
        return false;
    }
    State& state_;
    const apfsaccess::catalog::EncryptedImageRuntime* owner_;
};
}
