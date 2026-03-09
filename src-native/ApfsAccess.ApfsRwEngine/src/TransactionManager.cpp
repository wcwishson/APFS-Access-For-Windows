#include "TransactionManager.h"

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <utility>

namespace apfsaccess::rw
{
TransactionManager::TransactionManager(std::wstring safety_level)
    : safety_level_(std::move(safety_level))
{
}

TransactionManager::State TransactionManager::CurrentState() const noexcept
{
    return state_;
}

bool TransactionManager::Begin()
{
    if (state_ != State::Idle)
    {
        return false;
    }

    current_transaction_id_ = next_transaction_id_++;
    pending_mutations_.clear();
    state_ = State::Active;
    NotifyStage("begin");
    return true;
}

bool TransactionManager::Commit()
{
    if (state_ != State::Active)
    {
        return false;
    }

    state_ = State::Committing;
    NotifyStage("commit-start");
    NotifyStage("prepare");
    NotifyStage("write-data");
    NotifyStage("write-metadata");
    if (!PersistTransactionLocked(L"committed"))
    {
        state_ = State::Failed;
        NotifyStage("commit-failed");
        return false;
    }
    NotifyStage("flush-data");
    NotifyStage("switch-checkpoint");
    NotifyStage("finalize");
    NotifyStage("commit-finish");
    pending_mutations_.clear();
    current_transaction_id_ = 0;
    state_ = State::Idle;
    return true;
}

bool TransactionManager::Abort()
{
    if (state_ == State::Idle)
    {
        return true;
    }

    state_ = State::Failed;
    NotifyStage("abort");
    (void)PersistTransactionLocked(L"aborted");
    pending_mutations_.clear();
    current_transaction_id_ = 0;
    state_ = State::Idle;
    return true;
}

bool TransactionManager::RecordMutation(const MutationIntent& mutation)
{
    if (state_ != State::Active)
    {
        return false;
    }

    pending_mutations_.push_back(mutation);
    NotifyStage("mutation-recorded");
    return true;
}

void TransactionManager::SetJournalPath(std::wstring journal_path)
{
    journal_path_ = std::move(journal_path);
}

std::uint64_t TransactionManager::CurrentTransactionId() const noexcept
{
    return current_transaction_id_;
}

std::size_t TransactionManager::PendingMutationCount() const noexcept
{
    return pending_mutations_.size();
}

void TransactionManager::SetFaultInjectionHook(std::function<void(const std::string& stage)> hook)
{
    fault_hook_ = std::move(hook);
}

void TransactionManager::NotifyStage(const std::string& stage)
{
    if (fault_hook_)
    {
        fault_hook_(stage);
    }
}

bool TransactionManager::PersistTransactionLocked(const wchar_t* outcome) const
{
    if (journal_path_.empty())
    {
        return true;
    }

    std::error_code ec;
    const auto journal_file = std::filesystem::path(journal_path_);
    std::filesystem::create_directories(journal_file.parent_path(), ec);
    if (ec)
    {
        return false;
    }

    std::wofstream out(journal_file, std::ios::app);
    if (!out.good())
    {
        return false;
    }

    out << L"{\"transactionId\":" << current_transaction_id_
        << L",\"safetyLevel\":\"" << EscapeJson(safety_level_)
        << L"\",\"outcome\":\"" << (outcome ? outcome : L"unknown")
        << L"\",\"mutationCount\":" << pending_mutations_.size()
        << L",\"mutations\":[";

    for (std::size_t i = 0; i < pending_mutations_.size(); ++i)
    {
        const auto& mutation = pending_mutations_[i];
        if (i != 0)
        {
            out << L",";
        }

        out << L"{\"kind\":\"" << MutationKindToString(mutation.kind)
            << L"\",\"path\":\"" << EscapeJson(mutation.path)
            << L"\",\"secondaryPath\":\"" << EscapeJson(mutation.secondary_path)
            << L"\",\"offset\":" << mutation.offset
            << L",\"length\":" << mutation.length
            << L",\"replaceIfExists\":" << (mutation.replace_if_exists ? L"true" : L"false")
            << L"}";
    }

    out << L"]}" << std::endl;
    return out.good();
}

std::wstring TransactionManager::EscapeJson(const std::wstring& value)
{
    std::wstring out;
    out.reserve(value.size());
    for (const wchar_t ch : value)
    {
        switch (ch)
        {
        case L'\\': out += L"\\\\"; break;
        case L'"': out += L"\\\""; break;
        case L'\r': out += L"\\r"; break;
        case L'\n': out += L"\\n"; break;
        case L'\t': out += L"\\t"; break;
        default:
            if (ch < 0x20)
            {
                std::wostringstream hex;
                hex << L"\\u" << std::hex << std::setw(4) << std::setfill(L'0') << static_cast<unsigned int>(ch);
                out += hex.str();
            }
            else
            {
                out.push_back(ch);
            }
            break;
        }
    }
    return out;
}

const wchar_t* TransactionManager::MutationKindToString(MutationKind kind)
{
    switch (kind)
    {
    case MutationKind::CreateFile: return L"create-file";
    case MutationKind::CreateDirectory: return L"create-directory";
    case MutationKind::Write: return L"write";
    case MutationKind::SetFileSize: return L"set-file-size";
    case MutationKind::Rename: return L"rename";
    case MutationKind::Delete: return L"delete";
    case MutationKind::SetBasicInfo: return L"set-basic-info";
    default: return L"unknown";
    }
}
} // namespace apfsaccess::rw
