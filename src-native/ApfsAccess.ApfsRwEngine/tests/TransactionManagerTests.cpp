#include "TransactionManager.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>
#include <chrono>

namespace
{
bool Require(bool condition, const std::string& message)
{
    if (!condition)
    {
        std::cerr << "[FAIL] " << message << std::endl;
        return false;
    }

    return true;
}

bool Contains(const std::wstring& haystack, const std::wstring& needle)
{
    return haystack.find(needle) != std::wstring::npos;
}
} // namespace

int main()
{
    std::error_code ec;
    const auto unique_id = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto run_root = std::filesystem::temp_directory_path(ec) / ("ApfsAccessTxTests_" + std::to_string(unique_id));
    if (ec)
    {
        std::cerr << "[FAIL] unable to access temporary directory" << std::endl;
        return 1;
    }

    std::filesystem::remove_all(run_root, ec);
    ec.clear();
    std::filesystem::create_directories(run_root, ec);
    if (ec)
    {
        std::cerr << "[FAIL] unable to create test directory" << std::endl;
        return 1;
    }

    const auto journal_path = run_root / "rw-journal.jsonl";
    apfsaccess::rw::TransactionManager tx(L"Conservative");
    tx.SetJournalPath(journal_path.wstring());

    std::vector<std::string> stages;
    tx.SetFaultInjectionHook([&stages](const std::string& stage)
    {
        stages.push_back(stage);
    });

    bool ok = true;
    ok &= Require(tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Idle, "Initial state should be idle");
    ok &= Require(tx.Begin(), "Begin should succeed from idle state");
    ok &= Require(tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Active, "State should be active after begin");
    ok &= Require(tx.CurrentTransactionId() == 1, "First transaction id should be 1");

    apfsaccess::rw::TransactionManager::MutationIntent mutation{};
    mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::CreateFile;
    mutation.path = L"\\docs\\tx.txt";
    ok &= Require(tx.RecordMutation(mutation), "RecordMutation should succeed in active state");
    ok &= Require(tx.PendingMutationCount() == 1, "Pending mutation count should be 1");

    ok &= Require(tx.Commit(), "Commit should succeed");
    ok &= Require(tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Idle, "State should return to idle after commit");
    ok &= Require(tx.PendingMutationCount() == 0, "Pending mutation count should be reset after commit");

    const std::vector<std::string> expected_stages =
    {
        "begin",
        "mutation-recorded",
        "commit-start",
        "prepare",
        "write-data",
        "write-metadata",
        "flush-data",
        "switch-checkpoint",
        "finalize",
        "commit-finish",
    };
    ok &= Require(stages == expected_stages, "Stage callback sequence should match commit state machine");

    std::wifstream journal_in(journal_path);
    std::wstring journal_content;
    journal_content.assign(std::istreambuf_iterator<wchar_t>(journal_in), std::istreambuf_iterator<wchar_t>());
    ok &= Require(Contains(journal_content, L"\"outcome\":\"committed\""), "Journal should contain committed outcome");
    ok &= Require(Contains(journal_content, L"\"mutationCount\":1"), "Journal should capture mutation count");

    apfsaccess::rw::TransactionManager::MutationIntent delete_mutation{};
    delete_mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::Delete;
    delete_mutation.path = L"\\docs\\tx.txt";
    ok &= Require(tx.Begin(), "Second Begin should succeed");
    ok &= Require(tx.RecordMutation(delete_mutation), "Second RecordMutation should succeed");
    ok &= Require(tx.Abort(), "Abort should succeed");
    ok &= Require(tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Idle, "State should return to idle after abort");

    std::wifstream journal_in2(journal_path);
    std::wstring journal_content2;
    journal_content2.assign(std::istreambuf_iterator<wchar_t>(journal_in2), std::istreambuf_iterator<wchar_t>());
    ok &= Require(Contains(journal_content2, L"\"outcome\":\"aborted\""), "Journal should contain aborted outcome");

    std::filesystem::remove_all(run_root, ec);
    if (!ok)
    {
        return 1;
    }

    std::cout << "[PASS] TransactionManagerTests" << std::endl;
    return 0;
}
