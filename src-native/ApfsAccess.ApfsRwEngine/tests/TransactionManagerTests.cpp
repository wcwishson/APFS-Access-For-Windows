#include "TransactionManager.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
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

    std::ifstream journal_in(journal_path, std::ios::binary);
    std::string journal_content;
    journal_content.assign(std::istreambuf_iterator<char>(journal_in), std::istreambuf_iterator<char>());
    ok &= Require(journal_content.find("\"outcome\":\"committed\"") != std::string::npos, "Journal should contain committed outcome");
    ok &= Require(journal_content.find("\"mutationCount\":1") != std::string::npos, "Journal should capture mutation count");

    apfsaccess::rw::TransactionManager::MutationIntent delete_mutation{};
    delete_mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::Delete;
    delete_mutation.path = L"\\docs\\tx.txt";
    ok &= Require(tx.Begin(), "Second Begin should succeed");
    ok &= Require(tx.RecordMutation(delete_mutation), "Second RecordMutation should succeed");
    ok &= Require(tx.Abort(), "Abort should succeed");
    ok &= Require(tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Idle, "State should return to idle after abort");

    std::ifstream journal_in2(journal_path, std::ios::binary);
    std::string journal_content2;
    journal_content2.assign(std::istreambuf_iterator<char>(journal_in2), std::istreambuf_iterator<char>());
    ok &= Require(journal_content2.find("\"outcome\":\"aborted\"") != std::string::npos, "Journal should contain aborted outcome");

    apfsaccess::rw::TransactionManager unicode_tx(L"Conservative");
    unicode_tx.SetJournalPath(journal_path.wstring());
    apfsaccess::rw::TransactionManager::MutationIntent unicode_mutation{};
    unicode_mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::CreateDirectory;
    unicode_mutation.path = L"\\unicode-\x6587\x4EF6-\xD83D\xDE80";
    ok &= Require(unicode_tx.Begin(), "Unicode Begin should succeed");
    ok &= Require(unicode_tx.RecordMutation(unicode_mutation), "Unicode RecordMutation should succeed");
    ok &= Require(unicode_tx.Commit(), "Unicode Commit should succeed");

    std::ifstream journal_in3(journal_path, std::ios::binary);
    std::vector<std::string> lines;
    for (std::string line; std::getline(journal_in3, line);)
    {
        lines.push_back(line);
    }
    ok &= Require(lines.size() == 3, "Journal should contain exactly one complete line per committed or aborted transaction");
    for (const auto& line : lines)
    {
        ok &= Require(!line.empty() && line.front() == '{' && line.back() == '}', "Each journal line should be a complete JSON object");
    }
    const auto unicode_path_utf8 = apfsaccess::rw::TransactionManager::WideToUtf8(unicode_mutation.path);
    ok &= Require(
        !unicode_path_utf8.empty() &&
        lines.back().find(unicode_path_utf8) != std::string::npos,
        "Journal should persist Unicode paths as UTF-8 without truncating the transaction line");

    std::filesystem::remove_all(run_root, ec);
    if (!ok)
    {
        return 1;
    }

    std::cout << "[PASS] TransactionManagerTests" << std::endl;
    return 0;
}
