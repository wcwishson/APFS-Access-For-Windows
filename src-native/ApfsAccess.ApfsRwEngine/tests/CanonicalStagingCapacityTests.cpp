#include "MetadataStore.h"
#include "TestFixtureBuilder.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace
{
using Store = apfsaccess::rw::MetadataStore;

void Check(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

struct Image
{
    std::filesystem::path path;
    explicit Image(std::uint64_t free_blocks)
    {
        apfsaccess::testfixture::BuilderStore spec;
        spec.authoritative_checkpoint = true;
        spec.block_count = 2048;
        spec.authoritative_checkpoint_ring_blocks = 16;
        spec.authoritative_internal_pool_blocks = 16;
        spec.authoritative_main_free_blocks = free_blocks;
        static unsigned serial = 0;
        path = std::filesystem::temp_directory_path() /
            ("apfs-canonical-capacity-" + std::to_string(GetCurrentProcessId()) +
                "-" + std::to_string(++serial) + ".img");
        const auto bytes = apfsaccess::testfixture::BuildStoreImage(spec);
        std::ofstream output(path, std::ios::binary);
        output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        Check(output.good(), "write fixture");
    }
    ~Image()
    {
        std::error_code error;
        std::filesystem::remove(path, error);
    }
    Store::VolumeContext Context() const
    {
        Store::VolumeContext context;
        context.device_path = path.wstring();
        context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        return context;
    }
};

std::vector<std::byte> PrivateCheckpointPayload()
{
    using namespace apfsaccess::testfixture;
    std::vector<std::byte> block(4096);
    PutBytes(block, 0, "APFSRWINOD4", 11);
    PutU64LE(block, 12, 7);
    PutU32LE(block, 20, 2);
    std::size_t cursor = 32;
    const auto add_inode = [&](std::uint64_t object, std::uint64_t parent,
                              bool directory, const std::wstring& name,
                              const std::wstring& path) {
        PutU64LE(block, cursor, object);
        PutU64LE(block, cursor + 8, parent);
        PutU64LE(block, cursor + 32, 7);
        PutU32LE(block, cursor + 40, directory ? 1 : 0);
        PutU32LE(block, cursor + 44, static_cast<std::uint32_t>(name.size()));
        PutU32LE(block, cursor + 48, static_cast<std::uint32_t>(path.size()));
        cursor += 52;
        for (const auto& text : {name, path})
            for (const wchar_t ch : text)
            {
                PutU16LE(block, cursor, static_cast<std::uint16_t>(ch));
                cursor += 2;
            }
    };
    add_inode(2, 2, true, L"", L"\\");
    add_inode(100, 2, false, L"forged", L"\\forged");
    PutU32LE(block, 24, static_cast<std::uint32_t>(cursor - 32));
    std::vector<std::byte> payload(6 * 1024 * 1024);
    for (std::size_t offset = 0; offset < payload.size(); offset += block.size())
        std::copy(block.begin(), block.end(), payload.begin() + offset);
    return payload;
}

void TestCanonicalCapacity(bool checkpoint_shaped = false, bool legacy_options = false)
{
    Image image(0);
    auto context = image.Context();
    context.allow_legacy_scaffold_for_fixtures = legacy_options;
    context.allow_legacy_private_checkpoint_writer_for_tests = legacy_options;
    std::vector<std::byte> payload(6 * 1024 * 1024);
    for (std::size_t index = 0; index < payload.size(); ++index)
        payload[index] = static_cast<std::byte>((index * 29u + 17u) & 0xffu);
    if (checkpoint_shaped) payload = PrivateCheckpointPayload();
    {
        Store store(context);
        Check(store.PrepareNativeWritePath(), "prepare canonical writer");
        store.SetFilePayloadProvider([&](const std::wstring& path, std::uint64_t size)
            -> std::optional<std::vector<std::byte>> {
            if (path != L"\\payload.bin" || size != payload.size()) return std::nullopt;
            return payload;
        });
        Store::MutationRequest create;
        create.operation = Store::MutationOperation::CreateFile;
        create.path = L"\\payload.bin";
        Check(store.StageMutation(create) == Store::MutationStatus::Applied, "stage create");
        auto write = create;
        write.operation = Store::MutationOperation::Write;
        write.length = payload.size();
        Check(store.StageMutation(write) == Store::MutationStatus::Applied,
            "canonical staging must use free space in the unused private checkpoint band");
        const auto status = store.CommitPendingMutations();
        if (status != Store::CommitStatus::Committed)
            std::wcerr << L"commit " << store.LastCommitFailureReason() << L" "
                << store.LastCommitFailureDetail() << L'\n';
        Check(status == Store::CommitStatus::Committed, "canonical allocation publishes");
    }
    Store reopened(context);
    Check(reopened.PrepareNativeWritePath(), "fresh authoritative reopen");
    Check(reopened.ReplayOrRecover(), "fresh canonical recovery");
    Check(!reopened.LookupCommittedInodeByPath(L"\\forged"),
        "checkpoint-shaped file bytes never become canonical namespace");
    std::vector<std::byte> actual;
    Check(reopened.ReadCommittedFileRange(L"\\payload.bin", 0, payload.size(), actual) &&
        actual == payload, "whole payload remains exact after reopen");
    const auto count = reopened.PendingMutationCount();
    const auto free = reopened.DebugWorkingFreeExtentTotalBytes();
    Store::MutationRequest too_large;
    too_large.operation = Store::MutationOperation::Write;
    too_large.path = L"\\payload.bin";
    too_large.offset = payload.size();
    too_large.length = 4 * 1024 * 1024;
    Check(reopened.StageMutation(too_large) == Store::MutationStatus::AllocationFailed,
        "real exhausted space still refuses");
    Check(reopened.PendingMutationCount() == count &&
        reopened.DebugWorkingFreeExtentTotalBytes() == free && !reopened.IsRecoveryRequired(),
        "failed allocation rolls back local staging without recovery debt");
}
}

int main()
{
    try
    {
        TestCanonicalCapacity();
        TestCanonicalCapacity(true);
        TestCanonicalCapacity(true, true);
        std::cout << "Canonical staging capacity PASS\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
