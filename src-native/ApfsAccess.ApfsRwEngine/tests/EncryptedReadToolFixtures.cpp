#include "ApfsEncryptedReadSession.h"
#include "ApfsEncryptedReadVectors.h"
#include "ApfsKeybagUnlockVectors.h"
#include "TestFixtureBuilder.h"
#include <functional>
#include <fstream>
#include <iostream>
using namespace apfsaccess::catalog;
using namespace apfsaccess::testfixture;
namespace f=apfsaccess::encrypted_fixture;
namespace k=apfsaccess::keybag_fixture;
std::vector<std::byte> Hex(std::string_view s) { return HexToBytes(std::string(s)); }
class Source final : public ImmutableEncryptedReadSource
{
public:
    std::uint32_t bs;
    std::uint64_t root_block, size, revision = 521;
    std::string identity = "public-fixture-521";
    std::shared_ptr<ApfsReadBudget> budget;
    std::vector<std::byte> image, root, child, data, last;
    mutable std::uint64_t reads = 0;
    mutable std::function<void(std::uint64_t)> before;
    std::uint64_t fault_offset = UINT64_MAX;
    int fault = -1;
    explicit Source(unsigned profile = 0, std::uint64_t allowance = 100000)
        : bs(profile == 1 ? 65536 : 4096), root_block(profile == 2 ? 0x100000050ULL : 80),
          size((profile == 2 ? root_block + 128 : 128) * bs),
          budget(std::make_shared<ApfsReadBudget>(allowance, 1024ULL*1024*1024, 1000000, 1024ULL*1024*1024))
    {
        BuilderStore spec;
        spec.authoritative_checkpoint = true; spec.block_count = 128; spec.block_size = bs;
        spec.uuid_hex = std::string(k::ContainerUuid); spec.volumes[0].uuid_hex = std::string(k::VolumeUuid);
        spec.volumes[0].fs_flags = kFsFlagOneKey;
        image = BuildStoreImage(spec);
        for (std::size_t offset = 0; offset + bs <= image.size(); offset += bs)
        {
            if (ReadU32LE(image, offset + 32) != kNxsbMagic) continue;
            MutateAt(offset / bs, [&](auto& block) {
                PutU32LE(block, 24, kObjectEphemeral | kNxSuperblockObjectType);
                PutU64LE(block, 40, size / bs); PutU64LE(block, 0x510, 60); PutU64LE(block, 0x518, 1);
            });
        }
        const auto volume_map = ReadU64LE(image, 4ULL * bs + 0x80).value();
        const auto tree = ReadU64LE(image, volume_map * bs + 48).value();
        const auto omap = BuildBtreeNode({OmapRecordSpec{8293, root_block, 4, 7}, OmapRecordSpec{9000, root_block+1, 4, 7}},
            7, bs, 0, tree, 0x40000002, 11);
        std::copy(omap.begin(), omap.end(), image.begin() + tree * bs);
        root = Hex(profile == 1 ? f::LargeRoot : profile == 2 ? f::HighRoot : f::SmallRoot);
        child = Hex(profile == 1 ? f::LargeChild : profile == 2 ? f::HighChild : f::SmallChild);
        data = Hex(profile == 1 ? f::LargeData : profile == 2 ? f::HighData : f::SmallData);
        last = Hex(profile == 1 ? f::LargeLast : profile == 2 ? f::HighLast : f::SmallLast);
        if (!profile)
        {
            const auto container = Hex(k::ContainerCipher), volume = Hex(k::VolumeCipher);
            std::copy(container.begin(), container.end(), image.begin() + 60 * bs);
            std::copy(volume.begin(), volume.end(), image.begin() + 61 * bs);
        }
    }
    void MutateAt(std::uint64_t block_index, const std::function<void(std::vector<std::byte>&)>& change)
    {
        const auto offset = block_index * bs;
        std::vector<std::byte> block(image.begin()+offset, image.begin()+offset+bs);
        change(block); (void)FletcherForBlock(block, bs);
        std::copy(block.begin(), block.end(), image.begin()+offset);
    }
    std::uint64_t SizeBytes() const override { return size; }
    std::uint64_t Revision() const override { return revision; }
    std::string SourceIdentity() const override { return identity; }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return budget; }
    bool Read(std::uint64_t offset, std::size_t count, std::vector<std::byte>& out) const override
    {
        out.clear();
        if (!budget->Read(count)) return false;
        ++reads;
        if (before) before(offset);
        if (offset == fault_offset)
        {
            out.assign(count+1, std::byte{0x55});
            if (fault == 0) { out.resize(count-1); return true; }
            if (fault == 1) return true;
            if (fault == 2) return false;
            if (fault == 3) throw std::bad_alloc();
            throw std::runtime_error("public source fault");
        }
        for (const auto& part : {std::pair{root_block*bs, &root}, { (root_block+1)*bs, &child },
                {100ULL*bs, &data}, {104ULL*bs, &last}})
        {
            if (offset >= part.first && offset-part.first < part.second->size())
            {
                const auto relative = offset-part.first;
                if (count > part.second->size()-relative) return false;
                out.assign(part.second->begin()+relative, part.second->begin()+relative+count); return true;
            }
        }
        if (offset > image.size() || count > image.size()-offset) return false;
        out.assign(image.begin()+offset, image.begin()+offset+count); return true;
    }
};
std::vector<std::byte> Expected(std::uint32_t bs)
{
    std::vector<std::byte> bytes(4ULL*bs-137);
    for (std::size_t i = 0; i < 2ULL*bs; ++i) bytes[i] = static_cast<std::byte>((i*29+i/251+17)%256);
    for (std::size_t i = 0; i < bs-137; ++i) bytes[3ULL*bs+i] = static_cast<std::byte>((i*13+i/71+83)%256);
    return bytes;
}

void Write(const std::filesystem::path& p, const std::vector<std::byte>& bytes) {
    std::ofstream out(p,std::ios::binary); out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());
    if(!out) throw std::runtime_error("fixture output failure");
}
int wmain(int argc,wchar_t** argv) {
    if(argc!=2) return 2;
    const std::filesystem::path root(argv[1]); std::filesystem::create_directories(root);
    Source source;
    for(const auto& part : {std::pair{80ULL,&source.root}, {81ULL,&source.child}, {100ULL,&source.data}, {104ULL,&source.last}})
        std::copy(part.second->begin(),part.second->end(),source.image.begin()+part.first*source.bs);
    Write(root/L"encrypted.img",source.image);
    auto scoped = std::vector<std::byte>(4096, std::byte{0x44});
    scoped.insert(scoped.end(),source.image.begin(),source.image.end());
    scoped.insert(scoped.end(),4096,std::byte{0x55});
    Write(root/L"scoped.img",scoped);
    Write(root/L"expected.bin",Expected(4096));
    source.MutateAt(4,[](auto& block){PutU64LE(block,0x108,0);});
    Write(root/L"unsupported.img",source.image);
    std::cout << "public encrypted fixtures generated\n";
}
