#include "ApfsFusionCheckpointTarget.h"

#include <limits>

namespace apfsaccess::rw
{
ApfsFusionCheckpointTarget::ApfsFusionCheckpointTarget(
    const catalog::ApfsFusionStore& store,
    catalog::ApfsFusionWriteSession& writer,
    std::uint32_t block_size)
    : store_(&store), writer_(&writer), block_size_(block_size)
{
    binding_valid_ = writer.IsBoundTo(store) && block_size != 0 &&
        block_size == writer.BlockSize() && block_size == store.Checkpoint().superblock.block_size;
}

bool ApfsFusionCheckpointTarget::ReadBlock(std::uint64_t physical_block,
    std::uint32_t block_size, std::vector<std::byte>& out_bytes)
{
    out_bytes.clear();
    std::string error;
    if (!binding_valid_ || !writer_->CheckAvailable(error) || block_size != block_size_ ||
        physical_block > std::numeric_limits<std::uint64_t>::max() / block_size)
        return false;
    return store_->Read(physical_block * static_cast<std::uint64_t>(block_size),
        block_size, out_bytes) && out_bytes.size() == block_size;
}

bool ApfsFusionCheckpointTarget::WriteBlock(std::uint64_t physical_block,
    std::span<const std::byte> bytes)
{
    if (!binding_valid_) return false;
    std::string error;
    return writer_->WriteBlocks(physical_block, bytes, error);
}

bool ApfsFusionCheckpointTarget::Flush()
{
    if (!binding_valid_) return false;
    std::string error;
    return writer_->FlushOrdered(error);
}
} // namespace apfsaccess::rw
