#pragma once
#include "NativeSparse.h"

namespace apfsaccess::rw
{
// The inherited scope retains its layout. NSP2 gives payload_sha the explicitly
// versioned complete-ownership meaning and binds contributing bytes separately.
struct NativeSparseV2Proof : NativeSparseProof
{
    std::vector<NativeSparseSourceBlock> source_blocks;
    // Body 2 replays its original implicit-hole plan; body 3 emits hole records.
    std::uint64_t body_version = 3;
    bool operator==(const NativeSparseV2Proof&) const = default;
};
std::vector<std::byte> EncodeNativeSparseV2(const NativeSparseV2Proof&);
bool DecodeNativeSparseV2(std::span<const std::byte>, NativeSparseV2Proof&);
bool NativeSparseV2WalIsConsistent(const WriteAheadLog::Record&);
bool DecodeNativeSparseOriginalCheckpoint(std::span<const std::byte>, std::uint64_t& checkpoint);
}
