#pragma once
#include "AppleCheckpointPublisher.h"
#include <array>
#include <map>

namespace apfsaccess::rw {
class FusionImageRuntime;
class FusionPublicationJournal;
// No public constructor, fields or serializer. Recovery bytes never directly
// authorize writes: original WAL commitment and canonical rederivation must match.
class FusionPreparedPublication final {
    friend class FusionImageRuntime;
    friend class FusionPublicationJournal;
    friend class FusionJournalContinuation;
    FusionPreparedPublication() = default;
    static constexpr std::size_t WriteLimit = 1024;
    static constexpr std::size_t GuardLimit = 8192;
    static constexpr std::size_t PreimageLimit = WriteLimit + 3;
    std::array<std::byte,32> source{}, payload_hash{};
    std::string jid, name;
    std::uint64_t volume = 0, inode = 0, offset = 0, length = 0, operation = 0;
    // Enrolled only from the held original TM after acceptance. The preflight
    // commitment excludes these IDs; the immutable witness envelope binds them.
    std::uint64_t accepted_sequence = 0, transaction_id = 0, mutation_sequence = 0;
    std::vector<std::byte> payload;
    AppleCheckpointPublicationPlan plan;
    std::map<std::uint64_t,std::vector<std::byte>> before;
    bool Encode(std::vector<std::byte>&, std::string&) const;
    static bool Decode(std::span<const std::byte>, FusionPreparedPublication&, std::string&);
    bool Digest(std::string&, std::string&) const;
};
bool FusionPublicationHash(std::span<const std::byte>,std::array<std::byte,32>&);
}
