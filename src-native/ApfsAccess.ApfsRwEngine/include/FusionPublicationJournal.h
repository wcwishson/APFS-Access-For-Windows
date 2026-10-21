#pragma once
#include <memory>
#include <string>
#include <cstdint>
#include <array>
#include <cstddef>
#include <vector>
#include <utility>

namespace apfsaccess::rw {
class FusionImageRuntime;
class FusionPreparedPublication;
// Private immutable publication stream. Only the runtime can supply a prepared
// capability; original accepted WAL evidence remains the recovery authority.
class FusionPublicationJournal final {
public:
    ~FusionPublicationJournal();
    FusionPublicationJournal(const FusionPublicationJournal&) = delete;
    FusionPublicationJournal& operator=(const FusionPublicationJournal&) = delete;
private:
    friend class FusionImageRuntime;
    friend class FusionJournalContinuation;
    explicit FusionPublicationJournal(std::wstring path);
    bool Pin(std::string&);
    bool Preflight(std::uint64_t sequence, const FusionPreparedPublication&, std::string&);
    bool Store(std::uint64_t sequence, const FusionPreparedPublication&, std::string&);
    bool Load(std::uint64_t sequence, std::unique_ptr<FusionPreparedPublication>&, std::string&);
    // Read-only census of original-cleaned history. This cannot finalize or
    // publish an accepted boundary; Load retains the replay durability barrier.
    bool LoadRetained(std::uint64_t sequence, std::unique_ptr<FusionPreparedPublication>&, std::string&);
    enum class ReadPurpose { PendingReplay, RetainedCensus };
    bool Read(std::uint64_t sequence, std::unique_ptr<FusionPreparedPublication>&, std::string&, ReadPurpose);
    void BindContinuationProof(const std::array<std::byte,32>&,const std::string&,std::uint64_t,
        std::uint64_t generation,std::uint64_t serial,std::uint64_t file);
    bool PinContinuationProof(const std::wstring&,const std::array<std::byte,32>&,std::string&);
    bool HasContinuationProof(std::uint64_t,const std::array<std::byte,32>&) const;
    void RememberContinuationProof(std::uint64_t,const std::array<std::byte,32>&,
        const std::vector<std::pair<std::uint64_t,std::string>>&);
    void AdvanceContinuationProof(const std::array<std::byte,32>&,const std::string&,std::uint64_t,
        std::uint64_t generation,std::uint64_t serial,std::uint64_t before,std::uint64_t after);
    struct State;
    std::unique_ptr<State> state_;
};
}
