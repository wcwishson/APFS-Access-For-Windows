#pragma once
#include "WriteAheadLog.h"
#include <functional>

namespace apfsaccess::rw {
class TransactionManager;
class FusionJournalContinuation;
class FusionOriginalCapture final {
    friend class TransactionManager;
    friend class WriteAheadLog;
    friend class FusionJournalContinuation;
    FusionOriginalCapture() = default;
    std::filesystem::path path;
    std::string identity;
    std::uint64_t volume_serial=0, file_id=0, writer_generation=0;
    std::uint64_t next_transaction=0, next_sequence=0, accepted=0, floor=0;
    std::vector<std::uint8_t> bytes;
    std::vector<WriteAheadLog::Record> records;
};
// Minted only after the coordinator durably protects the full predecessor and
// proves its original/witness/endpoint correspondence under the held owner.
class FusionCertifiedPredecessor final {
    friend class TransactionManager;
    friend class WriteAheadLog;
    friend class FusionJournalContinuation;
    FusionCertifiedPredecessor() = default;
    const FusionOriginalCapture* original=nullptr;
    std::function<bool()> revalidate;
};
}
