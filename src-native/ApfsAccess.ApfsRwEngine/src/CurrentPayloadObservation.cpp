#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifdef _WIN32
#include <Windows.h>
#include <bcrypt.h>
#else
#include <utf8proc.h>
#endif
#include "CurrentPayloadObservation.h"
#include "ApfsExtendedRecordCodec.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <tuple>

namespace apfsaccess::catalog::payload
{
namespace
{
using Inode = rw::MetadataStore::InodeRecord;
using Extent = rw::MetadataStore::FileExtent;
struct Stop { Reason reason; };

struct Guard {
    const std::shared_ptr<catalog::ApfsReadBudget>& budget;
    const std::function<bool()>& deadline;
    void Check() const {
        if (!budget || !deadline) throw Stop{Reason::InvalidBinding};
        if (budget->Failed()) throw Stop{Reason::SharedBudget};
        bool alive = false;
        try { alive = deadline(); } catch (...) { throw Stop{Reason::CallbackFailure}; }
        if (!alive) {
            budget->Refuse("CurrentPayloadDeadline");
            throw Stop{Reason::Deadline};
        }
    }
    void Materialize(std::uint64_t count, std::uint64_t bytes) const {
        Check();
        if (!budget->Materialize(count, bytes)) throw Stop{Reason::SharedBudget};
    }
    [[noreturn]] void Limit(Reason reason, const char* name) const {
        budget->Refuse(name);
        throw Stop{reason};
    }
};

bool ValidName(std::string_view name) {
    if (name.empty() || name.size() > 4096 || name.find('\0') != name.npos) return false;
#ifdef _WIN32
    return
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.data(),
            static_cast<int>(name.size()), nullptr, 0) > 0;
#else
    for (std::size_t at = 0; at < name.size();) {
        utf8proc_int32_t codepoint = 0;
        const auto length = utf8proc_iterate(
            reinterpret_cast<const utf8proc_uint8_t*>(name.data() + at),
            static_cast<utf8proc_ssize_t>(name.size() - at), &codepoint);
        if (length <= 0) return false;
        at += static_cast<std::size_t>(length);
    }
    return true;
#endif
}

bool ByteLess(std::string_view a, std::string_view b) {
    return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end(),
        [](char x, char y) { return static_cast<unsigned char>(x) < static_cast<unsigned char>(y); });
}

bool EntryLess(const Entry& a, const Entry& b) {
    const auto left = std::tie(a.kind, a.inodeOid, a.streamOid);
    const auto right = std::tie(b.kind, b.inodeOid, b.streamOid);
    if (left != right) return left < right;
    if (a.nameUtf8.has_value() != b.nameUtf8.has_value()) return !a.nameUtf8;
    return a.nameUtf8 && ByteLess(*a.nameUtf8, *b.nameUtf8);
}

struct Plan {
    Kind kind = Kind::FileData;
    std::uint64_t inode = 0, stream = 0, size = 0;
    const std::string* name = nullptr;
    const std::vector<std::byte>* embedded = nullptr;
    std::span<const Extent> extents;
    bool unsupported = false;
};

void CheckRanges(const Plan& plan, SourceWindow window, const Guard& guard,
    std::optional<std::uint64_t> allocated = {}) {
    std::uint64_t end = 0;
    for (const auto& extent : plan.extents) {
        guard.Check();
        if (extent.bytes == 0 || extent.logical_offset != end || extent.bytes > UINT64_MAX - end)
            throw Stop{Reason::InvalidProjection};
        end += extent.bytes;
        if (extent.physical_address == 0) {
            if (plan.kind == Kind::Xattr) throw Stop{Reason::InvalidProjection};
            // Only explicit holes from the caller's admitted projection qualify.
        } else if (extent.physical_address < window.offsetBytes ||
            extent.physical_address - window.offsetBytes > window.sizeBytes ||
            extent.bytes > window.sizeBytes - (extent.physical_address - window.offsetBytes)) {
            throw Stop{Reason::InvalidProjection};
        }
    }
    if (end < plan.size || (allocated && end != *allocated)) throw Stop{Reason::InvalidProjection};
}

// Only projection descriptors are inspected; no tree/record/namespace decoding.
template<class Visit>
void VisitPlans(const Request& request, std::span<const Inode* const> inodes,
    const Guard& guard, Visit visit) {
    const auto& projection = request.projection;
    for (const auto* inode : inodes) {
        guard.Check();
        if (inode->node_type != rw::MetadataStore::NodeType::RegularFile) continue;
        if (inode->is_directory || (inode->mode & 0170000) != 0100000 || inode->private_id == 0)
            throw Stop{Reason::InvalidProjection};
        Plan plan;
        plan.inode = inode->object_id;
        plan.stream = inode->private_id;
        plan.size = inode->logical_size;
        const auto attributes = projection.extended_attributes_by_inode.find(inode->object_id);
        plan.unsupported = (inode->bsd_flags & rw::kAppleBsdCompressedFlag) != 0 ||
            (attributes != projection.extended_attributes_by_inode.end() &&
                attributes->second.contains("com.apple.decmpfs"));
        const auto extents = projection.read_extents_by_inode.find(inode->object_id);
        if (extents != projection.read_extents_by_inode.end()) plan.extents = extents->second;
        visit(plan);
    }
    for (const auto& [owner, attributes] : projection.extended_attributes_by_inode) {
        guard.Check();
        const auto found = std::lower_bound(inodes.begin(), inodes.end(), owner,
            [](const Inode* inode, std::uint64_t id) { return inode->object_id < id; });
        if (found == inodes.end() || (*found)->object_id != owner) throw Stop{Reason::InvalidProjection};
        for (const auto& [name, attribute] : attributes) {
            guard.Check();
            if (attribute.object_id != owner || name != attribute.name_utf8 || !ValidName(name))
                throw Stop{Reason::InvalidProjection};
            Plan plan;
            plan.kind = Kind::Xattr;
            plan.inode = owner;
            plan.name = &name;
            const auto representation = attribute.flags & ~rw::kAppleXattrFileSystemOwned;
            if (representation == rw::kAppleXattrDataEmbedded) {
                plan.size = attribute.data.size();
                plan.embedded = &attribute.data;
            } else if (representation == rw::kAppleXattrDataStream) {
                if (attribute.data.size() != rw::kAppleXattrDataStreamBytes)
                    throw Stop{Reason::InvalidProjection};
                plan.stream = *catalog::ReadU64LE(attribute.data, 0);
                plan.size = *catalog::ReadU64LE(attribute.data, 8);
                const auto allocated = *catalog::ReadU64LE(attribute.data, 16);
                if (*catalog::ReadU64LE(attribute.data, 24) != 0)
                    throw Stop{Reason::UnsupportedRepresentation};
                if (plan.stream == 0 || plan.size > allocated) throw Stop{Reason::InvalidProjection};
                const auto extents = projection.attribute_stream_extents.find(plan.stream);
                if (extents == projection.attribute_stream_extents.end() || !extents->second)
                    throw Stop{Reason::InvalidProjection};
                plan.extents = *extents->second;
                CheckRanges(plan, request.window, guard, allocated);
            } else {
                throw Stop{Reason::UnsupportedRepresentation};
            }
            visit(plan);
        }
    }
}

#ifdef _WIN32
class Sha256 {
    BCRYPT_ALG_HANDLE algorithm_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
    std::vector<unsigned char> object_;
public:
    explicit Sha256(const Guard& guard) {
        if (BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
            throw Stop{Reason::HashProviderFailure};
        try {
            ULONG bytes = 0, written = 0;
            if (BCryptGetProperty(algorithm_, BCRYPT_OBJECT_LENGTH,
                    reinterpret_cast<PUCHAR>(&bytes), sizeof(bytes), &written, 0) < 0 ||
                written != sizeof(bytes) || bytes == 0 || bytes > ChunkBytes)
                throw Stop{Reason::HashProviderFailure};
            guard.Materialize(0, bytes);
            object_.resize(bytes);
        } catch (...) {
            BCryptCloseAlgorithmProvider(algorithm_, 0);
            algorithm_ = nullptr;
            throw;
        }
    }
    ~Sha256() {
        if (hash_) BCryptDestroyHash(hash_);
        if (algorithm_) BCryptCloseAlgorithmProvider(algorithm_, 0);
    }
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;
    void Begin() {
        if (hash_) { BCryptDestroyHash(hash_); hash_ = nullptr; }
        if (BCryptCreateHash(algorithm_, &hash_, object_.data(),
                static_cast<ULONG>(object_.size()), nullptr, 0, 0) < 0)
            throw Stop{Reason::HashProviderFailure};
    }
    void Feed(const std::byte* data, std::size_t count) {
        if (count > ChunkBytes || BCryptHashData(hash_,
                reinterpret_cast<PUCHAR>(const_cast<std::byte*>(data)), static_cast<ULONG>(count), 0) < 0)
            throw Stop{Reason::HashProviderFailure};
    }
    std::string Finish() {
        std::array<unsigned char, 32> bytes{};
        if (BCryptFinishHash(hash_, bytes.data(), static_cast<ULONG>(bytes.size()), 0) < 0)
            throw Stop{Reason::HashProviderFailure};
        std::string hex(64, '0');
        constexpr char alphabet[] = "0123456789abcdef";
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            hex[i * 2] = alphabet[bytes[i] >> 4];
            hex[i * 2 + 1] = alphabet[bytes[i] & 15];
        }
        return hex;
    }
};
#else
class Sha256 {
public:
    explicit Sha256(const Guard&) { throw Stop{Reason::HashProviderUnavailable}; }
    void Begin() { throw Stop{Reason::HashProviderUnavailable}; }
    void Feed(const std::byte*, std::size_t) { throw Stop{Reason::HashProviderUnavailable}; }
    std::string Finish() { throw Stop{Reason::HashProviderUnavailable}; }
};
#endif

Outcome OutcomeFor(Reason reason) {
    switch (reason) {
    case Reason::LogicalLimit: case Reason::EntryLimit: case Reason::SharedBudget:
    case Reason::Deadline: case Reason::SourceReadFailure: case Reason::OutputLimit:
    case Reason::AdmissionNotComplete:
        return Outcome::Incomplete;
    case Reason::UnsupportedRepresentation: case Reason::HashProviderUnavailable: return Outcome::Unsupported;
    default: return Outcome::Error;
    }
}

ReadOutcome RowOutcomeFor(Reason reason) {
    switch (reason) {
    case Reason::LogicalLimit: case Reason::EntryLimit: case Reason::SharedBudget:
    case Reason::Deadline: return ReadOutcome::BudgetExceeded;
    case Reason::UnsupportedRepresentation: case Reason::HashProviderUnavailable: return ReadOutcome::Unsupported;
    default: return ReadOutcome::ReadFailure;
    }
}

struct Sink {
    std::string* output;
    std::size_t max, size = 0;
    void Text(std::string_view text) {
        if (text.size() > max - size) throw Stop{Reason::OutputLimit};
        size += text.size();
        if (output) output->append(text);
    }
    void Number(std::uint64_t value) {
        char buffer[32];
        const auto converted = std::to_chars(buffer, buffer + sizeof(buffer), value);
        Text("\""); Text({buffer, static_cast<std::size_t>(converted.ptr - buffer)}); Text("\"");
    }
    void String(std::string_view text) {
        Text("\"");
        constexpr char alphabet[] = "0123456789abcdef";
        for (const unsigned char c : text) {
            if (c == '"') Text("\\\"");
            else if (c == '\\') Text("\\\\");
            else if (c < 0x20) {
                const char escaped[] = {'\\', 'u', '0', '0', alphabet[c >> 4], alphabet[c & 15]};
                Text({escaped, sizeof(escaped)});
            } else { const char byte = static_cast<char>(c); Text({&byte, 1}); }
        }
        Text("\"");
    }
};

void ValidateResult(const Result& result, const Guard& guard) {
    if (result.entries.size() > MaxEntries ||
        (!result.enumerationComplete && (!result.entries.empty() || result.logicalBytesRead != 0)))
        throw Stop{Reason::InvalidProjection};
    std::uint64_t read = 0, size = 0;
    bool all = result.enumerationComplete;
    for (std::size_t i = 0; i < result.entries.size(); ++i) {
        guard.Check();
        const auto& e = result.entries[i];
        if (Name(e.kind).empty() || Name(e.readOutcome).empty() || e.inodeOid == 0 ||
            (e.kind == Kind::FileData && (e.nameUtf8 || e.streamOid == 0)) ||
            (e.kind == Kind::Xattr && (!e.nameUtf8 || !ValidName(*e.nameUtf8))) ||
            e.logicalBytesRead > e.logicalSizeBytes || e.logicalSizeBytes > MaxLogicalBytes - size ||
            e.logicalBytesRead > MaxLogicalBytes - read || (i && !EntryLess(result.entries[i - 1], e)))
            throw Stop{Reason::InvalidProjection};
        for (std::size_t j = 0; j < i; ++j) {
            guard.Check();
            const auto& other = result.entries[j];
            if (e.kind == other.kind && e.inodeOid == other.inodeOid &&
                (e.kind == Kind::FileData || e.nameUtf8 == other.nameUtf8))
                throw Stop{Reason::InvalidProjection};
        }
        size += e.logicalSizeBytes;
        read += e.logicalBytesRead;
        const bool complete = e.readOutcome == ReadOutcome::Complete;
        all &= complete;
        if (complete) {
            if (e.logicalBytesRead != e.logicalSizeBytes || !e.observedSha256 || e.observedSha256->size() != 64 ||
                e.observedSha256->find_first_not_of("0123456789abcdef") != std::string::npos ||
                (e.logicalSizeBytes == 0 && *e.observedSha256 !=
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
                throw Stop{Reason::InvalidProjection};
        } else if (e.observedSha256 ||
            ((e.readOutcome == ReadOutcome::NotRead || e.readOutcome == ReadOutcome::Unsupported) && e.logicalBytesRead != 0))
            throw Stop{Reason::InvalidProjection};
    }
    if (read != result.logicalBytesRead || result.readComplete != all || result.hashesObserved != all ||
        result.exactComplete() != all || (all && result.reason != Reason::None) ||
        (!all && (result.reason == Reason::None || result.outcome != OutcomeFor(result.reason))))
        throw Stop{Reason::InvalidProjection};
}

void EmitInventory(const Result& result, const Guard& guard, Sink& sink) {
    guard.Check();
    sink.Text("{\"scopeKind\":\"selected-current-volume\",\"algorithm\":\"SHA256\",\"enumerationComplete\":");
    sink.Text(result.enumerationComplete ? "true" : "false");
    sink.Text(",\"readComplete\":"); sink.Text(result.readComplete ? "true" : "false");
    sink.Text(",\"hashesObserved\":"); sink.Text(result.hashesObserved ? "true" : "false");
    sink.Text(",\"expectedComparison\":\"NotSupplied\",\"maxLogicalBytes\":"); sink.Number(MaxLogicalBytes);
    sink.Text(",\"maxEntries\":"); sink.Number(MaxEntries);
    sink.Text(",\"entryCount\":"); sink.Number(result.entries.size());
    sink.Text(",\"logicalBytesRead\":"); sink.Number(result.logicalBytesRead);
    sink.Text(",\"entries\":[");
    bool first = true;
    for (const auto& e : result.entries) {
        guard.Check();
        if (!first) sink.Text(",");
        first = false;
        sink.Text("{\"kind\":"); sink.String(Name(e.kind));
        sink.Text(",\"inodeOid\":"); sink.Number(e.inodeOid);
        sink.Text(",\"streamOid\":"); sink.Number(e.streamOid);
        sink.Text(",\"nameUtf8\":"); if (e.nameUtf8) sink.String(*e.nameUtf8); else sink.Text("null");
        sink.Text(",\"logicalSizeBytes\":"); sink.Number(e.logicalSizeBytes);
        sink.Text(",\"logicalBytesRead\":"); sink.Number(e.logicalBytesRead);
        sink.Text(",\"readOutcome\":"); sink.String(Name(e.readOutcome));
        sink.Text(",\"observedSha256\":"); if (e.observedSha256) sink.String(*e.observedSha256); else sink.Text("null");
        sink.Text(",\"expectedSha256\":null}");
    }
    sink.Text("]}");
    guard.Check();
}
}

Result ObserveCurrentPayload(const Request& request) {
    Result result;
    result.sharedBudget = request.budget;
    result.aliases = request.projection.directory_links;
    const Guard guard{request.budget, request.withinDeadline};
    std::optional<std::size_t> active;
    try {
        guard.Check();
#ifndef _WIN32
        throw Stop{Reason::HashProviderUnavailable};
#endif
        const auto& p = request.projection;
        const auto sourceBudget = request.source.ReadBudget();
        if (sourceBudget && sourceBudget != request.budget) {
            request.budget->Refuse("ApfsReadBudgetIdentityMismatch");
            throw Stop{Reason::InvalidBinding};
        }
        const auto w = request.window;
        if (!p.volume_object_id || !p.checkpoint_xid || !p.block_size || !p.total_blocks ||
            p.total_blocks > UINT64_MAX / p.block_size || w.sizeBytes != p.total_blocks * p.block_size ||
            w.offsetBytes % p.block_size != 0 || w.offsetBytes > request.source.SizeBytes() ||
            w.sizeBytes > request.source.SizeBytes() - w.offsetBytes)
            throw Stop{Reason::InvalidBinding};
        if (p.inodes.size() > UINT64_MAX / sizeof(const Inode*)) throw Stop{Reason::InvalidProjection};
        guard.Materialize(p.inodes.size(), p.inodes.size() * sizeof(const Inode*));
        std::vector<const Inode*> inodes;
        inodes.reserve(p.inodes.size());
        for (const auto& inode : p.inodes) { guard.Check(); inodes.push_back(&inode); }
        std::sort(inodes.begin(), inodes.end(), [&](const Inode* a, const Inode* b) {
            guard.Check();
            return a->object_id < b->object_id;
        });
        for (std::size_t i = 0; i < inodes.size(); ++i) {
            guard.Check();
            if (!inodes[i]->object_id || (i && inodes[i - 1]->object_id == inodes[i]->object_id))
                throw Stop{Reason::InvalidProjection};
        }
        std::uint64_t count = 0, total = 0, names = 0;
        VisitPlans(request, inodes, guard, [&](const Plan& plan) {
            if (count == MaxEntries) guard.Limit(Reason::EntryLimit, "CurrentPayloadEntryLimit");
            if (plan.size > MaxLogicalBytes - total) guard.Limit(Reason::LogicalLimit, "CurrentPayloadLogicalLimit");
            ++count; total += plan.size;
            if (plan.name) names += plan.name->size() + 1;
            if (!plan.embedded && !plan.unsupported) CheckRanges(plan, w, guard);
        });
        // Charge both plan storage and published rows/digests before allocating.
        guard.Materialize(count, count * (sizeof(Plan) + sizeof(Entry) + 128) + names);
        std::vector<Plan> plans;
        plans.reserve(static_cast<std::size_t>(count));
        result.entries.reserve(static_cast<std::size_t>(count));
        VisitPlans(request, inodes, guard, [&](const Plan& plan) { plans.push_back(plan); });
        std::sort(plans.begin(), plans.end(), [&](const Plan& a, const Plan& b) {
            guard.Check();
            const auto left = std::tie(a.kind, a.inode, a.stream), right = std::tie(b.kind, b.inode, b.stream);
            if (left != right) return left < right;
            if ((a.name != nullptr) != (b.name != nullptr)) return a.name == nullptr;
            return a.name && ByteLess(*a.name, *b.name);
        });
        for (const auto& plan : plans) {
            guard.Check();
            Entry e;
            e.kind = plan.kind; e.inodeOid = plan.inode; e.streamOid = plan.stream; e.logicalSizeBytes = plan.size;
            if (plan.name) e.nameUtf8 = *plan.name;
            result.entries.push_back(std::move(e));
        }
        result.enumerationComplete = true;
        if (!plans.empty()) {
            guard.Materialize(0, ChunkBytes);
            std::vector<std::byte> scratch;
            scratch.reserve(ChunkBytes);
            Sha256 sha(guard);
            catalog::BudgetedRandomAccessSource source(request.source, request.budget);
            for (std::size_t index = 0; index < plans.size(); ++index) {
                active = index;
                auto& e = result.entries[index];
                const auto& plan = plans[index];
                guard.Check();
                if (plan.unsupported) throw Stop{Reason::UnsupportedRepresentation};
                sha.Begin();
                const auto feed = [&](const std::byte* data, std::size_t bytes) {
                    guard.Check();
                    sha.Feed(data, bytes);
                    e.logicalBytesRead += bytes;
                    result.logicalBytesRead += bytes;
                };
                if (plan.embedded) {
                    for (std::size_t at = 0; at < plan.embedded->size();) {
                        guard.Check();
                        const auto n = (std::min)(ChunkBytes, plan.embedded->size() - at);
                        feed(plan.embedded->data() + at, n);
                        at += n;
                    }
                } else {
                    for (std::size_t extent_index = 0; extent_index < plan.extents.size();) {
                        guard.Check();
                        const auto& extent = plan.extents[extent_index++];
                        if (extent.logical_offset >= plan.size) break;
                        auto length = (std::min)(extent.bytes, plan.size - extent.logical_offset);
                        // The admitted descriptors prove both logical coverage and
                        // source bounds. Join only adjacent bytes of this stream;
                        // the existing chunk cap, scratch allowance and EOF remain.
                        while (extent_index < plan.extents.size() && length < plan.size - extent.logical_offset) {
                            guard.Check();
                            const auto& next = plan.extents[extent_index];
                            if (next.logical_offset != extent.logical_offset + length ||
                                (extent.physical_address == 0 ? next.physical_address != 0 :
                                    next.physical_address == 0 || next.physical_address != extent.physical_address + length)) break;
                            length += (std::min)(next.bytes, plan.size - next.logical_offset);
                            ++extent_index;
                        }
                        for (std::uint64_t at = 0; at < length;) {
                            guard.Check();
                            const auto n = static_cast<std::size_t>((std::min)(std::uint64_t{ChunkBytes}, length - at));
                            if (extent.physical_address == 0) {
                                scratch.assign(n, std::byte{0});
                            } else {
                                const auto offset = extent.physical_address + at;
                                bool read = false;
                                try { read = source.Read(offset, n, scratch); }
                                catch (...) {
                                    result.failedSourceOffset = offset;
                                    throw Stop{Reason::SourceReadFailure};
                                }
                                if (!read || scratch.size() != n) {
                                    result.failedSourceOffset = offset;
                                    throw Stop{request.budget->Failed() ? Reason::SharedBudget : Reason::SourceReadFailure};
                                }
                            }
                            feed(scratch.data(), n);
                            at += n;
                        }
                    }
                }
                guard.Check();
                if (e.logicalBytesRead != e.logicalSizeBytes) throw Stop{Reason::InvalidProjection};
                auto hash = sha.Finish();
                guard.Check();
                e.observedSha256 = std::move(hash);
                e.readOutcome = ReadOutcome::Complete;
                active.reset();
            }
        }
        guard.Check();
        result.outcome = Outcome::ExactComplete; result.reason = Reason::None;
        result.readComplete = true; result.hashesObserved = true;
        return result;
    } catch (const Stop& stop) {
        result.reason = stop.reason;
    } catch (const std::bad_alloc&) {
        if (request.budget) request.budget->Refuse("CurrentPayloadAllocationFailed");
        result.reason = Reason::AllocationFailure;
    } catch (...) {
        result.reason = Reason::CallbackFailure;
    }
    result.outcome = OutcomeFor(result.reason);
    if (!result.enumerationComplete) { result.entries.clear(); result.logicalBytesRead = 0; }
    else if (active) {
        auto& e = result.entries[*active];
        e.readOutcome = RowOutcomeFor(result.reason);
        e.observedSha256.reset();
        result.failedInodeOid = e.inodeOid;
        result.failedStreamOid = e.streamOid;
    }
    else if (std::all_of(result.entries.begin(), result.entries.end(),
        [](const Entry& e) { return e.readOutcome == ReadOutcome::Complete; })) {
        // Expiry after the last row must not publish a complete census.
        if (result.entries.empty()) result.enumerationComplete = false;
        else {
            auto& e = result.entries.back();
            e.readOutcome = RowOutcomeFor(result.reason);
            e.observedSha256.reset();
            result.failedInodeOid = e.inodeOid;
            result.failedStreamOid = e.streamOid;
        }
    }
    return result;
}

bool SerializeInventory(const Result& result, const std::shared_ptr<catalog::ApfsReadBudget>& budget,
    const std::function<bool()>& withinDeadline, std::size_t maxOutputBytes, std::string& output, Reason& failure) {
    output.clear(); failure = Reason::None;
    const Guard guard{budget, withinDeadline};
    try {
        if (budget != result.sharedBudget) throw Stop{Reason::InvalidBinding};
        guard.Check();
        ValidateResult(result, guard);
        Sink count{nullptr, maxOutputBytes};
        EmitInventory(result, guard, count);
        if (count.size > UINT64_MAX - 64) throw Stop{Reason::OutputLimit};
        guard.Materialize(1, count.size + 64);
        output.reserve(count.size);
        Sink sink{&output, maxOutputBytes};
        EmitInventory(result, guard, sink);
        return true;
    } catch (const Stop& stop) { failure = stop.reason; }
    catch (const std::bad_alloc&) { failure = Reason::AllocationFailure; }
    catch (...) { failure = Reason::CallbackFailure; }
    output.clear();
    return false;
}

std::string_view Name(Kind value) noexcept {
    switch (value) { case Kind::FileData: return "file-data"; case Kind::Xattr: return "xattr"; }
    return {};
}
std::string_view Name(ReadOutcome value) noexcept {
    switch (value) {
    case ReadOutcome::Complete: return "Complete"; case ReadOutcome::NotRead: return "NotRead";
    case ReadOutcome::ReadFailure: return "ReadFailure"; case ReadOutcome::BudgetExceeded: return "BudgetExceeded";
    case ReadOutcome::Unsupported: return "Unsupported";
    }
    return {};
}
std::string_view Name(Outcome value) noexcept {
    switch (value) {
    case Outcome::ExactComplete: return "ExactComplete"; case Outcome::Incomplete: return "Incomplete";
    case Outcome::Unsupported: return "Unsupported"; case Outcome::Error: return "Error";
    }
    return {};
}
std::string_view Name(Reason value) noexcept {
    switch (value) {
    case Reason::None: return "None"; case Reason::InvalidProjection: return "InvalidProjection";
    case Reason::InvalidBinding: return "InvalidBinding"; case Reason::LogicalLimit: return "LogicalLimit";
    case Reason::EntryLimit: return "EntryLimit"; case Reason::SharedBudget: return "SharedBudget";
    case Reason::Deadline: return "Deadline"; case Reason::UnsupportedRepresentation: return "UnsupportedRepresentation";
    case Reason::SourceReadFailure: return "SourceReadFailure"; case Reason::HashProviderFailure: return "HashProviderFailure";
    case Reason::OutputLimit: return "OutputLimit"; case Reason::AllocationFailure: return "AllocationFailure";
    case Reason::CallbackFailure: return "CallbackFailure";
    case Reason::HashProviderUnavailable: return "HashProviderUnavailable";
    case Reason::AdmissionNotComplete: return "AdmissionNotComplete";
    }
    return {};
}
}
