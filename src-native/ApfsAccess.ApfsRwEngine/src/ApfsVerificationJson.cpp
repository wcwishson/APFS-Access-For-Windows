#include "ApfsVerificationJson.h"
#include "ApfsFusionStore.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <stdexcept>
#include <unordered_set>

namespace apfsaccess::catalog
{
namespace
{
struct Stop { payload::Reason reason; };

struct Writer
{
    const VerificationReport& report;
    const std::function<bool()>& deadline;
    std::size_t cap, size = 0;
    std::string* output = nullptr;
    void Check() const
    {
        if (!report.read_budget || !deadline) throw Stop{payload::Reason::InvalidBinding};
        if (report.read_budget->Failed()) throw Stop{payload::Reason::SharedBudget};
        bool alive = false;
        try { alive = deadline(); } catch (...) { throw Stop{payload::Reason::CallbackFailure}; }
        if (!alive)
        {
            report.read_budget->Refuse("VerificationResponseDeadline");
            throw Stop{payload::Reason::Deadline};
        }
    }
    void Text(std::string_view value)
    {
        Check();
        if (value.size() > cap - size) throw Stop{payload::Reason::OutputLimit};
        size += value.size();
        if (output) output->append(value);
    }
    void String(std::string_view value)
    {
        Text("\"");
        constexpr char hex[] = "0123456789abcdef";
        // Copy plain UTF-8 spans; escaping does not reinterpret payload names.
        std::size_t begin = 0;
        for (std::size_t at = 0; at < value.size(); ++at)
        {
            if (at % payload::ChunkBytes == 0) Check();
            const auto c = static_cast<unsigned char>(value[at]);
            if (c >= 0x20 && c != '"' && c != '\\') continue;
            Text(value.substr(begin, at - begin));
            if (c == '"') Text("\\\"");
            else if (c == '\\') Text("\\\\");
            else
            {
                const char escaped[] = {'\\', 'u', '0', '0', hex[c >> 4], hex[c & 15]};
                Text({escaped, sizeof(escaped)});
            }
            begin = at + 1;
        }
        Text(value.substr(begin)); Text("\"");
    }
    void Number(std::uint64_t value, bool quoted = true)
    {
        char buffer[32];
        const auto result = std::to_chars(buffer, buffer + sizeof(buffer), value);
        if (quoted) Text("\"");
        Text({buffer, static_cast<std::size_t>(result.ptr - buffer)});
        if (quoted) Text("\"");
    }
    void Bool(bool value) { Text(value ? "true" : "false"); }
    void Optional(const std::optional<std::uint64_t>& value)
    { if (value) Number(*value); else Text("null"); }
    void Identity(const ApfsSnapshotScope& scope)
    {
        Text("\"containerUuid\":"); String(scope.container_uuid_hex);
        Text(",\"volumeUuid\":"); String(scope.volume_uuid_hex);
        Text(",\"volumeOid\":"); Number(scope.volume_oid);
        Text(",\"checkpointXid\":"); Number(scope.checkpoint_xid);
        Text(",\"storeOffsetBytes\":"); Number(scope.store_offset_bytes);
        Text(",\"storeSizeBytes\":"); Number(scope.store_size_bytes);
    }
    void Ranges(const std::vector<VerificationBlockRange>& ranges)
    {
        Text("["); bool first = true;
        for (const auto& range : ranges)
        {
            if (!first) Text(","); first = false;
            Text("{\"physicalBlock\":"); Number(range.physical_block);
            Text(",\"blockCount\":"); Number(range.block_count); Text("}");
        }
        Text("]");
    }
    void Selected(const VerifiedCheckpointIdentity& selected)
    {
        Text("{"); Identity(selected.exact);
        Text(",\"checkpointPhysicalBlock\":"); Number(selected.checkpoint_physical_block);
        Text(",\"volumeSuperblockPhysicalBlock\":"); Number(selected.volume_superblock_physical_block);
        Text(",\"volumeSuperblockXid\":"); Number(selected.volume_superblock_xid);
        Text(",\"rootOid\":"); Number(selected.root_oid);
        Text(",\"rootPhysicalBlock\":"); Number(selected.root_physical_block); Text("}");
    }
    void Emit(std::string_view path, std::string_view inventory, bool protected_history = false)
    {
        const auto& scope = report.requested_scope;
        const bool accounting = scope.account_retained_ownership && !protected_history;
        const bool history = protected_history || (accounting && scope.retained_from_xid.has_value());
        Text("{\"format\":"); String(protected_history ? "apfs-access-protected-history-verification" : "apfs-access-verification");
        Text(",\"version\":"); Number(protected_history ? 1 : accounting ? RetainedAccountingImageVerificationVersion : scope.observe_payload_content ? 3 : 2, false);
        Text(",\"readOnly\":true,\"source\":{\"kind\":\"image\",\"path\":"); String(path);
        Text(",\"identity\":"); String(scope.source_identity);
        Text(",\"lease\":\"windows-read-deny-write-delete\"},\"requestedScope\":{"); Identity(scope.exact);
        Text(",\"maxReads\":"); Number(scope.max_reads);
        Text(",\"maxReadBytes\":"); Number(scope.max_read_bytes);
        Text(",\"maxRecords\":"); Number(scope.max_records);
        Text(",\"maxRecordBytes\":"); Number(scope.max_record_bytes);
        Text(",\"requireWholeVolume\":"); Bool(scope.require_whole_volume);
        Text(",\"requirePayloadContentHashes\":"); Bool(scope.require_payload_content_hashes);
        if (accounting) Text(",\"accountRetainedOwnership\":true");
        if (history) { Text(",\"retainedFromXid\":"); Number(*scope.retained_from_xid); }
        if (scope.observe_payload_content)
        {
            Text(",\"maxPayloadLogicalBytes\":"); Number(scope.max_payload_logical_bytes);
            Text(",\"maxPayloadEntries\":"); Number(scope.max_payload_entries);
        }
        Text("},\"selected\":");
        if (report.selected)
        {
            Selected(*report.selected);
        }
        else Text("null");
        if (accounting)
        {
            Text(",\"retainedOwnership\":");
            if (!report.retained_ownership) Text("null");
            else
            {
                const auto& a = *report.retained_ownership;
                Text("{\"checkpointXids\":["); bool first = true;
                for (const auto xid : a.checkpoint_xids)
                { if (!first) Text(","); first = false; Number(xid); }
                Text("],\"metadataRanges\":"); Ranges(a.metadata_ranges);
                Text(",\"payloadRanges\":"); Ranges(a.payload_ranges);
                Text(",\"allocatedMainBlocks\":"); Number(a.allocated_main_blocks);
                Text(",\"allocatedInternalBlocks\":"); Number(a.allocated_internal_blocks);
                Text(",\"ownedMainBlocks\":"); Number(a.owned_main_blocks);
                Text(",\"ownedInternalBlocks\":"); Number(a.owned_internal_blocks);
                Text(",\"reservedMainBlocks\":"); Number(a.reserved_main_blocks);
                Text(",\"deferredMainBlocks\":"); Number(a.deferred_main_blocks);
                Text(",\"deferredInternalBlocks\":"); Number(a.deferred_internal_blocks);
                Text(",\"snapshotPayloadUsage\":["); first = true;
                for (const auto& usage : a.snapshot_payload_usage)
                {
                    if (!first) Text(","); first = false;
                    Text("{\"volumeOid\":"); Number(usage.volume_oid);
                    Text(",\"referencedBlocks\":"); Number(usage.referenced_blocks);
                    Text(",\"exclusiveBlocks\":"); Number(usage.exclusive_blocks);
                    Text(",\"referencedBytes\":"); Number(usage.referenced_bytes);
                    Text(",\"exclusiveBytes\":"); Number(usage.exclusive_bytes); Text("}");
                }
                Text("],\"snapshotTotalBytes\":null,\"purgeableBytes\":null}");
            }
        }
        Text(",\"outcome\":"); Number(static_cast<unsigned>(report.outcome), false);
        Text(",\"outcomeName\":"); String(report.outcome == VerificationOutcome::Complete ? "Complete" :
            report.outcome == VerificationOutcome::Refused ? "Refused" : "Incomplete");
        Text(",\"wholeVolumeVerified\":false,\"payloadContentHashesVerified\":false");
        Text(",\"sourceReads\":"); Number(report.source_reads);
        Text(",\"sourceReadBytes\":"); Number(report.source_read_bytes);
        Text(",\"coveredFilesystemRecords\":"); Number(report.covered_filesystem_records);
        Text(",\"coveredPhysicalExtents\":"); Number(report.covered_physical_extents);
        Text(",\"allocationCensus\":");
        if (report.allocation_census)
        {
            const auto& c = *report.allocation_census;
            Text("{\"blockSizeBytes\":"); Number(c.block_size_bytes);
            Text(",\"containerBlockCount\":"); Number(c.container_block_count);
            Text(",\"currentMetadataBlocks\":"); Number(c.current_metadata_blocks);
            Text(",\"currentPayloadBlocks\":"); Number(c.current_payload_blocks);
            Text(",\"unattributedMainBlocks\":"); Number(c.unattributed_main_blocks);
            Text(",\"unattributedInternalBlocks\":"); Number(c.unattributed_internal_blocks);
            const auto ranges = [&](const auto& values) {
                Text("["); bool first = true;
                for (const auto& range : values)
                {
                    if (!first) Text(","); first = false;
                    Text("{\"physicalBlock\":"); Number(range.physical_block);
                    Text(",\"blockCount\":"); Number(range.block_count); Text("}");
                }
                Text("]");
            };
            Text(",\"unattributedMainRanges\":"); ranges(c.unattributed_main_ranges);
            Text(",\"unattributedInternalRanges\":"); ranges(c.unattributed_internal_ranges); Text("}");
        }
        else Text("null");
        Text(",\"findings\":["); bool first = true;
        for (const auto& f : report.findings)
        {
            if (!first) Text(","); first = false;
            Text("{\"code\":"); Number(static_cast<unsigned>(f.code), false);
            Text(",\"severity\":"); Number(static_cast<unsigned>(f.severity), false);
            Text(",\"check\":"); Number(static_cast<unsigned>(f.check), false);
            Text(",\"volumeOid\":"); Optional(f.volume_oid);
            Text(",\"objectId\":"); Optional(f.object_id);
            Text(",\"physicalBlock\":"); Optional(f.physical_block);
            Text(",\"checkpointXid\":"); Optional(f.checkpoint_xid);
            Text(",\"failedSourceOffsetBytes\":"); Optional(f.failed_source_offset_bytes);
            Text(",\"detail\":"); String(f.detail); Text("}");
        }
        Text("],\"coverage\":["); first = true;
        for (const auto& c : report.coverage)
        {
            if (!first) Text(","); first = false;
            Text("{\"check\":"); Number(static_cast<unsigned>(c.check), false);
            Text(",\"implemented\":"); Bool(c.implemented);
            Text(",\"required\":"); Bool(c.required);
            Text(",\"state\":"); Number(static_cast<unsigned>(c.state), false);
            Text(",\"scopeDetail\":"); String(c.scope_detail); Text("}");
        }
        Text("]");
        if (history)
        {
            Text(",\"requestedHistory\":");
            if (!report.requested_history) Text("null");
            else
            {
                const auto& requested_history = *report.requested_history;
                Text("{\"fromXid\":"); Number(requested_history.from_xid);
                Text(",\"endpoint\":"); Selected(requested_history.endpoint);
                Text(",\"chainXids\":["); first = true;
                for (const auto xid : requested_history.chain_xids)
                { if (!first) Text(","); first = false; Number(xid); }
                Text("],\"checkpoints\":["); first = true;
                for (const auto& checkpoint : requested_history.checkpoints)
                {
                    if (!first) Text(","); first = false;
                    Text("{\"checkpointXid\":"); Number(checkpoint.checkpoint_xid);
                    Text(",\"metadataRanges\":"); Ranges(checkpoint.metadata_ranges);
                    Text(",\"payloadRanges\":"); Ranges(checkpoint.payload_ranges); Text("}");
                }
                Text("]}");
            }
        }
        if (!protected_history)
        {
            Text(",\"repair\":{\"planId\":"); String(report.repair.plan_id);
            Text(",\"refusal\":"); Number(static_cast<unsigned>(report.repair.refusal), false);
            Text(",\"nextActionableCandidate\":null}");
        }
        if (scope.observe_payload_content) { Text(",\"observePayloadContent\":true,\"payloadInventory\":"); Text(inventory); }
        Text("}");
    }
};

void ValidateReport(const VerificationReport& report)
{
    if (report.whole_volume_verified || report.payload_content_hashes_verified ||
        report.requested_scope.retained_from_xid || report.requested_history ||
        report.requested_scope.account_retained_ownership || report.retained_ownership)
        throw Stop{payload::Reason::InvalidProjection};
    if (!report.requested_scope.observe_payload_content)
    {
        if (report.payload_inventory || report.coverage.size() != 20)
            throw Stop{payload::Reason::InvalidProjection};
        return;
    }
    if (!report.payload_inventory || report.coverage.size() != 21 ||
        report.requested_scope.max_payload_logical_bytes != payload::MaxLogicalBytes ||
        report.requested_scope.max_payload_entries != payload::MaxEntries)
        throw Stop{payload::Reason::InvalidProjection};
    const auto c = std::find_if(report.coverage.begin(), report.coverage.end(), [](const auto& entry) {
        return entry.check == VerificationCheck::CurrentPayloadObservation;
    });
    const bool complete = report.payload_inventory->exactComplete();
    if (c == report.coverage.end() || !c->implemented || !c->required ||
        (c->state == VerificationCheckState::Verified) != complete ||
        (report.outcome == VerificationOutcome::Complete && !complete) ||
        (complete && (!report.selected || report.outcome == VerificationOutcome::Refused ||
            std::any_of(report.findings.begin(), report.findings.end(), [](const auto& f) {
                return f.code != VerificationCode::CoverageMissing;
            }))))
        throw Stop{payload::Reason::InvalidProjection};
}

void ValidateProtectedHistoryReport(const VerificationReport& report)
{
    const auto invalid = [] { throw Stop{payload::Reason::InvalidProjection}; };
    const auto& scope = report.requested_scope;
    if (!scope.retained_from_xid || !*scope.retained_from_xid ||
        *scope.retained_from_xid >= scope.exact.checkpoint_xid ||
        scope.observe_payload_content || scope.require_whole_volume || scope.require_payload_content_hashes ||
        report.payload_inventory || report.whole_volume_verified || report.payload_content_hashes_verified ||
        scope.account_retained_ownership || report.retained_ownership ||
        report.coverage.size() != 21 || report.source_reads > scope.max_reads ||
        report.source_read_bytes > scope.max_read_bytes) invalid();
    const auto outcome = static_cast<unsigned>(report.outcome);
    if (outcome < 1 || outcome > 3) invalid();
    const bool complete = report.outcome == VerificationOutcome::Complete;
    if (complete != report.requested_history.has_value() ||
        complete != report.findings.empty() ||
        (!complete && (report.allocation_census || report.covered_filesystem_records || report.covered_physical_extents))) invalid();
    std::array<bool, 23> checks{};
    for (const auto& coverage : report.coverage)
    {
        const auto id = static_cast<unsigned>(coverage.check);
        const auto state = static_cast<unsigned>(coverage.state);
        if (!id || id > 22 || id == 21 || checks[id] || !state || state > 5) invalid();
        checks[id] = true;
        const bool implemented = id <= 11 || id >= 17;
        if (coverage.implemented != implemented || coverage.required != implemented ||
            (coverage.required && coverage.state == VerificationCheckState::NotRequested) ||
            (complete && implemented && coverage.state != VerificationCheckState::Verified)) invalid();
        if (id == 22 && (coverage.state == VerificationCheckState::Verified) != complete) invalid();
        if ((id == 12 || id == 14) && coverage.state != VerificationCheckState::Unproven) invalid();
        if (id == 13 && coverage.state != VerificationCheckState::Unproven &&
            !(report.outcome == VerificationOutcome::Refused && coverage.state == VerificationCheckState::Unsupported)) invalid();
        if ((id == 15 || id == 16) && coverage.state != VerificationCheckState::Unsupported) invalid();
    }
    if (!checks[22]) invalid();
    if (!complete) return;
    if (!report.selected || !report.allocation_census || report.selected->exact != scope.exact) invalid();
    const auto& history = *report.requested_history;
    const auto& census = *report.allocation_census;
    if (history.from_xid != *scope.retained_from_xid || history.endpoint != *report.selected ||
        history.chain_xids.size() < 2 || history.chain_xids.front() != history.from_xid ||
        history.chain_xids.back() != scope.exact.checkpoint_xid ||
        history.checkpoints.size() != history.chain_xids.size() - 1 ||
        census.block_size_bytes < 4096 || census.block_size_bytes > 65536 ||
        (census.block_size_bytes & (census.block_size_bytes - 1)) || !census.container_block_count ||
        census.container_block_count > scope.exact.store_size_bytes / census.block_size_bytes) invalid();
    for (std::size_t index = 1; index < history.chain_xids.size(); ++index)
        if (history.chain_xids[index] <= history.chain_xids[index - 1]) invalid();
    const auto ranges_valid = [&](const auto& ranges) {
        std::uint64_t previous_end = 0;
        bool first = true;
        for (const auto& range : ranges)
        {
            if (!range.block_count || range.physical_block >= census.container_block_count ||
                range.block_count > census.container_block_count - range.physical_block ||
                (!first && range.physical_block <= previous_end)) return false;
            first = false;
            previous_end = range.physical_block + range.block_count;
        }
        return true;
    };
    for (std::size_t index = 0; index < history.checkpoints.size(); ++index)
    {
        const auto& checkpoint = history.checkpoints[index];
        if (checkpoint.checkpoint_xid != history.chain_xids[index] || checkpoint.metadata_ranges.empty() ||
            !ranges_valid(checkpoint.metadata_ranges) || !ranges_valid(checkpoint.payload_ranges)) invalid();
        std::size_t metadata = 0, payload = 0;
        while (metadata < checkpoint.metadata_ranges.size() && payload < checkpoint.payload_ranges.size())
        {
            const auto& m = checkpoint.metadata_ranges[metadata];
            const auto& p = checkpoint.payload_ranges[payload];
            if (m.physical_block + m.block_count <= p.physical_block) ++metadata;
            else if (p.physical_block + p.block_count <= m.physical_block) ++payload;
            else invalid();
        }
    }
}

void RequireAccounting(bool valid)
{
    if (!valid) throw Stop{payload::Reason::InvalidProjection};
}

std::uint64_t AccountingRanges(const std::vector<VerificationBlockRange>& ranges,
    std::uint64_t capacity, const Writer& guard)
{
    RequireAccounting(ranges.size() <= guard.report.requested_scope.max_records);
    std::uint64_t previous_end = 0, total = 0;
    bool first = true;
    for (const auto& range : ranges)
    {
        guard.Check();
        RequireAccounting(range.block_count && range.physical_block < capacity &&
            range.block_count <= capacity - range.physical_block &&
            (first || range.physical_block > previous_end));
        first = false;
        previous_end = range.physical_block + range.block_count;
        RequireAccounting(range.block_count <= capacity - total);
        total += range.block_count;
    }
    return total;
}

void AccountingDisjoint(const std::vector<VerificationBlockRange>& metadata,
    const std::vector<VerificationBlockRange>& payload, const Writer& guard)
{
    std::size_t m = 0, p = 0;
    while (m < metadata.size() && p < payload.size())
    {
        guard.Check();
        const auto& a = metadata[m]; const auto& b = payload[p];
        if (a.physical_block + a.block_count <= b.physical_block) ++m;
        else if (b.physical_block + b.block_count <= a.physical_block) ++p;
        else RequireAccounting(false);
    }
}

void AccountingContains(const std::vector<VerificationBlockRange>& all,
    const std::vector<VerificationBlockRange>& subset, const Writer& guard)
{
    std::size_t index = 0;
    for (const auto& range : subset)
    {
        guard.Check();
        while (index < all.size() && all[index].physical_block + all[index].block_count <= range.physical_block) ++index;
        RequireAccounting(index < all.size() && all[index].physical_block <= range.physical_block &&
            range.physical_block + range.block_count <= all[index].physical_block + all[index].block_count);
    }
}

void ValidateAccountingReport(const VerificationReport& report, const Writer& guard)
{
    const auto& scope = report.requested_scope;
    const bool pin = scope.retained_from_xid.has_value();
    const bool complete = report.outcome == VerificationOutcome::Complete;
    const auto outcome = static_cast<unsigned>(report.outcome);
    RequireAccounting(scope.account_retained_ownership && outcome >= 1 && outcome <= 3 &&
        !report.whole_volume_verified && !report.payload_content_hashes_verified &&
        report.coverage.size() == 20u + scope.observe_payload_content + pin &&
        report.source_reads <= scope.max_reads && report.source_read_bytes <= scope.max_read_bytes &&
        report.covered_filesystem_records <= scope.max_records && report.covered_physical_extents <= scope.max_records &&
        report.findings.size() <= scope.max_records && complete == report.findings.empty() &&
        complete == report.retained_ownership.has_value() && complete == report.allocation_census.has_value() &&
        report.requested_history.has_value() == (complete && pin) &&
        (complete || (!report.covered_filesystem_records && !report.covered_physical_extents)) &&
        (!pin || (*scope.retained_from_xid && *scope.retained_from_xid < scope.exact.checkpoint_xid)) &&
        (!report.selected || report.selected->exact == scope.exact));
    std::array<VerificationCheckState, 23> states{};
    for (const auto& coverage : report.coverage)
    {
        guard.Check();
        const auto id = static_cast<unsigned>(coverage.check);
        const auto state = static_cast<unsigned>(coverage.state);
        RequireAccounting(id && id <= 22 && (id != 21 || scope.observe_payload_content) &&
            (id != 22 || pin) && static_cast<unsigned>(states[id]) == 0 && state >= 1 && state <= 5);
        states[id] = coverage.state;
        const bool implemented = id <= 13 || id >= 17;
        const bool required = implemented || (id == 14 && (scope.require_whole_volume || scope.require_payload_content_hashes));
        RequireAccounting(coverage.implemented == implemented && coverage.required == required &&
            (!required || coverage.state != VerificationCheckState::NotRequested) &&
            (!complete || !required || coverage.state == VerificationCheckState::Verified));
        if (id == 14) RequireAccounting(coverage.state == VerificationCheckState::Unproven);
        if (id == 15 || id == 16) RequireAccounting(coverage.state == VerificationCheckState::Unsupported);
        if (id == 22) RequireAccounting((coverage.state == VerificationCheckState::Verified) == complete);
    }
    std::array<bool, 23> findings{};
    for (const auto& finding : report.findings)
    {
        guard.Check();
        const auto code = static_cast<unsigned>(finding.code);
        const auto check = static_cast<unsigned>(finding.check);
        RequireAccounting(code >= 1 && code <= 27 && check && check <= 22 && static_cast<unsigned>(states[check]) != 0);
        findings[check] = true;
        const bool refused = report.outcome == VerificationOutcome::Refused;
        const auto state = refused ? VerificationCheckState::Unsupported :
            (code == 3 || code == 4 || code == 5 || code == 18 ? VerificationCheckState::Unproven : VerificationCheckState::Inconsistent);
        RequireAccounting(finding.severity == (refused ? VerificationSeverity::Warning : VerificationSeverity::Error) && states[check] == state);
        if (code == 26) RequireAccounting(!refused && check == 12);
        if (code == 27) RequireAccounting(!refused && check == 13);
    }
    for (unsigned id = 1; id < states.size(); ++id)
        if (states[id] == VerificationCheckState::Inconsistent ||
            (states[id] == VerificationCheckState::Unsupported && id != 15 && id != 16)) RequireAccounting(findings[id]);
    RequireAccounting(scope.observe_payload_content == report.payload_inventory.has_value());
    if (scope.observe_payload_content)
    {
        RequireAccounting(scope.max_payload_logical_bytes == payload::MaxLogicalBytes &&
            scope.max_payload_entries == payload::MaxEntries);
        const bool observed = report.payload_inventory->exactComplete();
        RequireAccounting((states[21] == VerificationCheckState::Verified) == observed && (!complete || observed) &&
            (!observed || report.selected.has_value()));
    }
    RequireAccounting(report.repair.source_identity == scope.source_identity && report.repair.requested_identity == scope.exact &&
        report.repair.observed_identity == report.selected && report.repair.findings == report.findings &&
        report.repair.refusal == (complete ? ApfsRepairRefusal::NoIndependentReconstructionEvidence : ApfsRepairRefusal::VerificationNotComplete) &&
        report.repair.plan_id.starts_with("apfs-verifier-refusal-ownership-v1|"));
    if (!complete) return;
    RequireAccounting(report.selected.has_value());
    const auto& census = *report.allocation_census;
    const auto bs = census.block_size_bytes, capacity = census.container_block_count;
    RequireAccounting(bs >= 4096 && bs <= 65536 && !(bs & (bs - 1)) && capacity &&
        capacity <= UINT64_MAX / bs && capacity * bs == scope.exact.store_size_bytes &&
        !census.unattributed_main_blocks && !census.unattributed_internal_blocks &&
        census.unattributed_main_ranges.empty() && census.unattributed_internal_ranges.empty());
    RequireAccounting(report.selected->checkpoint_physical_block && report.selected->volume_superblock_physical_block &&
        report.selected->volume_superblock_xid && report.selected->volume_superblock_xid <= scope.exact.checkpoint_xid &&
        report.selected->root_oid && report.selected->root_physical_block);
    const auto& a = *report.retained_ownership;
    const auto metadata = AccountingRanges(a.metadata_ranges, capacity, guard);
    const auto payload = AccountingRanges(a.payload_ranges, capacity, guard);
    AccountingDisjoint(a.metadata_ranges, a.payload_ranges, guard);
    RequireAccounting(metadata && payload <= capacity - metadata &&
        a.owned_main_blocks == metadata + payload &&
        a.allocated_main_blocks <= capacity && a.owned_main_blocks <= a.allocated_main_blocks &&
        a.reserved_main_blocks <= a.allocated_main_blocks - a.owned_main_blocks &&
        a.deferred_main_blocks == a.allocated_main_blocks - a.owned_main_blocks - a.reserved_main_blocks &&
        a.allocated_internal_blocks <= a.allocated_main_blocks && a.owned_internal_blocks <= a.allocated_internal_blocks &&
        a.deferred_internal_blocks == a.allocated_internal_blocks - a.owned_internal_blocks &&
        a.owned_internal_blocks <= metadata && census.current_metadata_blocks <= metadata &&
        census.current_payload_blocks <= payload && !a.snapshot_total_bytes && !a.purgeable_bytes);
    const auto contains = [&](std::uint64_t block) {
        return std::any_of(a.metadata_ranges.begin(), a.metadata_ranges.end(), [&](const auto& range) {
            guard.Check(); return block >= range.physical_block && block - range.physical_block < range.block_count;
        });
    };
    RequireAccounting(contains(0) && contains(report.selected->checkpoint_physical_block) &&
        contains(report.selected->volume_superblock_physical_block) && contains(report.selected->root_physical_block));
    RequireAccounting(!a.checkpoint_xids.empty() && a.checkpoint_xids.size() <= scope.max_records &&
        a.checkpoint_xids.front() && a.checkpoint_xids.back() == scope.exact.checkpoint_xid);
    for (std::size_t i = 1; i < a.checkpoint_xids.size(); ++i)
    { guard.Check(); RequireAccounting(a.checkpoint_xids[i] > a.checkpoint_xids[i - 1]); }
    RequireAccounting(!a.snapshot_payload_usage.empty() && a.snapshot_payload_usage.size() <= scope.max_records);
    std::uint64_t previous_oid = 0, referenced = 0;
    bool selected_usage = false;
    for (const auto& usage : a.snapshot_payload_usage)
    {
        guard.Check();
        RequireAccounting(usage.volume_oid > previous_oid && usage.referenced_blocks <= payload - referenced &&
            usage.exclusive_blocks <= usage.referenced_blocks && usage.referenced_bytes == usage.referenced_blocks * bs &&
            usage.exclusive_bytes == usage.exclusive_blocks * bs);
        previous_oid = usage.volume_oid; referenced += usage.referenced_blocks;
        selected_usage |= usage.volume_oid == scope.exact.volume_oid;
    }
    RequireAccounting(selected_usage);
    if (pin)
    {
        const auto& h = *report.requested_history;
        const auto from = std::find(a.checkpoint_xids.begin(), a.checkpoint_xids.end(), *scope.retained_from_xid);
        RequireAccounting(from != a.checkpoint_xids.end() && h.from_xid == *scope.retained_from_xid &&
            h.endpoint == *report.selected && h.chain_xids.size() >= 2 &&
            h.chain_xids.size() == static_cast<std::size_t>(a.checkpoint_xids.end() - from) &&
            std::equal(from, a.checkpoint_xids.end(), h.chain_xids.begin()) && h.checkpoints.size() == h.chain_xids.size() - 1);
        for (std::size_t i = 0; i < h.checkpoints.size(); ++i)
        {
            guard.Check();
            const auto& c = h.checkpoints[i];
            RequireAccounting(c.checkpoint_xid == h.chain_xids[i] && !c.metadata_ranges.empty());
            (void)AccountingRanges(c.metadata_ranges, capacity, guard);
            (void)AccountingRanges(c.payload_ranges, capacity, guard);
            AccountingDisjoint(c.metadata_ranges, c.payload_ranges, guard);
            AccountingContains(a.metadata_ranges, c.metadata_ranges, guard);
            AccountingContains(a.payload_ranges, c.payload_ranges, guard);
        }
    }
}

bool AttributionTextValid(std::string_view value, bool empty = false)
{
    return (empty || !value.empty()) && value.size() <= 65535 &&
        value.find('\0') == std::string_view::npos &&
        IsValidUtf8(reinterpret_cast<const std::byte*>(value.data()), value.size());
}

void AttributionAmount(Writer& writer, const ApfsSpaceAmount& amount)
{
    writer.Text("{\"blocks\":"); writer.Number(amount.blocks);
    writer.Text(",\"bytes\":"); writer.Number(amount.bytes); writer.Text("}");
}

void AttributionMeasures(Writer& writer, const ApfsSnapshotAttributionAmounts& amount)
{
    writer.Text("{\"referenced\":"); AttributionAmount(writer, amount.referenced);
    writer.Text(",\"sharedWithLive\":"); AttributionAmount(writer, amount.shared_with_live);
    writer.Text(",\"absentFromLive\":"); AttributionAmount(writer, amount.absent_from_live);
    writer.Text(",\"sharedWithOtherSnapshots\":"); AttributionAmount(writer, amount.shared_with_other_snapshots);
    writer.Text(",\"uniqueInVisibleInventory\":"); AttributionAmount(writer, amount.unique_in_visible_inventory);
    writer.Text(",\"retainedOrPeerProtected\":"); AttributionAmount(writer, amount.retained_or_peer_protected);
    writer.Text(",\"potentialReclaimUpperBound\":"); AttributionAmount(writer, amount.potential_reclaim_upper_bound);
    writer.Text("}");
}

void EmitAttribution(Writer& writer, const ApfsSnapshotSpaceAttribution& result, std::string_view path)
{
    writer.Text("{\"format\":\"apfs-access-snapshot-space-attribution\",\"version\":");
    writer.Number(SnapshotSpaceAttributionVersion, false);
    writer.Text(",\"readOnly\":true,\"complete\":true,\"source\":{\"path\":"); writer.String(path);
    writer.Text(",\"identity\":"); writer.String(result.source_identity);
    writer.Text("},\"scope\":{"); writer.Identity(result.scope);
    writer.Text("},\"allocationUnitBytes\":"); writer.Number(result.allocation_unit_bytes, false);
    writer.Text(",\"retainedCheckpointXids\":["); bool first = true;
    for (const auto xid : result.retained_checkpoint_xids)
    { if (!first) writer.Text(","); first = false; writer.Number(xid); }
    writer.Text("],\"referencedMetadata\":"); AttributionAmount(writer, result.referenced_metadata);
    writer.Text(",\"referencedPayload\":"); AttributionAmount(writer, result.referenced_payload);
    writer.Text(",\"catalogMetadata\":"); AttributionAmount(writer, result.catalog_metadata);
    writer.Text(",\"snapshots\":["); first = true;
    for (const auto& row : result.snapshots)
    {
        if (!first) writer.Text(","); first = false;
        writer.Text("{\"snapshotXid\":"); writer.Number(row.snapshot_xid);
        writer.Text(",\"name\":"); writer.String(row.name_utf8);
        writer.Text(",\"metadata\":"); AttributionMeasures(writer, row.metadata);
        writer.Text(",\"payload\":"); AttributionMeasures(writer, row.payload);
        writer.Text(",\"purgeableMarkedPayload\":"); AttributionAmount(writer, row.purgeable_marked_payload);
        writer.Text(",\"applePurgeable\":null,\"reclaimable\":null}");
    }
    writer.Text("]}");
}

void ValidateAttribution(const ApfsSnapshotSpaceAttribution& result, const VerificationScope& expected,
    std::string_view path, const Writer& guard)
{
    if (result.source_identity != expected.source_identity || result.scope != expected.exact)
        throw Stop{payload::Reason::InvalidBinding};
    RequireAccounting(AttributionTextValid(path) && AttributionTextValid(result.source_identity) &&
        !expected.require_whole_volume && !expected.require_payload_content_hashes && !expected.observe_payload_content);
    const auto uuid = [](std::string_view value) {
        return value.size() == 32 && value.find_first_not_of("0123456789abcdef") == std::string_view::npos &&
            value.find_first_not_of('0') != std::string_view::npos;
    };
    const auto& scope = result.scope;
    const std::uint64_t bs = result.allocation_unit_bytes;
    RequireAccounting(uuid(scope.container_uuid_hex) && uuid(scope.volume_uuid_hex) && scope.volume_oid &&
        scope.checkpoint_xid && bs >= 4096 && bs <= 65536 && !(bs & (bs - 1)) &&
        scope.store_size_bytes && scope.store_size_bytes % bs == 0 && scope.store_offset_bytes % bs == 0 &&
        scope.store_offset_bytes <= UINT64_MAX - scope.store_size_bytes);
    const auto capacity = scope.store_size_bytes / bs;
    // The shared allowance can include earlier caller work. Its remaining
    // resources were restricted by the producer; encoding spends that allowance.
    RequireAccounting(result.read_budget->Consumed().reads &&
        result.snapshots.size() <= expected.max_records && !result.retained_checkpoint_xids.empty() &&
        result.retained_checkpoint_xids.size() <= expected.max_records &&
        result.retained_checkpoint_xids.front() && result.retained_checkpoint_xids.back() == scope.checkpoint_xid);
    for (std::size_t i = 1; i < result.retained_checkpoint_xids.size(); ++i)
    { guard.Check(); RequireAccounting(result.retained_checkpoint_xids[i] > result.retained_checkpoint_xids[i - 1]); }
    if (expected.retained_from_xid)
        RequireAccounting(*expected.retained_from_xid && *expected.retained_from_xid < scope.checkpoint_xid &&
            std::binary_search(result.retained_checkpoint_xids.begin(), result.retained_checkpoint_xids.end(), *expected.retained_from_xid));
    const auto amount = [&](const ApfsSpaceAmount& value) {
        guard.Check(); RequireAccounting(value.blocks <= capacity && value.bytes == value.blocks * bs);
    };
    for (const auto* value : {&result.referenced_metadata, &result.referenced_payload, &result.catalog_metadata}) amount(*value);
    RequireAccounting(result.catalog_metadata.blocks && result.referenced_metadata.blocks <= result.catalog_metadata.blocks &&
        result.referenced_payload.blocks <= capacity - result.catalog_metadata.blocks);
    const auto measures = [&](const ApfsSnapshotAttributionAmounts& value, std::uint64_t all) {
        for (const auto* field : {&value.referenced, &value.shared_with_live, &value.absent_from_live,
            &value.shared_with_other_snapshots, &value.unique_in_visible_inventory, &value.retained_or_peer_protected,
            &value.potential_reclaim_upper_bound}) amount(*field);
        const auto ref = value.referenced.blocks, shared = value.shared_with_live.blocks;
        const auto other = value.shared_with_other_snapshots.blocks, unique = value.unique_in_visible_inventory.blocks;
        const auto protected_blocks = value.retained_or_peer_protected.blocks, candidate = value.potential_reclaim_upper_bound.blocks;
        RequireAccounting(ref <= all && shared <= ref && value.absent_from_live.blocks == ref - shared && other <= ref &&
            unique <= ref - shared && unique <= ref - other &&
            unique >= (ref - shared > other ? ref - shared - other : 0) && protected_blocks <= ref &&
            candidate <= unique && candidate <= ref - protected_blocks &&
            candidate >= (unique > protected_blocks ? unique - protected_blocks : 0));
    };
    // Cross-row set constraints distinguish union footprints from summed rows.
    // Saturate sums at a physically bounded threshold rather than overflowing
    // when many snapshots share a large extent. capacity * 2 fits: bs >= 4096.
    struct Totals { std::uint64_t refs = 0, unique_other = 0, shared = 0; };
    std::array<Totals, 2> totals{};
    if (result.snapshots.size() > guard.cap / 512) throw Stop{payload::Reason::OutputLimit};
    if (result.snapshots.size() > UINT64_MAX / 128 ||
        !result.read_budget->Materialize(result.snapshots.size(), result.snapshots.size() * 128ull))
        throw Stop{payload::Reason::SharedBudget};
    std::unordered_set<std::string_view> names;
    names.reserve(result.snapshots.size());
    std::uint64_t previous_xid = 0;
    for (const auto& row : result.snapshots)
    {
        guard.Check();
        RequireAccounting(row.snapshot_xid > previous_xid && row.snapshot_xid <= scope.checkpoint_xid &&
            AttributionTextValid(row.name_utf8) && names.insert(row.name_utf8).second && !row.apple_purgeable && !row.reclaimable &&
            !row.purgeable_marked_payload.blocks && !row.purgeable_marked_payload.bytes && row.metadata.referenced.blocks);
        previous_xid = row.snapshot_xid;
        measures(row.metadata, result.referenced_metadata.blocks); measures(row.payload, result.referenced_payload.blocks);
        const ApfsSnapshotAttributionAmounts* values[] = {&row.metadata, &row.payload};
        const std::uint64_t unions[] = {result.referenced_metadata.blocks, result.referenced_payload.blocks};
        for (unsigned i = 0; i < 2; ++i)
        {
            const auto& value = *values[i]; auto& sum = totals[i];
            sum.refs += (std::min)(capacity - sum.refs, value.referenced.blocks);
            const auto unique = value.referenced.blocks - value.shared_with_other_snapshots.blocks;
            RequireAccounting(unique <= unions[i] - sum.unique_other);
            sum.unique_other += unique;
            sum.shared += (std::min)(2 * capacity - sum.shared, value.shared_with_other_snapshots.blocks);
        }
    }
    const std::uint64_t unions[] = {result.referenced_metadata.blocks, result.referenced_payload.blocks};
    for (unsigned i = 0; i < 2; ++i)
    {
        const auto all = unions[i]; const auto& total = totals[i];
        RequireAccounting(all <= total.refs && total.shared >= 2 * (all - total.unique_other));
        for (const auto& row : result.snapshots)
        { guard.Check(); RequireAccounting((i ? row.payload : row.metadata).shared_with_other_snapshots.blocks <= all - total.unique_other); }
    }
    guard.Check();
}

bool ProfileScopeEqual(const VerificationScope& a, const VerificationScope& b)
{
    return a.source_identity == b.source_identity && a.exact == b.exact &&
        a.max_reads == b.max_reads && a.max_read_bytes == b.max_read_bytes &&
        a.max_records == b.max_records && a.max_record_bytes == b.max_record_bytes &&
        a.require_whole_volume == b.require_whole_volume && a.require_payload_content_hashes == b.require_payload_content_hashes &&
        a.observe_payload_content == b.observe_payload_content && a.max_payload_logical_bytes == b.max_payload_logical_bytes &&
        a.max_payload_entries == b.max_payload_entries && a.retained_from_xid == b.retained_from_xid &&
        a.account_retained_ownership == b.account_retained_ownership;
}

void ValidateProfile(const CurrentProfileVerificationReport& r, CurrentVerificationProfile profile,
    const VerificationScope& scope, std::span<const VerificationStoreBinding> stores,
    std::span<const std::string> labels, const Writer& guard)
{
    const bool fusion = profile == CurrentVerificationProfile::FusionCleanCache;
    const bool encrypted = profile == CurrentVerificationProfile::EncryptedOneKeyGenerationZero;
    if (r.profile != profile || !ProfileScopeEqual(r.requested_scope, scope)) throw Stop{payload::Reason::InvalidBinding};
    RequireAccounting((fusion || encrypted) && stores.size() == (fusion ? 2u : 1u) && labels.size() == stores.size() &&
        AttributionTextValid(scope.source_identity) && scope.source_identity.size() <= 1024 &&
        scope.max_reads && scope.max_read_bytes && scope.max_records && scope.max_record_bytes &&
        r.source_reads <= scope.max_reads && r.source_read_bytes <= scope.max_read_bytes &&
        r.covered_filesystem_records <= scope.max_records && r.covered_physical_extents <= scope.max_records &&
        r.covered_volume_count <= scope.max_records && r.current_metadata_blocks <= scope.max_records &&
        !r.apple_purgeable_bytes && !r.reclaimable_bytes && !r.snapshot_allocation_charge_bytes);
    const auto uuid = [](const auto& value) {
        return value.size() == 32 && value.find_first_not_of("0123456789abcdef") == std::string::npos &&
            value.find_first_not_of('0') != std::string::npos;
    };
    RequireAccounting(uuid(scope.exact.container_uuid_hex) && uuid(scope.exact.volume_uuid_hex) &&
        scope.exact.volume_oid && scope.exact.checkpoint_xid);
    for (std::size_t i = 0; i < stores.size(); ++i)
    {
        guard.Check(); const auto& s = stores[i];
        RequireAccounting(AttributionTextValid(labels[i]) && AttributionTextValid(s.store_id) && s.store_id.size() <= 1024 &&
            s.size_bytes && s.offset_bytes <= UINT64_MAX - s.size_bytes && !(s.offset_bytes % 4096) && !(s.size_bytes % 4096));
        if (i) RequireAccounting(s.store_id != stores[0].store_id);
    }
    RequireAccounting(stores[0].offset_bytes == scope.exact.store_offset_bytes && stores[0].size_bytes == scope.exact.store_size_bytes &&
        (!encrypted || (!scope.exact.store_offset_bytes && stores[0].store_id == scope.source_identity)));
    RequireAccounting(r.stores.empty() || r.stores.size() == stores.size());
    for (std::size_t i = 0; i < r.stores.size(); ++i)
        if (r.stores[i].store_id != stores[i].store_id || r.stores[i].offset_bytes != stores[i].offset_bytes ||
            r.stores[i].size_bytes != stores[i].size_bytes) throw Stop{payload::Reason::InvalidBinding};
    const bool complete = r.outcome == VerificationOutcome::Complete;
    RequireAccounting(complete || r.outcome == VerificationOutcome::Incomplete || r.outcome == VerificationOutcome::Refused);
    RequireAccounting(complete == r.findings.empty() && r.findings.size() <= scope.max_records &&
        (!r.selected || r.selected->exact == scope.exact));
    std::array<unsigned, 23> seen{};
    constexpr unsigned common[] = {1, 2, 3, 5, 6, 7, 8, 9, 11, 13, 17};
    for (const auto& c : r.coverage)
    {
        guard.Check(); const auto id = static_cast<unsigned>(c.check), state = static_cast<unsigned>(c.state);
        RequireAccounting(id && id < seen.size() && !seen[id] && state >= 1 && state <= 5 && AttributionTextValid(c.scope_detail));
        const bool valid = std::find(std::begin(common), std::end(common), id) != std::end(common) ||
            (fusion && (id == 16 || id == 18)) || (encrypted && id == 15);
        RequireAccounting(valid); seen[id] = state;
        if (id == 13) RequireAccounting(!c.implemented && !c.required && c.state == VerificationCheckState::NotRequested);
        else RequireAccounting(c.implemented && c.required && (!complete || c.state == VerificationCheckState::Verified) &&
            c.state != VerificationCheckState::NotRequested);
    }
    for (const auto id : common) RequireAccounting(seen[id]);
    RequireAccounting(fusion ? (seen[16] && seen[18] && r.coverage.size() == 13) : (seen[15] && r.coverage.size() == 12));
    std::array<bool, 23> affected{};
    for (const auto& f : r.findings)
    {
        guard.Check(); const auto code = static_cast<unsigned>(f.code), id = static_cast<unsigned>(f.check);
        RequireAccounting(code >= 1 && code <= 27 && id && id < seen.size() && seen[id] && AttributionTextValid(f.detail) &&
            f.severity == (r.outcome == VerificationOutcome::Refused ? VerificationSeverity::Warning : VerificationSeverity::Error) &&
            seen[id] == static_cast<unsigned>(r.outcome == VerificationOutcome::Refused ? VerificationCheckState::Unsupported : VerificationCheckState::Inconsistent));
        affected[id] = true;
    }
    for (unsigned id = 1; id < seen.size(); ++id)
        if (seen[id] == 3 || seen[id] == 4) RequireAccounting(affected[id]);
    if (!complete)
    {
        RequireAccounting(!r.allocation_unit_bytes && !r.covered_volume_count && !r.covered_filesystem_records &&
            !r.covered_physical_extents && !r.current_metadata_blocks); return;
    }
    RequireAccounting(!scope.require_whole_volume && !scope.require_payload_content_hashes && !scope.observe_payload_content &&
        !scope.account_retained_ownership && !scope.retained_from_xid && r.selected && r.stores.size() == stores.size() &&
        r.source_reads && r.source_read_bytes && r.covered_volume_count && r.covered_filesystem_records && r.current_metadata_blocks &&
        (!encrypted || r.covered_volume_count == 1));
    const std::uint64_t bs = r.allocation_unit_bytes;
    RequireAccounting(bs >= 4096 && bs <= 65536 && !(bs & (bs - 1)));
    std::uint64_t capacity = 0;
    for (const auto& s : stores)
    {
        RequireAccounting(!(s.offset_bytes % bs) && !(s.size_bytes % bs) && s.size_bytes / bs <= UINT64_MAX - capacity);
        capacity += s.size_bytes / bs;
    }
    RequireAccounting(r.current_metadata_blocks <= capacity && r.covered_physical_extents <= capacity - r.current_metadata_blocks);
    const auto address = [&](std::uint64_t block) {
        if (block < stores[0].size_bytes / bs) return true;
        const auto tier = kFusionTier2ByteAddress / bs;
        return fusion && block >= tier && block - tier < stores[1].size_bytes / bs;
    };
    const auto& s = *r.selected;
    RequireAccounting(s.checkpoint_physical_block && address(s.checkpoint_physical_block) &&
        (!fusion || s.checkpoint_physical_block < stores[0].size_bytes / bs) &&
        s.volume_superblock_physical_block && address(s.volume_superblock_physical_block) &&
        s.volume_superblock_xid && s.volume_superblock_xid <= scope.exact.checkpoint_xid && s.root_oid &&
        s.root_physical_block && address(s.root_physical_block));
}

void EmitProfile(Writer& w, const CurrentProfileVerificationReport& r,
    std::span<const VerificationStoreBinding> stores, std::span<const std::string> labels)
{
    const bool fusion = r.profile == CurrentVerificationProfile::FusionCleanCache;
    w.Text("{\"format\":\"apfs-access-current-profile-verification\",\"version\":"); w.Number(CurrentProfileVerificationVersion, false);
    w.Text(",\"readOnly\":true,\"profile\":"); w.String(fusion ? "fusion-clean-cache" : "encrypted-onekey-generation-zero");
    w.Text(",\"source\":{\"identity\":"); w.String(r.requested_scope.source_identity);
    w.Text(",\"coordinateSystem\":"); w.String(fusion ? "member-image-relative" : "container-relative");
    w.Text(",\"stores\":[");
    for (std::size_t i = 0; i < stores.size(); ++i)
    {
        if (i) w.Text(","); w.Text("{\"role\":"); w.String(fusion ? (i ? "tier2" : "main") : "container");
        w.Text(",\"id\":"); w.String(stores[i].store_id); w.Text(",\"label\":"); w.String(labels[i]);
        w.Text(",\"offsetBytes\":"); w.Number(stores[i].offset_bytes); w.Text(",\"sizeBytes\":"); w.Number(stores[i].size_bytes); w.Text("}");
    }
    const auto& scope = r.requested_scope;
    w.Text("]},\"requestedScope\":{"); w.Identity(scope.exact);
    w.Text(",\"maxReads\":"); w.Number(scope.max_reads); w.Text(",\"maxReadBytes\":"); w.Number(scope.max_read_bytes);
    w.Text(",\"maxRecords\":"); w.Number(scope.max_records); w.Text(",\"maxRecordBytes\":"); w.Number(scope.max_record_bytes);
    w.Text(",\"requireWholeVolume\":"); w.Bool(scope.require_whole_volume);
    w.Text(",\"requirePayloadContentHashes\":"); w.Bool(scope.require_payload_content_hashes);
    w.Text(",\"observePayloadContent\":"); w.Bool(scope.observe_payload_content);
    w.Text(",\"accountRetainedOwnership\":"); w.Bool(scope.account_retained_ownership);
    w.Text(",\"retainedFromXid\":"); w.Optional(scope.retained_from_xid);
    w.Text("},\"selected\":"); if (r.selected) w.Selected(*r.selected); else w.Text("null");
    w.Text(",\"outcome\":"); w.Number(static_cast<unsigned>(r.outcome), false);
    w.Text(",\"outcomeName\":"); w.String(r.outcome == VerificationOutcome::Complete ? "Complete" : r.outcome == VerificationOutcome::Refused ? "Refused" : "Incomplete");
    w.Text(",\"wholeVolumeVerified\":false,\"retainedOwnershipComplete\":false,\"payloadContentHashesVerified\":false");
    w.Text(",\"sourceReads\":"); w.Number(r.source_reads); w.Text(",\"sourceReadBytes\":"); w.Number(r.source_read_bytes);
    w.Text(",\"counts\":");
    if (r.outcome != VerificationOutcome::Complete) w.Text("null");
    else
    {
        w.Text("{\"allocationUnitBytes\":"); w.Number(r.allocation_unit_bytes, false);
        w.Text(",\"volumeCount\":"); w.Number(r.covered_volume_count);
        w.Text(",\"filesystemRecords\":"); w.Number(r.covered_filesystem_records);
        w.Text(",\"physicalExtentRecords\":"); w.Number(r.covered_physical_extents);
        w.Text(",\"metadataDependencyBlocks\":"); w.Number(r.current_metadata_blocks);
        w.Text(",\"metadataCountScope\":"); w.String(fusion ? "current-object-tree-union" : "current-metadata-dependency-and-guard-union"); w.Text("}");
    }
    w.Text(",\"snapshotAllocationChargeBytes\":null,\"applePurgeableBytes\":null,\"reclaimableBytes\":null,\"findings\":["); bool first = true;
    for (const auto& f : r.findings)
    {
        if (!first) w.Text(","); first = false; w.Text("{\"code\":"); w.Number(static_cast<unsigned>(f.code), false);
        w.Text(",\"severity\":"); w.Number(static_cast<unsigned>(f.severity), false); w.Text(",\"check\":"); w.Number(static_cast<unsigned>(f.check), false);
        w.Text(",\"volumeOid\":"); w.Optional(f.volume_oid); w.Text(",\"objectId\":"); w.Optional(f.object_id);
        w.Text(",\"physicalBlock\":"); w.Optional(f.physical_block); w.Text(",\"checkpointXid\":"); w.Optional(f.checkpoint_xid);
        w.Text(",\"failedSourceOffsetBytes\":"); w.Optional(f.failed_source_offset_bytes); w.Text(",\"detail\":"); w.String(f.detail); w.Text("}");
    }
    w.Text("],\"coverage\":["); first = true;
    for (const auto& c : r.coverage)
    {
        if (!first) w.Text(","); first = false; w.Text("{\"check\":"); w.Number(static_cast<unsigned>(c.check), false);
        w.Text(",\"implemented\":"); w.Bool(c.implemented); w.Text(",\"required\":"); w.Bool(c.required);
        w.Text(",\"state\":"); w.Number(static_cast<unsigned>(c.state), false); w.Text(",\"scopeDetail\":"); w.String(c.scope_detail); w.Text("}");
    }
    w.Text("]}");
}

void ValidateRetainedProfile(const RetainedProfileHistoryReport& r, CurrentVerificationProfile profile,
    const VerificationScope& scope, std::uint64_t from, std::span<const VerificationStoreBinding> stores,
    std::span<const std::string> labels, const Writer& guard)
{
    if (r.profile != profile || !ProfileScopeEqual(r.endpoint_scope, scope) || r.from_xid != from)
        throw Stop{payload::Reason::InvalidBinding};
    const bool fusion = profile == CurrentVerificationProfile::FusionCleanCache;
    const bool complete = r.outcome == VerificationOutcome::Complete;
    RequireAccounting((fusion || profile == CurrentVerificationProfile::EncryptedOneKeyGenerationZero) &&
        stores.size() == (fusion ? 2u : 1u) && labels.size() == stores.size() && from && from < scope.exact.checkpoint_xid &&
        AttributionTextValid(scope.source_identity) && scope.source_identity.size() <= 1024 &&
        scope.max_reads && scope.max_read_bytes && scope.max_records && scope.max_record_bytes &&
        !scope.retained_from_xid && r.source_reads <= scope.max_reads && r.source_read_bytes <= scope.max_read_bytes &&
        !r.snapshot_allocation_charge_bytes && !r.apple_purgeable_bytes && !r.reclaimable_bytes &&
        (complete || r.outcome == VerificationOutcome::Incomplete || r.outcome == VerificationOutcome::Refused) &&
        complete == r.findings.empty() && r.findings.size() <= scope.max_records);
    const auto uuid = [](const std::string& value) { return value.size() == 32 &&
        value.find_first_not_of("0123456789abcdef") == std::string::npos && value.find_first_not_of('0') != std::string::npos; };
    RequireAccounting(uuid(scope.exact.container_uuid_hex) && uuid(scope.exact.volume_uuid_hex) && scope.exact.volume_oid);
    for (std::size_t i = 0; i < stores.size(); ++i)
    {
        guard.Check(); const auto& s = stores[i];
        RequireAccounting(AttributionTextValid(s.store_id) && s.store_id.size() <= 1024 && AttributionTextValid(labels[i]) &&
            s.size_bytes && s.offset_bytes <= UINT64_MAX - s.size_bytes && !(s.offset_bytes % 4096) && !(s.size_bytes % 4096) &&
            (!i || s.store_id != stores[0].store_id));
    }
    RequireAccounting(stores[0].offset_bytes == scope.exact.store_offset_bytes && stores[0].size_bytes == scope.exact.store_size_bytes &&
        (fusion || (!scope.exact.store_offset_bytes && stores[0].store_id == scope.source_identity)) &&
        (r.stores.empty() || r.stores.size() == stores.size()));
    for (std::size_t i = 0; i < r.stores.size(); ++i)
        if (r.stores[i].store_id != stores[i].store_id || r.stores[i].offset_bytes != stores[i].offset_bytes ||
            r.stores[i].size_bytes != stores[i].size_bytes) throw Stop{payload::Reason::InvalidBinding};
    for (const auto& f : r.findings)
    {
        guard.Check(); RequireAccounting(static_cast<unsigned>(f.code) >= 1 && static_cast<unsigned>(f.code) <= 27 &&
            static_cast<unsigned>(f.check) >= 1 && static_cast<unsigned>(f.check) <= 22 && AttributionTextValid(f.detail) &&
            f.severity == (r.outcome == VerificationOutcome::Refused ? VerificationSeverity::Warning : VerificationSeverity::Error));
    }
    if (!complete)
    {
        RequireAccounting(r.chain_xids.empty() && r.checkpoints.empty() && !r.selected && !r.allocation_unit_bytes &&
            !r.historical_namespace_verified); return;
    }
    const std::uint64_t bs = r.allocation_unit_bytes;
    RequireAccounting(!scope.require_whole_volume && !scope.require_payload_content_hashes && !scope.observe_payload_content &&
        !scope.account_retained_ownership && r.selected && r.selected->exact == scope.exact && r.stores.size() == stores.size() &&
        r.historical_namespace_verified == true && bs >= 4096 && bs <= 65536 && !(bs & (bs - 1)) &&
        r.source_reads && r.source_read_bytes && r.chain_xids.size() >= 2 && r.chain_xids.size() <= scope.max_records &&
        r.chain_xids.front() == from && r.chain_xids.back() == scope.exact.checkpoint_xid && r.checkpoints.size() == r.chain_xids.size());
    std::uint64_t capacity = 0;
    for (const auto& s : stores)
    {
        RequireAccounting(!(s.offset_bytes % bs) && !(s.size_bytes % bs) && s.size_bytes / bs <= UINT64_MAX - capacity);
        capacity += s.size_bytes / bs;
    }
    const auto address = [&](std::uint64_t block, std::uint64_t count = 1) {
        if (!count) return false;
        if (block < stores[0].size_bytes / bs) return count <= stores[0].size_bytes / bs - block;
        const auto base = kFusionTier2ByteAddress / bs;
        return fusion && block >= base && block - base < stores[1].size_bytes / bs && count <= stores[1].size_bytes / bs - (block - base);
    };
    const auto& selected = *r.selected;
    RequireAccounting(selected.checkpoint_physical_block && selected.checkpoint_physical_block < stores[0].size_bytes / bs &&
        selected.volume_superblock_physical_block && address(selected.volume_superblock_physical_block) &&
        selected.root_physical_block && address(selected.root_physical_block) && selected.root_oid &&
        selected.volume_superblock_xid && selected.volume_superblock_xid <= scope.exact.checkpoint_xid);
    for (std::size_t i = 0; i < r.checkpoints.size(); ++i)
    {
        guard.Check(); const auto& cp = r.checkpoints[i];
        RequireAccounting(cp.checkpoint_xid == r.chain_xids[i] && (!i || r.chain_xids[i-1] < cp.checkpoint_xid) && !cp.metadata_ranges.empty());
        std::uint64_t total = 0;
        for (const auto* ranges : {&cp.metadata_ranges, &cp.payload_ranges})
        {
            RequireAccounting(ranges->size() <= scope.max_records); std::uint64_t previous = 0; bool first = true;
            for (const auto& range : *ranges)
            {
                guard.Check(); RequireAccounting(address(range.physical_block, range.block_count) &&
                    range.physical_block <= UINT64_MAX - range.block_count && (first || range.physical_block > previous) &&
                    range.block_count <= capacity - total);
                if (!r.read_budget->Materialize(1, 0)) throw Stop{payload::Reason::SharedBudget};
                total += range.block_count; previous = range.physical_block + range.block_count; first = false;
            }
        }
    }
    for (const auto& a : r.checkpoints) for (const auto& b : r.checkpoints)
    {
        guard.Check(); if (!r.read_budget->Materialize(1, 0)) throw Stop{payload::Reason::SharedBudget};
        AccountingDisjoint(a.metadata_ranges, b.payload_ranges, guard);
    }
}

void EmitRetainedProfile(Writer& w, const RetainedProfileHistoryReport& r,
    std::span<const VerificationStoreBinding> stores, std::span<const std::string> labels)
{
    const bool fusion = r.profile == CurrentVerificationProfile::FusionCleanCache;
    w.Text("{\"format\":\"apfs-access-retained-profile-verification\",\"version\":"); w.Number(RetainedProfileVerificationVersion, false);
    w.Text(",\"readOnly\":true,\"profile\":"); w.String(fusion ? "fusion-clean-cache" : "encrypted-onekey-generation-zero");
    w.Text(",\"source\":{\"identity\":"); w.String(r.endpoint_scope.source_identity);
    w.Text(",\"coordinateSystem\":"); w.String(fusion ? "member-image-relative" : "container-relative"); w.Text(",\"stores\":[");
    for (std::size_t i = 0; i < stores.size(); ++i)
    {
        if (i) w.Text(","); w.Text("{\"role\":"); w.String(fusion ? (i ? "tier2" : "main") : "container");
        w.Text(",\"id\":"); w.String(stores[i].store_id); w.Text(",\"label\":"); w.String(labels[i]);
        w.Text(",\"offsetBytes\":"); w.Number(stores[i].offset_bytes); w.Text(",\"sizeBytes\":"); w.Number(stores[i].size_bytes); w.Text("}");
    }
    const auto& scope = r.endpoint_scope;
    w.Text("]},\"requestedScope\":{"); w.Identity(scope.exact);
    w.Text(",\"maxReads\":"); w.Number(scope.max_reads); w.Text(",\"maxReadBytes\":"); w.Number(scope.max_read_bytes);
    w.Text(",\"maxRecords\":"); w.Number(scope.max_records); w.Text(",\"maxRecordBytes\":"); w.Number(scope.max_record_bytes);
    w.Text(",\"requireWholeVolume\":"); w.Bool(scope.require_whole_volume);
    w.Text(",\"requirePayloadContentHashes\":"); w.Bool(scope.require_payload_content_hashes);
    w.Text(",\"observePayloadContent\":"); w.Bool(scope.observe_payload_content);
    w.Text(",\"accountRetainedOwnership\":"); w.Bool(scope.account_retained_ownership);
    w.Text(",\"retainedFromXid\":null},\"fromXid\":"); w.Number(r.from_xid);
    w.Text(",\"selected\":"); if (r.selected) w.Selected(*r.selected); else w.Text("null");
    w.Text(",\"outcome\":"); w.Number(static_cast<unsigned>(r.outcome), false);
    w.Text(",\"outcomeName\":"); w.String(r.outcome == VerificationOutcome::Complete ? "Complete" : r.outcome == VerificationOutcome::Refused ? "Refused" : "Incomplete");
    w.Text(",\"wholeVolumeVerified\":false,\"retainedOwnershipComplete\":false,\"payloadContentHashesVerified\":false,\"historicalNamespaceVerified\":");
    w.Text(r.historical_namespace_verified == true ? "true" : "null");
    w.Text(",\"sourceReads\":"); w.Number(r.source_reads); w.Text(",\"sourceReadBytes\":"); w.Number(r.source_read_bytes);
    w.Text(",\"history\":");
    if (r.outcome != VerificationOutcome::Complete) w.Text("null");
    else
    {
        w.Text("{\"allocationUnitBytes\":"); w.Number(r.allocation_unit_bytes, false);
        w.Text(",\"snapshotOwnerScope\":\"canonical-empty-inventories-only\",\"chainXids\":[");
        for (std::size_t i = 0; i < r.chain_xids.size(); ++i) { if (i) w.Text(","); w.Number(r.chain_xids[i]); }
        w.Text("],\"checkpoints\":[");
        for (std::size_t i = 0; i < r.checkpoints.size(); ++i)
        {
            if (i) w.Text(","); const auto& cp = r.checkpoints[i]; w.Text("{\"checkpointXid\":"); w.Number(cp.checkpoint_xid);
            w.Text(",\"metadataRanges\":"); w.Ranges(cp.metadata_ranges); w.Text(",\"payloadRanges\":"); w.Ranges(cp.payload_ranges); w.Text("}");
        }
        w.Text("]}");
    }
    w.Text(",\"snapshotAllocationChargeBytes\":null,\"applePurgeableBytes\":null,\"reclaimableBytes\":null,\"findings\":[");
    for (std::size_t i = 0; i < r.findings.size(); ++i)
    {
        if (i) w.Text(","); const auto& f = r.findings[i]; w.Text("{\"code\":"); w.Number(static_cast<unsigned>(f.code), false);
        w.Text(",\"severity\":"); w.Number(static_cast<unsigned>(f.severity), false); w.Text(",\"check\":"); w.Number(static_cast<unsigned>(f.check), false);
        w.Text(",\"volumeOid\":"); w.Optional(f.volume_oid); w.Text(",\"objectId\":"); w.Optional(f.object_id);
        w.Text(",\"physicalBlock\":"); w.Optional(f.physical_block); w.Text(",\"checkpointXid\":"); w.Optional(f.checkpoint_xid);
        w.Text(",\"failedSourceOffsetBytes\":"); w.Optional(f.failed_source_offset_bytes); w.Text(",\"detail\":"); w.String(f.detail); w.Text("}");
    }
    w.Text("],\"coverage\":[{\"check\":22,\"implemented\":true,\"required\":true,\"state\":");
    w.Number(r.outcome == VerificationOutcome::Complete ? 2 : r.outcome == VerificationOutcome::Refused ? 4 : 3, false);
    w.Text(",\"scopeDetail\":\"Explicit checkpoint chain, canonical namespaces and physical protection continuity; canonical empty snapshot inventories only; no exhaustive hidden-owner or orphan census\"}]}");
}
}

static bool SerializeVerificationReportImpl(const VerificationReport& report, std::string_view image_path,
    const std::function<bool()>& within_deadline, std::size_t max_output_bytes,
    std::string& output, payload::Reason& failure, bool protected_history)
{
    output.clear(); failure = payload::Reason::None;
    const auto cap = (std::min)(max_output_bytes, MaxImageVerificationJsonBytes);
    Writer count{report, within_deadline, cap};
    try
    {
        count.Check();
        if (protected_history) ValidateProtectedHistoryReport(report);
        else if (report.requested_scope.account_retained_ownership) ValidateAccountingReport(report, count);
        else ValidateReport(report);
        std::string inventory;
        if (report.payload_inventory && !payload::SerializeInventory(*report.payload_inventory,
            report.read_budget, within_deadline, cap, inventory, failure))
        {
            if (failure == payload::Reason::OutputLimit) report.read_budget->Refuse("VerificationResponseLimit");
            return false;
        }
        count.Emit(image_path, inventory, protected_history);
        if (!report.read_budget->Materialize(1, count.size + 64)) throw Stop{payload::Reason::SharedBudget};
        output.reserve(count.size);
        Writer writer{report, within_deadline, cap, 0, &output};
        writer.Emit(image_path, inventory, protected_history); writer.Check();
        return true;
    }
    catch (const Stop& stop) { failure = stop.reason; }
    catch (const std::bad_alloc&) { failure = payload::Reason::AllocationFailure; }
    catch (const std::length_error&) { failure = payload::Reason::AllocationFailure; }
    catch (...) { failure = payload::Reason::CallbackFailure; }
    if (report.read_budget && (failure == payload::Reason::OutputLimit || failure == payload::Reason::AllocationFailure))
        report.read_budget->Refuse(failure == payload::Reason::OutputLimit ? "VerificationResponseLimit" : "VerificationResponseAllocationFailed");
    output.clear(); return false;
}

bool SerializeImageVerificationReport(const VerificationReport& report, std::string_view image_path,
    const std::function<bool()>& within_deadline, std::size_t max_output_bytes,
    std::string& output, payload::Reason& failure)
{
    return SerializeVerificationReportImpl(report, image_path, within_deadline, max_output_bytes, output, failure, false);
}

bool SerializeProtectedHistoryVerificationReport(const VerificationReport& report, std::string_view image_path,
    const std::function<bool()>& within_deadline, std::size_t max_output_bytes,
    std::string& output, payload::Reason& failure)
{
    return SerializeVerificationReportImpl(report, image_path, within_deadline, max_output_bytes, output, failure, true);
}

bool SerializeSnapshotSpaceAttribution(const std::optional<ApfsSnapshotSpaceAttribution>& result,
    const VerificationScope& expected_scope, std::string_view image_path,
    const std::function<bool()>& within_deadline, std::size_t max_output_bytes,
    std::string& output, payload::Reason& failure)
{
    output.clear(); failure = payload::Reason::None;
    if (!result || !result->complete) { failure = payload::Reason::AdmissionNotComplete; return false; }
    // Reuse the existing bounded JSON writer without changing any legacy codec.
    VerificationReport binding; binding.read_budget = result->read_budget;
    const auto cap = (std::min)(max_output_bytes, MaxSnapshotSpaceAttributionJsonBytes);
    Writer count{binding, within_deadline, cap};
    try
    {
        count.Check(); ValidateAttribution(*result, expected_scope, image_path, count);
        EmitAttribution(count, *result, image_path);
        if (!result->read_budget->Materialize(1, count.size + 64)) throw Stop{payload::Reason::SharedBudget};
        output.reserve(count.size);
        Writer writer{binding, within_deadline, cap, 0, &output};
        EmitAttribution(writer, *result, image_path); writer.Check(); return true;
    }
    catch (const Stop& stop) { failure = stop.reason; }
    catch (const std::bad_alloc&) { failure = payload::Reason::AllocationFailure; }
    catch (const std::length_error&) { failure = payload::Reason::AllocationFailure; }
    catch (...) { failure = payload::Reason::CallbackFailure; }
    if (result->read_budget && (failure == payload::Reason::OutputLimit || failure == payload::Reason::AllocationFailure))
        result->read_budget->Refuse(failure == payload::Reason::OutputLimit ? "SnapshotAttributionResponseLimit" : "SnapshotAttributionResponseAllocationFailed");
    output.clear(); return false;
}

bool SerializeCurrentProfileVerificationReport(const CurrentProfileVerificationReport& report,
    CurrentVerificationProfile expected_profile, const VerificationScope& expected_scope,
    std::span<const VerificationStoreBinding> expected_stores, std::span<const std::string> source_labels,
    const std::function<bool()>& within_deadline, std::size_t max_output_bytes,
    std::string& output, payload::Reason& failure)
{
    output.clear(); failure = payload::Reason::None;
    VerificationReport binding; binding.read_budget = report.read_budget;
    const auto cap = (std::min)(max_output_bytes, MaxImageVerificationJsonBytes);
    Writer count{binding, within_deadline, cap};
    try
    {
        count.Check(); ValidateProfile(report, expected_profile, expected_scope, expected_stores, source_labels, count);
        EmitProfile(count, report, expected_stores, source_labels);
        if (!report.read_budget->Materialize(1, count.size + 64)) throw Stop{payload::Reason::SharedBudget};
        output.reserve(count.size); Writer writer{binding, within_deadline, cap, 0, &output};
        EmitProfile(writer, report, expected_stores, source_labels); writer.Check(); return true;
    }
    catch (const Stop& stop) { failure = stop.reason; }
    catch (const std::bad_alloc&) { failure = payload::Reason::AllocationFailure; }
    catch (const std::length_error&) { failure = payload::Reason::AllocationFailure; }
    catch (...) { failure = payload::Reason::CallbackFailure; }
    if (report.read_budget && (failure == payload::Reason::OutputLimit || failure == payload::Reason::AllocationFailure))
        report.read_budget->Refuse(failure == payload::Reason::OutputLimit ? "ProfileVerificationResponseLimit" : "ProfileVerificationResponseAllocationFailed");
    output.clear(); return false;
}

bool SerializeRetainedProfileVerificationReport(const RetainedProfileHistoryReport& report,
    CurrentVerificationProfile expected_profile, const VerificationScope& expected_scope, std::uint64_t expected_from_xid,
    std::span<const VerificationStoreBinding> expected_stores, std::span<const std::string> source_labels,
    const std::function<bool()>& within_deadline, std::size_t max_output_bytes,
    std::string& output, payload::Reason& failure)
{
    output.clear(); failure = payload::Reason::None;
    VerificationReport binding; binding.read_budget = report.read_budget; binding.requested_scope = expected_scope;
    const auto cap = (std::min)(max_output_bytes, MaxImageVerificationJsonBytes);
    Writer count{binding, within_deadline, cap};
    try
    {
        count.Check(); ValidateRetainedProfile(report, expected_profile, expected_scope, expected_from_xid, expected_stores, source_labels, count);
        EmitRetainedProfile(count, report, expected_stores, source_labels);
        if (!report.read_budget->Materialize(1, count.size + 64)) throw Stop{payload::Reason::SharedBudget};
        output.reserve(count.size); Writer writer{binding, within_deadline, cap, 0, &output};
        EmitRetainedProfile(writer, report, expected_stores, source_labels); writer.Check(); return true;
    }
    catch (const Stop& stop) { failure = stop.reason; }
    catch (const std::bad_alloc&) { failure = payload::Reason::AllocationFailure; }
    catch (const std::length_error&) { failure = payload::Reason::AllocationFailure; }
    catch (...) { failure = payload::Reason::CallbackFailure; }
    if (report.read_budget && (failure == payload::Reason::OutputLimit || failure == payload::Reason::AllocationFailure))
        report.read_budget->Refuse(failure == payload::Reason::OutputLimit ? "RetainedProfileResponseLimit" : "RetainedProfileResponseAllocationFailed");
    output.clear(); return false;
}
#include "SnapshotAllocationCounterJson.inc"
#include "VisibleSnapshotProfileJson.inc"
#include "MarkedReferenceSpaceJson.inc"
#include "MarkedOwnerSpaceJson.inc"
}
