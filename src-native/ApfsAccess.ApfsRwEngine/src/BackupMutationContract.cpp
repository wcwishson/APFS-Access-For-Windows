#include "BackupMutationContract.h"
#include <Windows.h>
#include <algorithm>

namespace apfsaccess::rw
{
std::optional<TransactionManager::MutationKind> BackupMutationJournalKind(MetadataStore::MutationOperation operation) noexcept
{
    using Op = MetadataStore::MutationOperation;
    using Kind = TransactionManager::MutationKind;
    switch (operation)
    {
    case Op::Write: return Kind::Write;
    case Op::CreateFile: return Kind::CreateFile;
    case Op::CreateDirectory: return Kind::CreateDirectory;
    case Op::Rename: return Kind::Rename;
    case Op::Delete: return Kind::Delete;
    case Op::SetFileSize: return Kind::SetFileSize;
    case Op::SetAllocationSize: return Kind::SetAllocationSize;
    case Op::SetBasicInfo: return Kind::SetBasicInfo;
    case Op::SetInodeMetadata: return Kind::SetInodeMetadata;
    case Op::SetExtendedAttribute: return Kind::SetExtendedAttribute;
    case Op::RemoveExtendedAttribute: return Kind::RemoveExtendedAttribute;
    case Op::CloneFile: return Kind::CloneFile;
    default: return {};
    }
}
bool IsBackupRetainedMutation(MetadataStore::MutationOperation operation) noexcept
{ return BackupMutationJournalKind(operation).has_value(); }

bool DecodeBackupAcceptedMutation(const WriteAheadLog::Record& record,
    MetadataStore::MutationRequest& request, std::string& error)
{
    request = {}; error.clear();
    const auto fail = [&] { request = {}; error = "BackupAcceptedTypedMutationInvalid"; return false; };
    using Wal = WriteAheadLog::OperationKind;
    using Op = MetadataStore::MutationOperation;
    if (!record.transaction_id || !record.sequence || record.object_id <= 2 || !record.parent_object_id ||
        record.state != WriteAheadLog::RecordState::Prepared || !WriteAheadLog::UnlinkOutcomeIsConsistent(record)) return fail();
    const auto text = [](const std::string& value, std::wstring& out, bool path) {
        if (value.empty() || value.size() > 4096 || value.find('\0') != value.npos) return false;
        const auto size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
        if (size <= 0) return false;
        out.resize(static_cast<std::size_t>(size));
        if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), out.data(), size) != size ||
            TransactionManager::WideToUtf8(out) != value) return false;
        return !path || (out.front() == L'\\' && out.find(L'/') == out.npos &&
            (out.size() == 1 || out.back() != L'\\') && out.find(L"\\\\") == out.npos &&
            out.find(L"\\.\\") == out.npos && out.find(L"\\..\\") == out.npos &&
            !out.ends_with(L"\\.") && !out.ends_with(L"\\.."));
    };
    if (!text(record.path_utf8, request.path, true)) return fail();
    request.object_id = record.object_id; request.generation = record.parent_object_id;
    const bool write = record.operation == Wal::Write, rename = record.operation == Wal::Rename;
    const bool patch = record.operation == Wal::SetInodeMetadata;
    const bool attribute = record.operation == Wal::SetExtendedAttribute || record.operation == Wal::RemoveExtendedAttribute;
    const bool clone = record.operation == Wal::CloneFile;
    if ((record.flags && (!rename || (record.flags & ~0x4u))) ||
        (record.unlink_outcome && record.operation != Wal::Delete) ||
        (!rename && !attribute && !clone && !record.secondary_path_utf8.empty()) ||
        (!write && !patch && !attribute && !clone && (record.payload_length || record.payload_offset || record.payload_spool_id ||
            !record.inline_payload.empty() || std::any_of(record.payload_sha256.begin(), record.payload_sha256.end(), [](auto b) { return b != 0; }))) ||
        (!write && record.operation != Wal::SetBasicInfo && record.logical_offset) ||
        (!write && record.operation != Wal::SetFileSize && record.operation != Wal::SetAllocationSize && !clone && record.logical_length))
        return fail();
    switch (record.operation)
    {
    case Wal::CreateFile: request.operation = Op::CreateFile; break;
    case Wal::CreateDirectory: request.operation = Op::CreateDirectory; break;
    case Wal::Rename:
        if (!text(record.secondary_path_utf8, request.secondary_path, true)) return fail();
        request.operation = Op::Rename; request.replace_if_exists = (record.flags & 0x4u) != 0; break;
    case Wal::Delete:
        if (!record.unlink_outcome) return fail();
        request.operation = Op::Delete; request.expected_unlink_outcome = record.unlink_outcome; break;
    case Wal::SetFileSize:
    case Wal::SetAllocationSize:
        if (record.logical_length > (8ull << 20) ||
            (record.operation == Wal::SetAllocationSize && !WriteAheadLog::AllocationSizeMutationIsConsistent(record))) return fail();
        request.operation = record.operation == Wal::SetFileSize ? Op::SetFileSize : Op::SetAllocationSize;
        request.length = record.logical_length; break;
    case Wal::SetBasicInfo: request.operation = Op::SetBasicInfo; request.timestamp_utc = record.logical_offset; break;
    case Wal::SetInodeMetadata:
        if (!WriteAheadLog::InodeMetadataMutationIsConsistent(record)) return fail();
        request.operation = Op::SetInodeMetadata; request.inline_payload = record.inline_payload; request.length = record.payload_length; break;
    case Wal::SetExtendedAttribute:
    case Wal::RemoveExtendedAttribute:
        if (!WriteAheadLog::ExtendedAttributeMutationIsConsistent(record) ||
            !text(record.secondary_path_utf8, request.secondary_path, false)) return fail();
        request.operation = record.operation == Wal::SetExtendedAttribute ? Op::SetExtendedAttribute : Op::RemoveExtendedAttribute;
        request.inline_payload = record.inline_payload; request.length = record.payload_length; break;
    case Wal::CloneFile:
        if (!MetadataStore::NativeCloneFromWal(record, request)) return fail();
        if (!text(record.path_utf8, request.path, true) || !text(record.secondary_path_utf8, request.secondary_path, true)) return fail();
        break;
    case Wal::Write:
        if (!record.payload_length || record.payload_length != record.logical_length || record.payload_spool_id != record.sequence ||
            record.payload_length > (256ull << 10) || record.logical_offset > (8ull << 20) - record.payload_length ||
            !WriteAheadLog::InlinePayloadIsConsistent(record)) return fail();
        request.operation = Op::Write; request.offset = record.logical_offset; request.length = record.logical_length; break;
    default: return fail();
    }
    return IsBackupRetainedMutation(request.operation);
}
}
