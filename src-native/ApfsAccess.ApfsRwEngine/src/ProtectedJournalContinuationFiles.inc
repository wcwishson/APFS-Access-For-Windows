// Included inside apfsaccess::rw. Only certificate metadata and ciphertext are
// buffered here; each provider plaintext chunk is authenticated in SecureBytes.
namespace
{
using ContinuationHash = std::array<std::uint8_t, 32>;
constexpr std::size_t continuation_limit = 4u * 1024u * 1024u;
bool CHash(std::span<const std::byte> bytes, ContinuationHash& hash)
{
    return bytes.size() <= ULONG_MAX && BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())), static_cast<ULONG>(bytes.size()),
        hash.data(), static_cast<ULONG>(hash.size())) >= 0;
}
void CPut(std::span<std::byte> b, std::size_t at, std::uint64_t n)
{ for (unsigned i = 0; i < 8; ++i) b[at + i] = std::byte((n >> (i * 8)) & 255); }
std::uint64_t CGet(std::span<const std::byte> b, std::size_t at)
{ std::uint64_t n = 0; for (unsigned i = 0; i < 8; ++i) n |= std::to_integer<std::uint64_t>(b[at + i]) << (i * 8); return n; }
bool CPath(const std::filesystem::path& path)
{
    const auto p = path.wstring();
    if (p.size() < 4 || p.size() > 210 || !path.is_absolute() || p[1] != L':' || p[2] != L'\\' ||
        p.back() == L'\\' || p.find_first_of(L":/*?\"<>|", 3) != p.npos || GetDriveTypeW(p.substr(0, 3).c_str()) != DRIVE_FIXED) return false;
    for (auto c : p) if (c < 32) return false;
    for (const auto& part : path.relative_path()) {
        const auto s = part.wstring();
        if (s.empty() || s == L"." || s == L".." || s.back() == L'.' || s.back() == L' ') return false;
        const auto stem = s.substr(0, s.find(L'.'));
        for (const auto* name : {L"CON", L"PRN", L"AUX", L"NUL", L"CONIN$", L"CONOUT$"})
            if (CompareStringOrdinal(stem.c_str(), -1, name, -1, TRUE) == CSTR_EQUAL) return false;
        if (stem.size() == 4 && (CompareStringOrdinal(stem.data(), 3, L"COM", 3, TRUE) == CSTR_EQUAL ||
            CompareStringOrdinal(stem.data(), 3, L"LPT", 3, TRUE) == CSTR_EQUAL)) return false;
    }
    return true;
}
bool CExact(HANDLE h, const std::filesystem::path& path, bool directory = false)
{
    BY_HANDLE_FILE_INFORMATION info{};
    if (h == INVALID_HANDLE_VALUE || GetFileType(h) != FILE_TYPE_DISK || !GetFileInformationByHandle(h, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || (!directory && info.nNumberOfLinks != 1) ||
        bool(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != directory) return false;
    std::array<wchar_t, 512> actual{};
    const auto n = GetFinalPathNameByHandleW(h, actual.data(), static_cast<DWORD>(actual.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    const auto expected = L"\\\\?\\" + path.wstring();
    return n && n < actual.size() && CompareStringOrdinal(actual.data(), -1, expected.c_str(), -1, TRUE) == CSTR_EQUAL;
}
bool CAbsent(const std::filesystem::path& p)
{ return GetFileAttributesW(p.c_str()) == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND; }
struct CFile
{
    HANDLE h = INVALID_HANDLE_VALUE; bool owns = true;
    std::filesystem::path path;
    CFile() = default;
    CFile(const CFile&) = delete;
    ~CFile() { if (owns && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    bool Open(const std::filesystem::path& p, bool create = false)
    { return OpenWithFlags(p, create, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH); }
    bool OpenCandidate(const std::filesystem::path& p, bool create)
    {
        if (!p.wstring().ends_with(L".jcont.next")) return false;
        return OpenWithFlags(p, create, FILE_FLAG_OPEN_REPARSE_POINT);
    }
private:
    bool OpenWithFlags(const std::filesystem::path& p, bool create, DWORD flags)
    {
        if (!CPath(p)) return false;
        path = p; h = CreateFileW(p.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ,
            nullptr, create ? CREATE_NEW : OPEN_EXISTING, flags, nullptr);
        return CExact(h, p);
    }
public:
    bool Read(std::vector<std::byte>& b, std::uint64_t limit) const
    {
        LARGE_INTEGER size{}, at{}; DWORD read = 0;
        if (!CExact(h, path) || !GetFileSizeEx(h, &size) || size.QuadPart < 0 ||
            static_cast<std::uint64_t>(size.QuadPart) > limit || size.QuadPart > MAXDWORD || !SetFilePointerEx(h, at, nullptr, FILE_BEGIN)) return false;
        b.resize(static_cast<std::size_t>(size.QuadPart));
        return ReadFile(h, b.data(), static_cast<DWORD>(b.size()), &read, nullptr) && read == b.size();
    }
    bool WriteBytes(std::span<const std::byte> b) const
    {
        LARGE_INTEGER zero{}; DWORD wrote = 0;
        return b.size() <= MAXDWORD && CExact(h, path) && SetFilePointerEx(h, zero, nullptr, FILE_BEGIN) &&
            WriteFile(h, b.data(), static_cast<DWORD>(b.size()), &wrote, nullptr) && wrote == b.size();
    }
    bool Write(std::span<const std::byte> b) const
    { return WriteBytes(b) && FlushFileBuffers(h); }
    bool Rename(const std::filesystem::path& to)
    {
        if (!CExact(h, path) || !CPath(to) || !CAbsent(to)) return false;
        const auto s = to.wstring();
        std::vector<std::byte> b(sizeof(FILE_RENAME_INFO) + s.size() * sizeof(wchar_t));
        auto* info = reinterpret_cast<FILE_RENAME_INFO*>(b.data());
        info->ReplaceIfExists = FALSE; info->FileNameLength = static_cast<DWORD>(s.size() * sizeof(wchar_t));
        std::memcpy(info->FileName, s.data(), info->FileNameLength);
        if (!SetFileInformationByHandle(h, FileRenameInfo, info, static_cast<DWORD>(b.size()))) return false;
        path = to;
        return CExact(h, path) && FlushFileBuffers(h);
    }
};
struct CStamp
{
    std::uint64_t bytes = 0, volume = 0, file = 0;
    ContinuationHash hash{};
    bool operator==(const CStamp&) const = default;
};
bool CStampFile(const CFile& f, CStamp& stamp)
{
    BY_HANDLE_FILE_INFORMATION info{}; LARGE_INTEGER size{};
    if (!CExact(f.h, f.path) || !GetFileInformationByHandle(f.h, &info) || !GetFileSizeEx(f.h, &size) || size.QuadPart < 0) return false;
    stamp.bytes = static_cast<std::uint64_t>(size.QuadPart); stamp.volume = info.dwVolumeSerialNumber;
    stamp.file = (std::uint64_t{info.nFileIndexHigh} << 32) | info.nFileIndexLow;
    // The bounded files are streamed; no 64 MiB locked allocation is required.
    auto object = crypto::SecureBytes::Allocate(512), buffer = crypto::SecureBytes::Allocate(4096);
    DWORD object_bytes = 0, got = 0;
    if (!object || !buffer || BCryptGetProperty(BCRYPT_SHA256_ALG_HANDLE, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&object_bytes), sizeof(object_bytes), &got, 0) < 0 || object_bytes > object.bytes.Size()) return false;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &hash, reinterpret_cast<PUCHAR>(object.bytes.Bytes().data()),
        static_cast<ULONG>(object.bytes.Size()), nullptr, 0, 0) < 0) return false;
    bool ok = true; LARGE_INTEGER at{};
    ok = SetFilePointerEx(f.h, at, nullptr, FILE_BEGIN) != FALSE;
    for (std::uint64_t n = 0; ok && n < stamp.bytes;) {
        const auto b = buffer.bytes.Bytes().first(static_cast<std::size_t>((std::min)(stamp.bytes - n, std::uint64_t{4096})));
        DWORD read = 0;
        ok = ReadFile(f.h, b.data(), static_cast<DWORD>(b.size()), &read, nullptr) && read == b.size() &&
            BCryptHashData(hash, reinterpret_cast<PUCHAR>(b.data()), static_cast<ULONG>(b.size()), 0) >= 0;
        n += b.size();
    }
    ok = ok && BCryptFinishHash(hash, stamp.hash.data(), static_cast<ULONG>(stamp.hash.size()), 0) >= 0;
    BCryptDestroyHash(hash); return ok;
}
struct CEncoder
{
    std::vector<std::byte> b;
    ~CEncoder() { SecureZeroMemory(b.data(), b.size()); }
    void N(std::uint64_t n) { const auto at = b.size(); if (at > continuation_limit - 8) throw std::runtime_error("ContinuationLimit"); b.resize(at + 8); CPut(b, at, n); }
    void B(std::span<const std::byte> bytes) { N(bytes.size()); if (bytes.size() > continuation_limit - b.size()) throw std::runtime_error("ContinuationLimit"); b.insert(b.end(), bytes.begin(), bytes.end()); }
    template<class T> void A(const T& bytes) { B(std::as_bytes(std::span(bytes))); }
    void S(std::string_view s) { B(std::as_bytes(std::span(s))); }
};
struct CDecoder
{
    std::span<const std::byte> b;
    std::uint64_t N() { if (b.size() < 8) throw std::runtime_error("ContinuationTruncated"); const auto n = CGet(b, 0); b = b.subspan(8); return n; }
    auto B(std::size_t max) { const auto n = N(); if (n > max || n > b.size()) throw std::runtime_error("ContinuationLength"); const auto v = b.first(static_cast<std::size_t>(n)); b = b.subspan(static_cast<std::size_t>(n)); return v; }
    template<class T> void A(T& a) { const auto bytes = B(sizeof(a)); if (bytes.size() != sizeof(a)) throw std::runtime_error("ContinuationField"); std::memcpy(a.data(), bytes.data(), bytes.size()); }
    std::string S() { const auto s = B(4096); return {reinterpret_cast<const char*>(s.data()), s.size()}; }
};
struct CRecordsWipe
{
    std::vector<WriteAheadLog::Record>& rows;
    ~CRecordsWipe() { for (auto& r : rows) { SecureZeroMemory(r.inline_payload.data(), r.inline_payload.size()); SecureZeroMemory(r.path_utf8.data(), r.path_utf8.size()); SecureZeroMemory(r.secondary_path_utf8.data(), r.secondary_path_utf8.size()); } }
};
struct CBytesWipe
{
    std::vector<std::byte>& bytes;
    ~CBytesWipe() { SecureZeroMemory(bytes.data(), bytes.size()); }
};
}

struct ProtectedJournalContinuation::Operation
{
    struct Entry { std::uint64_t role = 0, number = 0; CStamp stamp; };
    std::uint64_t generation = 0;
    Authority authority;
    Endpoint::Description endpoint;
    Seed predecessor_seed;
    Digest predecessor_publication{};
    std::optional<WriteAheadLog::ContinuationAdmission> predecessor_original, predecessor_witness;
    WriteAheadLog::ContinuationAdmission original, witness;
    PayloadSpool::ContinuationBaseline spool;
    std::vector<Entry> entries;
    std::array<std::vector<std::byte>, 3> candidates;
    Digest certificate_hash{};
    std::vector<std::unique_ptr<CFile>> retained;
    std::vector<std::unique_ptr<CFile>> directories;
    std::mutex control_read_mutex;
    std::uint32_t progress_slots = 0;
    int progress_rank = -1;
    std::uint8_t progress_ordinal = 0;

    bool Completed(DurableBoundary boundary, std::uint8_t index, const ProgressHook& progress, std::string& error)
    {
        unsigned slot = 20, rank = 20;
        switch (boundary) {
        case DurableBoundary::OriginalSpoolBarrier: if (!index) slot = rank = 0; break;
        case DurableBoundary::IntentFlushed: if (!index) slot = rank = 1; break;
        case DurableBoundary::RecoveryBarrier: if (!index) slot = rank = 2; break;
        case DurableBoundary::ControlRenamed: if (index >= 5 && index <= 8) slot = rank = index - 2; break;
        case DurableBoundary::CertificatePromoted: if (!index) slot = rank = 7; break;
        case DurableBoundary::CandidateFlushed: if (index < 3) { slot = 8 + index; rank = 8 + 3 * index; } break;
        case DurableBoundary::OldRenamed: if (index < 3) { slot = 11 + index; rank = 9 + 3 * index; } break;
        case DurableBoundary::NewRenamed: if (index < 3) { slot = 14 + index; rank = 10 + 3 * index; } break;
        case DurableBoundary::CompletionReceipt: if (!index) slot = rank = 17; break;
        case DurableBoundary::RetirementReceipt: if (!index) slot = rank = 18; break;
        case DurableBoundary::ReadyReceipt: if (!index) slot = rank = 19; break;
        }
        if (slot >= 20 || static_cast<int>(rank) <= progress_rank || (progress_slots & (1u << slot))) {
            error = "ContinuationProgressOrderInvalid"; return false;
        }
        progress_slots |= 1u << slot; progress_rank = static_cast<int>(rank); ++progress_ordinal;
        const DurableProgress event(boundary, index, static_cast<std::uint8_t>(slot), progress_ordinal);
        if (progress && !progress(event)) { error = "ContinuationProgressObserverRefused"; return false; }
        return true;
    }

    static auto Side(const std::filesystem::path& p, const wchar_t* suffix) { return std::filesystem::path(p.wstring() + suffix); }
    static void SeedOut(CEncoder& e, const Seed& s) { for (auto n : {s.last_sequence,s.next_transaction_id,s.accepted_sequence,s.durable_sequence,s.cleanup_sequence}) e.N(n); }
    static Seed SeedIn(CDecoder& d) { return {d.N(),d.N(),d.N(),d.N(),d.N()}; }
    static void HeadOut(CEncoder& e, const WriteAheadLog::ProtectedHistoryHead& h) { e.N(h.bytes);e.N(h.records);e.N(h.last_sequence);e.A(h.sha256); }
    static auto HeadIn(CDecoder& d) { WriteAheadLog::ProtectedHistoryHead h; h.bytes=d.N();h.records=d.N();h.last_sequence=d.N();d.A(h.sha256);return h; }
    static void AdmissionOut(CEncoder& e, const WriteAheadLog::ContinuationAdmission& a) { e.A(a.anchor);e.N(a.last_sequence); }
    static auto AdmissionIn(CDecoder& d) { WriteAheadLog::ContinuationAdmission a; d.A(a.anchor);a.last_sequence=d.N();return a; }
    static void BaselineOut(CEncoder& e, const PayloadSpool::ContinuationBaseline& s) { e.N(s.floor);e.N(s.generation);e.A(s.certificate);e.A(s.tip); }
    static auto BaselineIn(CDecoder& d) { PayloadSpool::ContinuationBaseline s; s.floor=d.N();s.generation=d.N();d.A(s.certificate);d.A(s.tip);return s; }
    std::vector<std::byte> Encode() const
    {
        CEncoder e; e.N(6);e.N(generation);
        e.A(authority.source_binding);e.A(authority.original_journal_identity);e.A(authority.witness_journal_identity);e.A(authority.scope_binding);
        HeadOut(e,authority.original_head);HeadOut(e,authority.witness_head);SeedOut(e,authority.original_seed);
        e.N(authority.witness_last_sequence);e.N(authority.witness_retained_first_sequence);e.N(authority.checkpoint_xid);
        e.A(authority.complete_publication_sha256);e.A(authority.planned_guard_sha256);
        e.A(endpoint.source_binding);e.S(endpoint.source_identity);e.S(endpoint.container_uuid);e.S(endpoint.volume_uuid);
        e.N(endpoint.container_bytes);e.N(endpoint.volume_object_id);e.N(endpoint.checkpoint_xid);e.N(endpoint.physical_nx_offset);
        e.A(endpoint.physical_nx_sha256);e.B(endpoint.physical_nx_bytes);
        SeedOut(e,predecessor_seed);e.A(predecessor_publication);e.N(predecessor_original.has_value());
        if(predecessor_original){AdmissionOut(e,*predecessor_original);AdmissionOut(e,*predecessor_witness);}
        AdmissionOut(e,original);AdmissionOut(e,witness);BaselineOut(e,spool);
        e.N(entries.size());
        for(const auto& v:entries){e.N(v.role);e.N(v.number);e.N(v.stamp.bytes);e.N(v.stamp.volume);e.N(v.stamp.file);e.A(v.stamp.hash);}
        for(const auto& c:candidates)e.B(c);
        e.N(7); e.N(authority.retained_authorizations.size());
        for (const auto& value : authority.retained_authorizations) {
            e.N(value.version); e.N(value.accepted); e.N(value.transaction); e.N(value.spent ? 1 : 0);
            e.A(value.body_sha256); e.A(value.intent_sha256); e.A(value.receipt_sha256);
            e.N(value.original_records.size()); for (const auto& row : value.original_records) e.A(row);
            e.N(value.witness_sequences.size()); for (auto sequence : value.witness_sequences) e.N(sequence);
        }
        return std::move(e.b);
    }
    void Decode(std::span<const std::byte> bytes)
    {
        CDecoder d{bytes}; if(d.N()!=6)throw std::runtime_error("ContinuationVersion");generation=d.N();
        d.A(authority.source_binding);d.A(authority.original_journal_identity);d.A(authority.witness_journal_identity);d.A(authority.scope_binding);
        authority.original_head=HeadIn(d);authority.witness_head=HeadIn(d);authority.original_seed=SeedIn(d);
        authority.witness_last_sequence=d.N();authority.witness_retained_first_sequence=d.N();authority.checkpoint_xid=d.N();
        d.A(authority.complete_publication_sha256);d.A(authority.planned_guard_sha256);
        d.A(endpoint.source_binding);endpoint.source_identity=d.S();endpoint.container_uuid=d.S();endpoint.volume_uuid=d.S();
        endpoint.container_bytes=d.N();endpoint.volume_object_id=d.N();endpoint.checkpoint_xid=d.N();endpoint.physical_nx_offset=d.N();
        d.A(endpoint.physical_nx_sha256);const auto nx=d.B(65536);endpoint.physical_nx_bytes.assign(nx.begin(),nx.end());
        predecessor_seed=SeedIn(d);d.A(predecessor_publication);const auto has=d.N();if(has>1)throw std::runtime_error("ContinuationPredecessor");
        if(has){predecessor_original=AdmissionIn(d);predecessor_witness=AdmissionIn(d);}
        original=AdmissionIn(d);witness=AdmissionIn(d);spool=BaselineIn(d);
        const auto count=d.N();if(count>2060)throw std::runtime_error("ContinuationRetirementLimit");
        std::set<std::pair<std::uint64_t,std::uint64_t>> seen;
        for(std::uint64_t n=0;n<count;++n){Entry v;v.role=d.N();v.number=d.N();v.stamp.bytes=d.N();v.stamp.volume=d.N();v.stamp.file=d.N();d.A(v.stamp.hash);
            if(v.role<1||v.role>8||!seen.emplace(v.role,v.number).second||(v.role!=4&&v.number)||(v.role==4&&(!v.number||v.number>2048)))throw std::runtime_error("ContinuationRetirementEntry");entries.push_back(v);}
        for(auto& c:candidates){const auto b=d.B(2u*1024u*1024u);c.assign(b.begin(),b.end());}
        if (!d.b.empty()) {
            if (d.N() != 7) throw std::runtime_error("ContinuationRetainedVersion");
            const auto count_retained = d.N();
            if (count_retained > 8) throw std::runtime_error("ContinuationRetainedLimit");
            std::uint64_t prior = 0; std::size_t bytes_retained = 0;
            for (std::uint64_t n = 0; n < count_retained; ++n) {
                Authority::RetainedAuthorization value;
                value.version=d.N(); value.accepted=d.N(); value.transaction=d.N(); const auto spent=d.N();
                if ((value.version!=4 && value.version!=6 && value.version!=8) || spent>1 ||
                    (!spent && value.version!=6 && value.version!=8) ||
                    !value.transaction || value.transaction==UINT64_MAX || value.accepted<=prior ||
                    value.accepted>(spent?authority.original_seed.last_sequence:authority.original_seed.cleanup_sequence))
                    throw std::runtime_error("ContinuationRetainedFields");
                value.spent=spent!=0; prior=value.accepted;
                d.A(value.body_sha256); d.A(value.intent_sha256); d.A(value.receipt_sha256);
                const auto rows=d.N();
                if (rows>256 || (value.spent ? rows!=0 : rows==0)) throw std::runtime_error("ContinuationRetainedRows");
                for (std::uint64_t r=0; r<rows; ++r) {
                    const auto encoded=d.B(16384); bytes_retained+=encoded.size();
                    if (bytes_retained>2u*1024u*1024u) throw std::runtime_error("ContinuationRetainedBytes");
                    value.original_records.emplace_back(reinterpret_cast<const std::uint8_t*>(encoded.data()),
                        reinterpret_cast<const std::uint8_t*>(encoded.data()+encoded.size()));
                }
                const auto sequences=d.N(); if (!sequences || sequences>512) throw std::runtime_error("ContinuationRetainedWitnessLimit");
                std::uint64_t previous=0;
                for (std::uint64_t r=0; r<sequences; ++r) {
                    const auto sequence=d.N();
                    if (sequence<=previous || sequence>authority.witness_last_sequence) throw std::runtime_error("ContinuationRetainedWitnessOrder");
                    value.witness_sequences.push_back(sequence); previous=sequence;
                }
                authority.retained_authorizations.push_back(std::move(value));
            }
        }
        if(!d.b.empty()||!generation||generation>4095||spool.floor!=authority.original_seed.cleanup_sequence||
            spool.generation!=generation||authority.original_seed.accepted_sequence!=spool.floor||
            authority.original_seed.durable_sequence!=spool.floor||!spool.floor||original.last_sequence!=authority.original_seed.last_sequence||
            witness.last_sequence+1!=authority.witness_retained_first_sequence)throw std::runtime_error("ContinuationCertificateFields");
    }
    static journal::JournalRecordContext Context(const WriteAheadLog::Options& o, std::span<const std::byte> nonce,
        std::uint64_t bytes, std::uint64_t chunk, const Digest& previous, std::uint32_t purpose = 0x4a4306u)
    {
        CEncoder e;e.S("apfs-journal-continuation-certificate-v6");e.A(o.protected_persistence->source_binding);
        e.A(o.protected_persistence->journal_identity);const auto p=o.path.wstring(),k=o.protected_persistence->key_directory.wstring();
        e.A(p);e.A(k);e.S(o.volume_identity);e.B(nonce);e.N(bytes);e.A(previous);
        Digest hash{};if(!CHash(e.b,hash))throw std::runtime_error("ContinuationContextHash");
        journal::JournalRecordContext c;c.purpose=purpose;c.chunk=chunk;std::memcpy(c.operation.data(),hash.data(),32);return c;
    }
    static bool Protect(const WriteAheadLog::Options& o, journal::ProtectedJournalEpoch& epoch,
        std::span<const std::byte> plain, std::vector<std::byte>& cipher)
    {
        if(plain.empty()||plain.size()>continuation_limit)return false;
        cipher.assign(64,std::byte{});std::memcpy(cipher.data(),"APFSCNT6",8);CPut(cipher,8,plain.size());
        CPut(cipher,16,(plain.size()+4095)/4096);
        if(BCryptGenRandom(nullptr,reinterpret_cast<PUCHAR>(cipher.data()+24),32,BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)return false;
        const std::array<std::byte,32> nonce=[&]{std::array<std::byte,32> n;std::copy_n(cipher.begin()+24,32,n.begin());return n;}();
        Digest previous{};
        for(std::size_t at=0,n=0;at<plain.size();++n){const auto b=plain.subspan(at,(std::min)(std::size_t{4096},plain.size()-at));
            auto frame=epoch.Seal(Context(o,nonce,plain.size(),n,previous),b);if(!frame||!CHash(frame.bytes.Bytes(),previous))return false;
            cipher.insert(cipher.end(),frame.bytes.Bytes().begin(),frame.bytes.Bytes().end());at+=b.size();}
        return true;
    }
    static bool Unprotect(const WriteAheadLog::Options& o,std::span<const std::byte> cipher,std::vector<std::byte>& plain)
    {
        SecureZeroMemory(plain.data(),plain.size());plain.clear();if(cipher.size()<64||std::memcmp(cipher.data(),"APFSCNT6",8)||CGet(cipher,56))return false;
        const auto bytes=CGet(cipher,8),count=CGet(cipher,16);
        if(!bytes||bytes>continuation_limit||count!=(bytes+4095)/4096||cipher.size()!=64+bytes+count*80)return false;
        auto pass=journal::ProtectedJournalReadPass::Acquire(o.protected_persistence->key_directory.wstring(),o.protected_persistence->source_binding);
        if(!pass)return false;Digest previous{};std::size_t at=64;
        for(std::uint64_t n=0;n<count;++n){const auto size=static_cast<std::size_t>((std::min)(std::uint64_t{4096},bytes-plain.size()));
            const auto frame=cipher.subspan(at,size+80);auto opened=pass.reader->Open(Context(o,cipher.subspan(24,32),bytes,n,previous),frame);
            if(!opened||opened.bytes.Size()!=size||!CHash(frame,previous)){SecureZeroMemory(plain.data(),plain.size());plain.clear();return false;}
            plain.insert(plain.end(),opened.bytes.Bytes().begin(),opened.bytes.Bytes().end());at+=frame.size();}
        return plain.size()==bytes;
    }
    bool Pin(const std::filesystem::path& p)
    {
        if(!CPath(p))return false;
        for(auto parent=p.parent_path();!parent.empty();parent=parent.parent_path()){
            auto f=std::make_unique<CFile>();f->path=parent;f->h=CreateFileW(parent.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ,nullptr,
                OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
            if(!CExact(f->h,parent,true))return false;directories.push_back(std::move(f));
            if(parent==parent.root_path())break;
        }return true;
    }
    static bool Hook(const StageHook& hook,std::string_view stage,std::string& error)
    { if(hook&&!hook(stage)){error="ContinuationInjectedCut:"+std::string(stage);return false;}return true; }
    static std::filesystem::path ReceiptPath(const PayloadSpool& s, std::uint64_t number)
    {
        const auto serial=(number+1)/2;const auto digits=std::to_wstring(serial);
        return s.options_.root/(L"payload-spool.cleanup."+std::wstring(16-digits.size(),L'0')+digits+(number%2?L".intent":L".commit"));
    }
    static const wchar_t* Control(std::uint64_t role)
    {
        switch(role){case 5:return L".jcont.certificate";case 6:return L".jcont.done";
            case 7:return L".jcont.retire";case 8:return L".jcont.ready";default:throw std::runtime_error("ContinuationControlRole");}
    }
    std::filesystem::path EntryPath(const Entry& e,const WriteAheadLog::Options& o,const WriteAheadLog& w,const PayloadSpool& s,bool archive) const
    {
        if(e.role==1)return archive?Side(o.path,L".jcont.old"):o.path;
        if(e.role==2)return archive?Side(w.options_.path,L".jcont.old"):w.options_.path;
        if(e.role==3)return archive?Side(s.index_file_,L".jcont.old"):s.index_file_;
        if(e.role==4)return ReceiptPath(s,e.number);
        const auto canonical=Side(o.path,Control(e.role));
        return archive?Side(canonical,L".previous"):canonical;
    }
    CFile* Find(const std::filesystem::path& p) const
    {
        for(const auto& f:retained)if(CompareStringOrdinal(f->path.c_str(),-1,p.c_str(),-1,TRUE)==CSTR_EQUAL)return f.get();
        return nullptr;
    }
    CFile* Open(const std::filesystem::path& p)
    {
        if(auto* f=Find(p))return f;
        auto f=std::make_unique<CFile>();if(!f->Open(p))return nullptr;
        auto* ptr=f.get();retained.push_back(std::move(f));return ptr;
    }
    bool AddEntry(std::uint64_t role,std::uint64_t number,CFile& f)
    {
        Entry e;e.role=role;e.number=number;
        if(!CStampFile(f,e.stamp)||!FlushFileBuffers(f.h))return false;
        entries.push_back(e);return true;
    }
    bool AddReceiptEntry(const PayloadSpool::ContinuationLease& lease,std::size_t n)
    {
        if(!lease.lock.owns_lock()||n>=lease.receipts.size()||n>=2048)return false;
        const auto& [path,handle]=lease.receipts[n];
        auto file=std::make_unique<CFile>();file->path=path;file->h=reinterpret_cast<HANDLE>(handle);file->owns=false;
        Entry e;e.role=4;e.number=n+1;
        // The private held lease carries reconciliation's exact flushed,
        // write-denying handle. Hash it again without another durability fence.
        if(!CStampFile(*file,e.stamp))return false;
        entries.push_back(e);retained.push_back(std::move(file));return true;
    }
    CFile* Old(const Entry& e,const WriteAheadLog::Options& o,const WriteAheadLog& w,const PayloadSpool& s)
    {
        for(const auto archive:{true,false}){
            const auto p=EntryPath(e,o,w,s,archive);
            if(CAbsent(p))continue;
            auto* f=Open(p);CStamp actual;
            if(f&&CStampFile(*f,actual)&&actual==e.stamp)return f;
            if(e.role>=4)return nullptr;
        }return nullptr;
    }
    bool Bindings(const WriteAheadLog::Options& o,const WriteAheadLog& w,const PayloadSpool& s,std::string& error)
    {
        const auto same=[](const auto& a,const auto& b){return CompareStringOrdinal(a.c_str(),-1,b.c_str(),-1,TRUE)==CSTR_EQUAL;};
        if(!o.protected_persistence||!w.options_.protected_persistence||!s.options_.protected_persistence||
            authority.source_binding!=o.protected_persistence->source_binding||authority.source_binding!=w.options_.protected_persistence->source_binding||
            authority.source_binding!=s.options_.protected_binding||authority.original_journal_identity!=o.protected_persistence->journal_identity||
            authority.witness_journal_identity!=w.options_.protected_persistence->journal_identity||w.options_.volume_identity.empty()||
            o.volume_identity!=s.options_.volume_identity||same(o.path,w.options_.path)||same(o.protected_persistence->key_directory,w.options_.protected_persistence->key_directory)||
            same(o.protected_persistence->key_directory,s.options_.protected_key_directory)||same(w.options_.protected_persistence->key_directory,s.options_.protected_key_directory)){
            error="ContinuationConfiguredAuthorityMismatch";return false;
        }
        for(const auto& p:{o.path,w.options_.path,s.index_file_,s.spool_file_,s.protected_marker_file_})if(!Pin(p)){error="ContinuationUnsafePath";return false;}
        for(const auto& base:{o.path,w.options_.path,s.index_file_})
            for(const auto* suffix:{L".jcont.next",L".jcont.old"})
                if(!CPath(Side(base,suffix))){error="ContinuationGeneratedPathUnsafe";return false;}
        if(!CPath(Side(o.path,L".jcont.pending"))){error="ContinuationGeneratedPathUnsafe";return false;}
        for(std::uint64_t role=5;role<=8;++role){
            const auto path=Side(o.path,Control(role));
            if(!CPath(path)||!CPath(Side(path,L".previous"))){error="ContinuationGeneratedPathUnsafe";return false;}
        }
        return true;
    }
    bool Namespace(const WriteAheadLog::Options& o,const WriteAheadLog& w,const PayloadSpool& s) const
    {
        for(const auto& base:{o.path,w.options_.path,s.index_file_}){
            std::set<std::wstring> allowed;
            for(const auto* suffix:{L".jcont.next",L".jcont.old"})allowed.insert(Side(base,suffix).filename().wstring());
            if(base==o.path){allowed.insert(Side(base,L".jcont.pending").filename().wstring());
                for(std::uint64_t role=5;role<=8;++role){const auto p=Side(base,Control(role));allowed.insert(p.filename().wstring());allowed.insert(Side(p,L".previous").filename().wstring());}}
            std::size_t count=0;
            for(const auto& entry:std::filesystem::directory_iterator(base.parent_path())){
                const auto name=entry.path().filename().wstring(),prefix=base.filename().wstring()+L".jcont";
                if(name.size()<prefix.size()||CompareStringOrdinal(name.data(),static_cast<int>(prefix.size()),prefix.data(),static_cast<int>(prefix.size()),TRUE)!=CSTR_EQUAL)continue;
                if(++count>16||!allowed.contains(name)||!CPath(entry.path()))return false;
                const auto attrs=GetFileAttributesW(entry.path().c_str());if(attrs==INVALID_FILE_ATTRIBUTES||(attrs&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)))return false;
            }
        }return true;
    }
    bool Receipt(const WriteAheadLog::Options& o,unsigned phase,bool create,std::string& error)
    {
        const auto suffix=phase==1?L".jcont.done":phase==2?L".jcont.retire":L".jcont.ready";
        const auto path=Side(o.path,suffix);auto context=Context(o,std::as_bytes(std::span(spool.certificate)),generation,0,{},0x4a4310u+phase);
        if(!CAbsent(path)){
            auto* f=Open(path);std::vector<std::byte> bytes;if(!f||!f->Read(bytes,144))return false;
            auto plain=journal::ProtectedJournalEpoch::Open(o.protected_persistence->key_directory.wstring(),o.protected_persistence->source_binding,context,bytes);
            return plain&&plain.bytes.Size()==64&&!std::memcmp(plain.bytes.Bytes().data(),certificate_hash.data(),32)&&
                CGet(plain.bytes.Bytes(),32)==generation&&CGet(plain.bytes.Bytes(),40)==phase&&
                !CGet(plain.bytes.Bytes(),48)&&!CGet(plain.bytes.Bytes(),56)&&FlushFileBuffers(f->h);
        }
        if(!create)return false;
        auto epoch=journal::ProtectedJournalEpoch::AcquireWriter(o.protected_persistence->key_directory.wstring(),o.protected_persistence->source_binding);
        if(!epoch){error="ContinuationReceiptKeyUnavailable";return false;}
        std::array<std::byte,64> plain{};std::memcpy(plain.data(),certificate_hash.data(),32);CPut(plain,32,generation);CPut(plain,40,phase);
        auto frame=epoch.epoch->Seal(context,plain);if(!frame)return false;
        auto f=std::make_unique<CFile>();if(!f->Open(path,true))return false;
        auto* ptr=f.get();retained.push_back(std::move(f));
        if(!ptr->Write(frame.bytes.Bytes()))return false;
        std::vector<std::byte> checked;return ptr->Read(checked,144)&&std::equal(checked.begin(),checked.end(),frame.bytes.Bytes().begin(),frame.bytes.Bytes().end());
    }
    bool ReceiptKeysAvailable(const WriteAheadLog::Options& options)
    {
        std::lock_guard lock(control_read_mutex);
        auto pass=journal::ProtectedJournalReadPass::Acquire(options.protected_persistence->key_directory.wstring(),
            options.protected_persistence->source_binding);
        if(!pass)return false;
        for(unsigned phase=1;phase<=3;++phase){
            const auto* file=Find(Side(options.path,phase==1?L".jcont.done":phase==2?L".jcont.retire":L".jcont.ready"));
            std::vector<std::byte> bytes;
            if(!file||!const_cast<CFile*>(file)->Read(bytes,144))return false;
            const auto context=Context(options,std::as_bytes(std::span(spool.certificate)),generation,0,{},0x4a4310u+phase);
            auto plain=pass.reader->Open(context,bytes);
            if(!plain||plain.bytes.Size()!=64||std::memcmp(plain.bytes.Bytes().data(),certificate_hash.data(),32)||
                CGet(plain.bytes.Bytes(),32)!=generation||CGet(plain.bytes.Bytes(),40)!=phase||
                CGet(plain.bytes.Bytes(),48)||CGet(plain.bytes.Bytes(),56))return false;
        }
        return true;
    }
    bool Evidence(TransactionManager& tm,WriteAheadLog& w,PayloadSpool& s,bool completed,RecoveryEvidence& evidence,std::string& error)
    {
        evidence={};evidence.certificate_authority=authority;evidence.certified_endpoint=endpoint;
        evidence.generation=generation;evidence.certificate_sha256=certificate_hash;evidence.pending=!completed;evidence.admission_only=completed;
        evidence.active_original_seed=completed?authority.original_seed:predecessor_seed;
        if(!completed&&predecessor_seed.last_sequence)evidence.certificate_authority.complete_publication_sha256=predecessor_publication;
        const auto load=[&](unsigned role,WriteAheadLog& wal,const auto& admission,auto& records,auto& head){
            CFile* f=nullptr;
            if(completed)f=Open(wal.options_.path);
            else {const auto it=std::find_if(entries.begin(),entries.end(),[&](const auto& e){return e.role==role;});if(it!=entries.end())f=Old(*it,tm.journal_.options_,w,s);}
            std::vector<std::byte> bytes;if(!f||!f->Read(bytes,wal.options_.max_bytes)||!FlushFileBuffers(f->h))return false;
            records=wal.DecodeContinuationEvidence({reinterpret_cast<const std::uint8_t*>(bytes.data()),bytes.size()},admission,head);
            return records.status==WriteAheadLog::ReadStatus::Ok&&!records.recovered_torn_tail;
        };
        const std::optional<WriteAheadLog::ContinuationAdmission> oa=completed?std::optional{original}:predecessor_original;
        const std::optional<WriteAheadLog::ContinuationAdmission> wa=completed?std::optional{witness}:predecessor_witness;
        if(!load(1,tm.journal_,oa,evidence.original,evidence.original_head)||!load(2,w,wa,evidence.witness,evidence.witness_head)||
            (!completed&&(evidence.original_head!=authority.original_head||evidence.witness_head!=authority.witness_head))){error="ContinuationHistoryEvidenceDamaged";return false;}
        return true;
    }
    bool Candidate(const std::filesystem::path& p,std::span<const std::byte> bytes,
        std::size_t ordinal,std::string& error,const StageHook& hook,const ProgressHook& progress)
    {
        auto* f=Find(p);
        if(!f){auto file=std::make_unique<CFile>();if(!file->OpenCandidate(p,CAbsent(p)))return false;
            f=file.get();retained.push_back(std::move(file));}
        std::vector<std::byte> current;
        if(!f||!f->Read(current,bytes.size())||!std::equal(current.begin(),current.end(),bytes.begin())){error="ContinuationCandidateNotOwned";return false;}
        // Resume only an exact prefix of the encrypted candidate committed by
        // the authenticated intent. Buffer candidate writes, then unconditionally
        // flush and verify before the old canonical name can be changed.
        if(current.size()!=bytes.size()&&!f->WriteBytes(bytes))return false;
        if(!Hook(hook,"continuation-before-candidate-flush-"+std::to_string(ordinal),error)||
            !FlushFileBuffers(f->h)||!f->Read(current,bytes.size())||
            !std::equal(current.begin(),current.end(),bytes.begin(),bytes.end()))return false;
        return Completed(DurableBoundary::CandidateFlushed,static_cast<std::uint8_t>(ordinal),progress,error);
    }
    bool Promote(const WriteAheadLog::Options& o,WriteAheadLog& w,PayloadSpool& s,std::string& error,const StageHook& hook,
        const ProgressHook& progress)
    {
        const std::array<std::filesystem::path,3> bases{o.path,w.options_.path,s.index_file_};
        for(std::size_t n=0;n<3;++n){
            const auto& base=bases[n];const auto it=std::find_if(entries.begin(),entries.end(),[&](const auto& e){return e.role==n+1;});
            if(it==entries.end())return false;
            auto* old=Old(*it,o,w,s);if(!old)return false;
            const auto archived=Side(base,L".jcont.old"),next=Side(base,L".jcont.next");
            bool candidate_ready=false;
            if(old->path==base){
                if(!Candidate(next,candidates[n],n,error,hook,progress)||!Hook(hook,"continuation-after-candidate-"+std::to_string(n),error)||
                    !old->Rename(archived)||!Completed(DurableBoundary::OldRenamed,static_cast<std::uint8_t>(n),progress,error)||
                    !Hook(hook,"continuation-after-old-rename-"+std::to_string(n),error))return false;
                candidate_ready=true;
            }
            if(CAbsent(base)){
                if(!candidate_ready&&!Candidate(next,candidates[n],n,error,hook,progress))return false;
                auto* f=Find(next);if(!f||!f->Rename(base))return false;
            }else{
                auto* f=Open(base);std::vector<std::byte> bytes;if(!f||!f->Read(bytes,candidates[n].size())||bytes!=candidates[n])return false;
                // A prior rename may have completed before its flush failed.
                // Re-establish that exact canonical barrier before any receipt.
                if(!CAbsent(next)||!FlushFileBuffers(f->h))return false;
            }
            if(!Completed(DurableBoundary::NewRenamed,static_cast<std::uint8_t>(n),progress,error)||
                !Hook(hook,"continuation-after-new-rename-"+std::to_string(n),error))return false;
        }return true;
    }
    bool Retire(const WriteAheadLog::Options& o,WriteAheadLog& w,PayloadSpool& s,
        const PayloadSpool::ContinuationLease& lease,std::string& error,const StageHook& hook)
    {
        for(const auto& e:entries){
            const auto p=EntryPath(e,o,w,s,true);
            if(CAbsent(p))continue;
            auto* f=Open(p);CStamp actual;
            const bool held_receipt=f&&!f->owns&&e.role==4&&lease.lock.owns_lock()&&e.number&&e.number<=lease.receipts.size()&&
                lease.receipts[static_cast<std::size_t>(e.number-1)].first==p&&
                lease.receipts[static_cast<std::size_t>(e.number-1)].second==reinterpret_cast<std::uintptr_t>(f->h);
            if(!f||!CStampFile(*f,actual)||actual!=e.stamp||(!held_receipt&&!FlushFileBuffers(f->h))){error="ContinuationRetirementIdentityMismatch";return false;}
            FILE_DISPOSITION_INFO info{TRUE};
            if(!SetFileInformationByHandle(f->h,FileDispositionInfo,&info,sizeof(info)))return false;
            if(f->owns){CloseHandle(std::exchange(f->h,INVALID_HANDLE_VALUE));}
            // Borrowed receipt handles remain under the spool lease. Release
            // that exact authenticated chain only after marking every entry.
            if(!Hook(hook,"continuation-after-retirement-"+std::to_string(e.role)+"-"+std::to_string(e.number),error))return false;
        }
        return true;
    }
    bool RotateControls(const WriteAheadLog::Options& o,WriteAheadLog& w,PayloadSpool& s,std::string& error,const StageHook& hook,
        const ProgressHook& progress)
    {
        for(const auto& e:entries)if(e.role>=5){
            auto* old=Old(e,o,w,s);if(!old)return false;
            const auto archive=EntryPath(e,o,w,s,true);
            if(old->path!=archive&&(!old->Rename(archive)||
                !Completed(DurableBoundary::ControlRenamed,static_cast<std::uint8_t>(e.role),progress,error)||
                !Hook(hook,"continuation-after-control-rename-"+std::to_string(e.role),error)))return false;
        }
        const auto pending=Side(o.path,L".jcont.pending"),canonical=Side(o.path,L".jcont.certificate");
        if(!CAbsent(pending)){
            auto* f=Open(pending);CStamp stamp;
            if(!f||!CStampFile(*f,stamp)||stamp.hash!=certificate_hash||!f->Rename(canonical))return false;
        }else{
            auto* f=Open(canonical);CStamp stamp;if(!f||!CStampFile(*f,stamp)||stamp.hash!=certificate_hash||!FlushFileBuffers(f->h))return false;
        }
        return Completed(DurableBoundary::CertificatePromoted,0,progress,error)&&
            Hook(hook,"continuation-after-certificate-promotion",error);
    }
    void CloseActive(const WriteAheadLog::Options& o,const WriteAheadLog& w,const PayloadSpool& s)
    {
        (void)w; (void)s;
        std::erase_if(retained,[&](const auto& f){
            for(std::uint64_t role=5;role<=8;++role)if(f->path==Side(o.path,Control(role)))return false;
            return true;
        });
    }
    bool Finish(std::shared_ptr<Operation> self,TransactionManager& tm,PayloadSpool& s,WriteAheadLog& w,
        Endpoint& held,const RecoveryAuthorizer& authorize,bool completed,PayloadSpool::ContinuationLease& lease,
        std::string& error,const StageHook& hook,const ProgressHook& progress)
    {
        const auto options=tm.journal_.options_;
        if(!Namespace(options,w,s)||!held.revalidate_||!held.revalidate_(error))return false;
        RecoveryEvidence evidence;CRecordsWipe ow{evidence.original.records},ww{evidence.witness.records};Authority checked;
        if(!Evidence(tm,w,s,completed,evidence,error)||!authorize(evidence,checked,error)||!checked.flush_and_recheck||
            !checked.flush_and_recheck(error)||checked.scope_binding!=authority.scope_binding||
            (!completed&&(checked.original_head!=authority.original_head||checked.witness_head!=authority.witness_head||
             checked.complete_publication_sha256!=authority.complete_publication_sha256||checked.planned_guard_sha256!=authority.planned_guard_sha256))){
            if(error.empty())error="ContinuationRecoveryAuthorityMismatch";return false;
        }
        // Evidence() flushed the exact pinned old/active streams. Revalidation
        // and Journal correspondence precede the first namespace mutation.
        if(!Completed(DurableBoundary::RecoveryBarrier,0,progress,error)||
            !Hook(hook,"continuation-after-recovery-barrier",error))return false;
        if(!completed){
            if(!RotateControls(options,w,s,error,hook,progress)||!Promote(options,w,s,error,hook,progress)||
                !Receipt(options,1,true,error)||!Completed(DurableBoundary::CompletionReceipt,0,progress,error)||
                !Hook(hook,"continuation-after-completion-receipt",error))return false;
        }
        const auto ready=Side(options.path,L".jcont.ready");
        if(CAbsent(ready)){
            if(!Receipt(options,2,true,error)||!Completed(DurableBoundary::RetirementReceipt,0,progress,error)||
                !Hook(hook,"continuation-after-retirement-receipt",error)||
                !Retire(options,w,s,lease,error,hook))return false;
            s.ReleaseContinuationReceipts(lease);
            if(!Receipt(options,3,true,error)||!Completed(DurableBoundary::ReadyReceipt,0,progress,error)||
                !Hook(hook,"continuation-after-ready-receipt",error))return false;
        }else if(!Receipt(options,2,false,error)||!Receipt(options,3,false,error))return false;
        for(const auto& base:{options.path,w.options_.path,s.index_file_})
            if(!CAbsent(Side(base,L".jcont.old"))||!CAbsent(Side(base,L".jcont.next")))return false;
        for(std::uint64_t role=5;role<=8;++role)if(!CAbsent(Side(Side(options.path,Control(role)),L".previous")))return false;
        original.immutable_siblings.clear();witness.immutable_siblings.clear();
        for(std::uint64_t role=5;role<=8;++role)original.immutable_siblings.push_back(Side(options.path,Control(role)).filename().wstring());
        CloseActive(options,w,s);
        const std::weak_ptr<Operation> weak=self;
        const auto counterpart=[weak,options,root=options.path,other=w.options_.path,index=s.index_file_]{
            const auto owner=weak.lock();if(!owner)return false;
            for(const auto& base:{root,other,index}){
                std::set<std::wstring> expected;
                if(base==root)for(std::uint64_t role=5;role<=8;++role){
                    const auto p=Side(root,Control(role));const auto* f=owner->Find(p);
                    if(!f||!CExact(f->h,p))return false;expected.insert(p.filename().wstring());
                }
                std::size_t count=0;
                for(const auto& entry:std::filesystem::directory_iterator(base.parent_path())){
                    const auto name=entry.path().filename().wstring(),prefix=base.filename().wstring()+L".jcont";
                    if(name.size()<prefix.size()||CompareStringOrdinal(name.data(),static_cast<int>(prefix.size()),prefix.data(),static_cast<int>(prefix.size()),TRUE)!=CSTR_EQUAL)continue;
                    if(!expected.contains(name))return false;++count;
                }if(count!=expected.size())return false;
            }return owner->ReceiptKeysAvailable(options);
        };
        original.validate_authority=counterpart;witness.validate_authority=counterpart;
        authority.flush_and_recheck={};
        if(!tm.journal_.InstallContinuationAdmission(original,self)||!w.InstallContinuationAdmission(witness,self)){
            error="ContinuationActiveHistoryAdmissionFailed";return false;
        }
        tm.continuation_seed_=TransactionManager::ContinuationSeed{authority.original_seed.last_sequence,
            authority.original_seed.next_transaction_id,{authority.original_seed.accepted_sequence,authority.original_seed.durable_sequence,authority.original_seed.cleanup_sequence}};
        auto active=tm.journal_.ReadAllWithExclusiveWriterLease();CRecordsWipe aw{active.records};
        if(active.status!=WriteAheadLog::ReadStatus::Ok||active.recovered_torn_tail){
            error="ContinuationActiveOriginalSemanticsInvalid";return false;
        }
        const bool closed=tm.SeedIdsFromJournalRecords(active.records,tm.journal_.ExclusiveWriterLeaseGeneration());
        if(!closed&&(!completed||!tm.SeedAuthorizationPreparedPrefix(active.records,tm.journal_.ExclusiveWriterLeaseGeneration()))){
            error="ContinuationActiveOriginalSemanticsInvalid";return false;
        }
        auto baseline=spool;baseline.authority=self;
        if(!s.InstallContinuationSpool(lease,std::move(baseline),error))return false;
        lease.lock.unlock();
        // Journal's typed authorizer already matched the complete private
        // authorization to this suffix and held preimage. Keep TM invalid until
        // its durable abort/disposition finishes before the wrapper returns.
        if(!closed)return Hook(hook,"continuation-after-admission",error);
        WriteAheadLog::ProtectedHistoryHead head;
        if(!tm.CaptureProtectedOriginalHistoryHead(head,error)||
            tm.ReconcileProtectedPayloadSpool(s,head,error)!=PayloadSpool::ProtectedMaintenanceResult::Succeeded)return false;
        return Hook(hook,"continuation-after-admission",error);
    }
};
