namespace apfsaccess::rw
{
bool WriteAheadLog::MaterializeAbsentProtectedStartupJournal(const std::function<bool()>& census_current) const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    try
    {
        if (!options_.protected_persistence || !preserve_startup_evidence_ ||
            startup_journal_state_ != StartupJournalState::Absent || !startup_evidence_valid_ ||
            !census_current || !census_current() || append_handle_ || !writer_lease_handle_ ||
            !startup_writer_lease_generation_ || writer_lease_generation_ != startup_writer_lease_generation_ ||
            writer_lease_name_ != WriterLeaseName(options_.volume_identity) || !EnsureProtectedState() ||
            protected_state_->verified || protected_state_->poisoned || protected_state_->epoch ||
            !PathIsAbsent(options_.path) || !ProtectedMaintenanceAbsent()) return false;
        WIN32_FIND_DATAW entry{};
        const auto search = FindFirstFileW((options_.protected_persistence->key_directory / L"*").c_str(), &entry);
        if (search == INVALID_HANDLE_VALUE) {
            if (GetLastError() != ERROR_FILE_NOT_FOUND) return false;
        } else {
            bool empty = true;
            do { if (wcscmp(entry.cFileName, L".") && wcscmp(entry.cFileName, L"..")) { empty = false; break; } }
            while (FindNextFileW(search, &entry));
            const auto find_error = GetLastError(); FindClose(search);
            if (!empty || find_error != ERROR_NO_MORE_FILES) return false;
        }
        startup_evidence_valid_ = false;
        // Claim the absent leaf before creating key material. An unexpected
        // existing original is preserved, including a zero-length foreign leaf.
        const auto handle = OpenWalFile(options_.path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr);
        if (handle == INVALID_HANDLE_VALUE) return false;
        append_handle_ = handle; ++append_handle_open_count_;
        append_handle_size_ = 0; append_handle_size_known_ = true;
        const auto fail = [&] {
            protected_state_->poisoned = true;
            startup_evidence_valid_ = false;
            (void)CloseAppendHandle();
            return false;
        };
        std::uint64_t size = 0;
        if (!ProtectedExactHandle(handle, options_.path, false) || !TryGetPhysicalFileSize(handle, size) || size ||
            !census_current() || !ProtectedMaintenanceAbsent()) return fail();
        auto epoch = jc::ProtectedJournalEpoch::AcquireWriter(options_.protected_persistence->key_directory.wstring(),
            options_.protected_persistence->source_binding);
        if (!epoch) return fail();
        protected_state_->epoch = std::move(epoch.epoch);
        ProtectedPosition start; start.offset = kProtectedWalHeader.size();
        jc::JournalRecordContext context{};
        if (!ProtectedContext(options_, start, context)) return fail();
        auto anchor = protected_state_->epoch->Seal(context,
            std::as_bytes(std::span(kProtectedAnchor.data(), kProtectedAnchor.size())));
        if (!anchor) return fail();
        const auto bytes = anchor.bytes.Bytes();
        std::vector<std::uint8_t> encoded(kProtectedWalHeader.begin(), kProtectedWalHeader.end());
        encoded.insert(encoded.end(), reinterpret_cast<const std::uint8_t*>(bytes.data()),
            reinterpret_cast<const std::uint8_t*>(bytes.data() + bytes.size()));
        protected_state_->position = start; protected_state_->verified = true; protected_state_->write_pending = true;
        if (AppendEncoded(encoded) != EncodedAppendResult::Succeeded || !FlushAppendHandle() ||
            !ProtectedAdvance(protected_state_->position, bytes, 0) || !census_current() || !ProtectedMaintenanceAbsent())
            return fail();
        protected_state_->write_pending = false;
        startup_journal_state_ = StartupJournalState::Materialized;
        startup_evidence_valid_ = true;
        return ValidatedAppendLeaseGeneration(true) == writer_lease_generation_;
    }
    catch (...)
    {
        startup_evidence_valid_ = false;
        if (protected_state_) protected_state_->poisoned = true;
        return false;
    }
}
}
