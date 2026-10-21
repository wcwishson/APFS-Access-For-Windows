#pragma once

namespace backup_image_mount {
struct Options {
    bool enabled = false;
    std::wstring volume_uuid, source_sha256, file_identity, journal_root;
    std::uint64_t checkpoint_xid = 0;
};
}
