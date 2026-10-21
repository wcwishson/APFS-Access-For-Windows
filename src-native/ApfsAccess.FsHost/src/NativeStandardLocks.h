#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace apfsaccess::fshost::standard_mount
{
enum class LockAdmission { Allowed, Invalid, Conflict, NotLocked, Exhausted };
class RangeLocks
{
    struct Lock
    {
        std::uint64_t owner, inode, offset, length;
        std::wstring stream;
        bool exclusive;
    };
    std::vector<Lock> locks_;
    static bool Fits(std::uint64_t offset, std::uint64_t length) noexcept
    { return offset <= INT64_MAX && length && length <= std::uint64_t(INT64_MAX) - offset; }
    static bool Overlap(const Lock& lock, std::uint64_t offset, std::uint64_t length) noexcept
    { return lock.offset < offset + length && offset < lock.offset + lock.length; }
public:
    LockAdmission Acquire(std::uint64_t owner, std::uint64_t inode, std::wstring_view stream,
        std::uint64_t offset, std::uint64_t length, bool exclusive)
    {
        if (!owner || !inode || !Fits(offset, length)) return LockAdmission::Invalid;
        for (const auto& lock : locks_)
            if (lock.inode == inode && lock.stream == stream && Overlap(lock, offset, length) &&
                (exclusive || lock.exclusive && lock.owner != owner)) return LockAdmission::Conflict;
        if (locks_.size() >= 8192) return LockAdmission::Exhausted;
        locks_.push_back({owner, inode, offset, length, std::wstring(stream), exclusive});
        return LockAdmission::Allowed;
    }
    LockAdmission Release(std::uint64_t owner, std::uint64_t offset, std::uint64_t length) noexcept
    {
        if (!owner || !Fits(offset, length)) return LockAdmission::Invalid;
        const auto found = std::find_if(locks_.begin(), locks_.end(), [&](const auto& lock) {
            return lock.owner == owner && lock.offset == offset && lock.length == length;
        });
        if (found == locks_.end()) return LockAdmission::NotLocked;
        locks_.erase(found); return LockAdmission::Allowed;
    }
    void Cleanup(std::uint64_t owner) noexcept
    { std::erase_if(locks_, [&](const auto& lock) { return lock.owner == owner; }); }
    bool AllowsIo(std::uint64_t owner, std::uint64_t inode, std::wstring_view stream,
        std::uint64_t offset, std::uint64_t length, bool write) const noexcept
    {
        if (!length) return offset <= INT64_MAX;
        if (!owner || !inode || !Fits(offset, length)) return false;
        for (const auto& lock : locks_)
            if (lock.inode == inode && lock.stream == stream && Overlap(lock, offset, length) &&
                (write ? !lock.exclusive || lock.owner != owner : lock.exclusive && lock.owner != owner)) return false;
        return true;
    }
};
}
