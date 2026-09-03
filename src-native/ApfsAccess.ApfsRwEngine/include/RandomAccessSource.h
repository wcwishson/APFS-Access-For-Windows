#pragma once

// Portable read-only random-access byte source behind the APFS catalog parser.
// Adapters exist for in-memory fixtures, regular files, and Windows
// BlockDevice handles. No parsing lives here; see ApfsFormat.h.

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

namespace apfsaccess::catalog
{

class RandomAccessSource
{
public:
    virtual ~RandomAccessSource() = default;

    [[nodiscard]] virtual std::uint64_t SizeBytes() const = 0;

    // Reads exactly `size` bytes at `offset`. Returns false (leaving
    // `out_bytes` empty) on any short read, overflow, or I/O failure.
    [[nodiscard]] virtual bool Read(
        std::uint64_t offset,
        std::size_t size,
        std::vector<std::byte>& out_bytes) const = 0;
};

class VectorRandomAccessSource final : public RandomAccessSource
{
public:
    explicit VectorRandomAccessSource(std::vector<std::byte> bytes)
        : bytes_(std::move(bytes))
    {
    }

    [[nodiscard]] std::uint64_t SizeBytes() const override
    {
        return static_cast<std::uint64_t>(bytes_.size());
    }

    [[nodiscard]] bool Read(
        std::uint64_t offset,
        std::size_t size,
        std::vector<std::byte>& out_bytes) const override
    {
        out_bytes.clear();
        if (size == 0)
        {
            return true;
        }
        if (offset > static_cast<std::uint64_t>(bytes_.size()) ||
            size > static_cast<std::uint64_t>(bytes_.size()) - offset)
        {
            return false;
        }
        const auto begin = bytes_.begin() +
            static_cast<std::vector<std::byte>::difference_type>(offset);
        out_bytes.assign(begin, begin + static_cast<std::vector<std::byte>::difference_type>(size));
        return true;
    }

private:
    std::vector<std::byte> bytes_;
};

class FileRandomAccessSource final : public RandomAccessSource
{public:
    // Opens `path` read-only. Use IsOpen() to check construction success.
    // Every Read opens its own handle, so concurrent readers are safe.
    explicit FileRandomAccessSource(std::string path)
        : path_(std::move(path))
        , size_bytes_(0)
        , open_(false)
    {
        std::ifstream probe(path_, std::ios::in | std::ios::binary | std::ios::ate);
        if (!probe.is_open())
        {
            return;
        }
        const auto end = probe.tellg();
        if (end < 0)
        {
            return;
        }
        size_bytes_ = static_cast<std::uint64_t>(end);
        open_ = true;
    }

    [[nodiscard]] bool IsOpen() const noexcept
    {
        return open_;
    }

    [[nodiscard]] std::uint64_t SizeBytes() const override
    {
        return size_bytes_;
    }

    [[nodiscard]] bool Read(
        std::uint64_t offset,
        std::size_t size,
        std::vector<std::byte>& out_bytes) const override
    {
        out_bytes.clear();
        if (!open_)
        {
            return false;
        }
        if (size == 0)
        {
            return true;
        }
        if (offset >= size_bytes_ || size > size_bytes_ - offset)
        {
            return false;
        }
        std::ifstream stream(path_, std::ios::in | std::ios::binary);
        if (!stream.is_open())
        {
            return false;
        }
        std::vector<char> staging(size);
        stream.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        if (!stream.good())
        {
            return false;
        }
        stream.read(staging.data(), static_cast<std::streamsize>(size));
        if (static_cast<std::size_t>(stream.gcount()) != size)
        {
            return false;
        }
        out_bytes.resize(size);
        for (std::size_t index = 0; index < size; ++index)
        {
            out_bytes[index] = static_cast<std::byte>(staging[index]);
        }
        return true;
    }

private:
    std::string path_;
    std::uint64_t size_bytes_;
    bool open_;
};

// Presents [base_offset, base_offset + view_size) of an inner source as a
// zero-based source. Lets store-relative parser math stay absolute-free.
class OffsetRandomAccessSource final : public RandomAccessSource
{
public:
    OffsetRandomAccessSource(
        const RandomAccessSource* inner, std::uint64_t base_offset, std::uint64_t view_size)
        : inner_(inner)
        , base_offset_(base_offset)
        , view_size_(view_size)
    {
    }

    [[nodiscard]] std::uint64_t SizeBytes() const override
    {
        return view_size_;
    }

    [[nodiscard]] bool Read(
        std::uint64_t offset,
        std::size_t size,
        std::vector<std::byte>& out_bytes) const override
    {
        out_bytes.clear();
        if (inner_ == nullptr)
        {
            return false;
        }
        if (size == 0)
        {
            return offset <= view_size_bytes();
        }
        if (offset >= view_size_bytes() || size > view_size_bytes() - offset)
        {
            return false;
        }
        if (base_offset_ > 0xFFFFFFFFFFFFFFFFull - offset)
        {
            return false;
        }
        return inner_->Read(base_offset_ + offset, size, out_bytes) &&
            out_bytes.size() == size;
    }

private:
    [[nodiscard]] std::uint64_t view_size_bytes() const noexcept
    {
        return view_size_;
    }

    const RandomAccessSource* inner_;
    std::uint64_t base_offset_;
    std::uint64_t view_size_;
};

} // namespace apfsaccess::catalog
