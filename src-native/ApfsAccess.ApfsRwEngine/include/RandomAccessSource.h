#pragma once

// Portable read-only random-access byte source behind the APFS catalog parser.
// Adapters exist for in-memory fixtures, regular files, and Windows
// BlockDevice handles. No parsing lives here; see ApfsFormat.h.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace apfsaccess::catalog
{

// One caller-owned, single-threaded cumulative allowance for an entire walk.
// Failed reservations are sticky; retries must not silently reset the budget.
// Bytes are logical materialization bytes, not an allocator/peak-RSS meter.
class ApfsReadBudget final
{
public:
    ApfsReadBudget(std::uint64_t reads, std::uint64_t read_bytes,
        std::uint64_t records, std::uint64_t record_bytes)
        : reads_left_(reads), read_bytes_left_(read_bytes),
          records_left_(records), record_bytes_left_(record_bytes) {}
    ApfsReadBudget(const ApfsReadBudget&) = delete;
    ApfsReadBudget& operator=(const ApfsReadBudget&) = delete;

    [[nodiscard]] bool Read(std::uint64_t bytes) noexcept
    {
        if (Failed()) return false;
        if (reads_left_ == 0 || bytes > read_bytes_left_)
            return Refuse("ApfsReadBudgetSourceLimit");
        --reads_left_;
        read_bytes_left_ -= bytes;
        return true;
    }
    [[nodiscard]] bool Materialize(std::uint64_t count, std::uint64_t bytes) noexcept
    {
        if (Failed()) return false;
        if (count > records_left_ || bytes > record_bytes_left_)
            return Refuse("ApfsReadBudgetRecordLimit");
        records_left_ -= count;
        record_bytes_left_ -= bytes;
        return true;
    }
    // reason must have static lifetime (all parser reasons are string literals).
    bool Refuse(const char* reason) noexcept
    {
        if (!failure_) failure_ = reason;
        return false;
    }
    [[nodiscard]] bool Failed() const noexcept { return failure_ != nullptr; }
    [[nodiscard]] const char* Failure() const noexcept { return failure_ ? failure_ : ""; }
private:
    std::uint64_t reads_left_, read_bytes_left_, records_left_, record_bytes_left_;
    const char* failure_ = nullptr;
};

class RandomAccessSource
{
public:
    virtual ~RandomAccessSource() = default;

    [[nodiscard]] virtual std::uint64_t SizeBytes() const = 0;

    // Views forward this exact object. A source advertising a budget must
    // reserve each read before allocating or dispatching it to its backing IO.
    [[nodiscard]] virtual std::shared_ptr<ApfsReadBudget> ReadBudget() const { return {}; }

    // Reads exactly `size` bytes at `offset`. Returns false (leaving
    // `out_bytes` empty) on any short read, overflow, or I/O failure.
    [[nodiscard]] virtual bool Read(
        std::uint64_t offset,
        std::size_t size,
        std::vector<std::byte>& out_bytes) const = 0;
};

// Attach before any catalog/checkpoint/retention traversal. Nested views with
// the same budget charge once; replacing an existing budget fails closed.
class BudgetedRandomAccessSource final : public RandomAccessSource
{
public:
    BudgetedRandomAccessSource(const RandomAccessSource& inner,
        std::shared_ptr<ApfsReadBudget> budget)
        : inner_(inner), budget_(budget ? std::move(budget) : inner.ReadBudget()) {}
    std::uint64_t SizeBytes() const override { return inner_.SizeBytes(); }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return budget_; }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
    {
        out.clear();
        const auto inherited = inner_.ReadBudget();
        if (inherited && inherited != budget_)
            return budget_->Refuse("ApfsReadBudgetIdentityMismatch");
        if (budget_ && (budget_->Failed() || (!inherited && !budget_->Read(size)))) return false;
        if (!inner_.Read(offset, size, out) || out.size() != size)
        {
            out.clear();
            return false;
        }
        return true;
    }
private:
    const RandomAccessSource& inner_;
    std::shared_ptr<ApfsReadBudget> budget_;
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

// Opens one read-only handle and holds it for its lifetime: every Read goes
// through the held handle (no per-read reopens), and the size/mtime captured
// at open can be re-checked afterwards with VerifyUnchanged. Single-threaded
// use only. Residual risk (documented): a same-size same-mtime content swap
// is not detectable portably.
class HeldFileSource final : public RandomAccessSource
{
public:
    explicit HeldFileSource(const std::string& path)
        : path_(path)
        , size_bytes_(0)
        , open_(false)
    {
        stream_.open(path_, std::ios::in | std::ios::binary);
        if (!stream_.is_open())
        {
            return;
        }
        std::error_code code;
        const auto observed_size = std::filesystem::file_size(path_, code);
        const auto observed_time = std::filesystem::last_write_time(path_, code);
        if (code)
        {
            stream_.close();
            return;
        }
        size_bytes_ = static_cast<std::uint64_t>(observed_size);
        write_time_ = observed_time;
        open_ = true;
    }

    [[nodiscard]] bool IsOpen() const noexcept
    {
        return open_ && stream_.is_open();
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
        if (!IsOpen())
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
        std::vector<char> staging(size);
        stream_.clear();
        stream_.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        if (!stream_.good())
        {
            return false;
        }
        stream_.read(staging.data(), static_cast<std::streamsize>(size));
        if (static_cast<std::size_t>(stream_.gcount()) != size)
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

    // Re-checks size and mtime against the open-time capture. Fails closed
    // on any difference or stat error.
    [[nodiscard]] bool VerifyUnchanged(std::string& out_detail) const
    {
        out_detail.clear();
        if (!IsOpen())
        {
            out_detail = "held source is not open";
            return false;
        }
        std::error_code code;
        const auto current_size = std::filesystem::file_size(path_, code);
        const auto current_time = std::filesystem::last_write_time(path_, code);
        if (code)
        {
            out_detail = "held source cannot be re-stated";
            return false;
        }
        if (static_cast<std::uint64_t>(current_size) != size_bytes_ ||
            current_time != write_time_)
        {
            out_detail = "held source changed during observation";
            return false;
        }
        return true;
    }

private:
    std::string path_;
    mutable std::ifstream stream_;
    std::uint64_t size_bytes_;
    std::filesystem::file_time_type write_time_{};
    bool open_;
};

// Presents [base_offset, base_offset + view_size) of an inner source as a
// zero-based source. Lets store-relative parser math stay absolute-free.
class OffsetRandomAccessSource final : public RandomAccessSource
{
public:
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override
    {
        return inner_ ? inner_->ReadBudget() : nullptr;
    }
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
        if (const auto budget = ReadBudget(); budget && budget->Failed()) return false;
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
