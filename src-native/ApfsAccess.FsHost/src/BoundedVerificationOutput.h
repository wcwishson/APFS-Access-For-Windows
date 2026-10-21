#pragma once

#include "RandomAccessSource.h"
#include <functional>
#include <ostream>
#include <streambuf>
#include <string>

// Counts without materializing, then appends into a separately reserved string.
// Every write shares the operation's sticky allowance and cooperative deadline.
class BoundedVerificationOutput final : public std::streambuf
{
public:
    BoundedVerificationOutput(std::size_t cap,
        const std::shared_ptr<apfsaccess::catalog::ApfsReadBudget>& budget,
        const std::function<bool()>& within_deadline, std::string* output = nullptr)
        : cap_(cap), budget_(budget), within_deadline_(within_deadline), output_(output) {}
    std::size_t Size() const { return size_; }
    bool Check()
    {
        if (!budget_ || budget_->Failed()) return false;
        if (!within_deadline_ || !within_deadline_()) return budget_->Refuse("LiveVerificationTimeLimit");
        return true;
    }
protected:
    std::streamsize xsputn(const char* bytes, std::streamsize length) override
    {
        if (length < 0 || !Check()) return 0;
        const auto count = static_cast<std::size_t>(length);
        if (count > cap_ - size_) { budget_->Refuse("VerificationResponseLimit"); return 0; }
        if (output_) output_->append(bytes, count);
        size_ += count;
        return length;
    }
    int_type overflow(int_type c) override
    {
        if (traits_type::eq_int_type(c, traits_type::eof())) return traits_type::not_eof(c);
        const auto byte = traits_type::to_char_type(c);
        return xsputn(&byte, 1) == 1 ? c : traits_type::eof();
    }
private:
    std::size_t cap_, size_ = 0;
    std::shared_ptr<apfsaccess::catalog::ApfsReadBudget> budget_;
    const std::function<bool()>& within_deadline_;
    std::string* output_;
};
