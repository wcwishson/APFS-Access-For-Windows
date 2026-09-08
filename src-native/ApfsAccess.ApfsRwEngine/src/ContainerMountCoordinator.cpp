// One safe RW owner per APFS container: single raw lease, one container
// identity, serialized commits, shared extent ledger, independent sessions.

#include "ContainerMountCoordinator.h"

#include "ApfsContainerCatalog.h"
#include "BlockDevice.h"
#include "CheckpointDelta.h"
#include "ExtentAllocator.h"
#include "MetadataStore.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <sstream>
#include <thread>
#include <tuple>
#include <utility>

namespace apfsaccess::catalog
{
namespace
{

namespace fs = std::filesystem;
using apfsaccess::rw::BlockDevice;
using apfsaccess::rw::MetadataStore;

std::wstring WidenUtf8(const std::string& text)
{
#if defined(_WIN32)
    if (text.empty())
    {
        return std::wstring();
    }
    const int needed = ::MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(),
        static_cast<int>(text.size()), nullptr, 0);
    if (needed <= 0)
    {
        return std::wstring();
    }
    std::wstring wide(static_cast<std::size_t>(needed), L'\0');
    if (::MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(),
            static_cast<int>(text.size()), wide.data(), needed) != needed)
    {
        return std::wstring();
    }
    return wide;
#else
    std::mbstate_t state{};
    const char* src = text.c_str();
    const std::size_t needed =
        std::mbsrtowcs(nullptr, &src, 0, &state);
    if (needed == static_cast<std::size_t>(-1))
    {
        return std::wstring();
    }
    std::wstring wide(needed, L'\0');
    src = text.c_str();
    state = std::mbstate_t{};
    if (std::mbsrtowcs(wide.data(), &src, needed, &state) ==
        static_cast<std::size_t>(-1))
    {
        return std::wstring();
    }
    return wide;
#endif
}

std::string NarrowLossy(const std::wstring& text)
{
    std::string narrow;
    narrow.reserve(text.size());
    for (wchar_t ch : text)
    {
        narrow.push_back(
            (ch >= 0 && ch < 0x80) ? static_cast<char>(ch) : '?');
    }
    return narrow;
}

std::string LowerHex(std::string text)
{
    for (char& ch : text)
    {
        if (ch >= 'A' && ch <= 'F')
        {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
    }
    return text;
}

std::string NormalizeWindowsMountKey(std::string text)
{
    for (char& ch : text)
    {
        if (ch == '/')
        {
            ch = '\\';
        }
        else if (ch >= 'A' && ch <= 'Z')
        {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
    }
    while (text.size() > 3 && text.back() == '\\')
    {
        text.pop_back();
    }
    return text;
}

bool IsHexLen(const std::string& text, std::size_t want)
{
    if (text.size() != want)
    {
        return false;
    }
    for (char ch : text)
    {
        const bool hex = (ch >= '0' && ch <= '9') ||
            (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
        if (!hex)
        {
            return false;
        }
    }
    return true;
}

bool IsHex32(const std::string& text)
{
    return IsHexLen(text, 32);
}

bool IsHex64(const std::string& text)
{
    return IsHexLen(text, 64);
}

// Minimal private SHA-256 (FIPS 180-4) so the engine library gains no new
// link dependency. Cross-checked by tests against Sha256Portable.
class Sha256Self
{
public:
    Sha256Self() { Reset(); }

    void Reset()
    {
        state_ = {0x6a09e667ULL, 0xbb67ae85ULL, 0x3c6ef372ULL,
            0xa54ff53aULL, 0x510e527fULL, 0x9b05688cULL,
            0x1f83d9abULL, 0x5be0cd19ULL};
        total_ = 0;
        buffered_ = 0;
    }

    void Update(const void* data, std::size_t size)
    {
        const auto* bytes = static_cast<const unsigned char*>(data);
        total_ += size;
        while (size > 0)
        {
            const std::size_t room = 64 - buffered_;
            const std::size_t take = size < room ? size : room;
            std::memcpy(block_.data() + buffered_, bytes, take);
            bytes += take;
            size -= take;
            buffered_ += take;
            if (buffered_ == 64)
            {
                Compress();
                buffered_ = 0;
            }
        }
    }

    void Update(const std::string& text) { Update(text.data(), text.size()); }

    std::string FinalHex()
    {
        const std::uint64_t bit_length = total_ * 8ULL;
        unsigned char pad = 0x80;
        Update(&pad, 1);
        unsigned char zero = 0x00;
        while (buffered_ != 56)
        {
            Update(&zero, 1);
        }
        unsigned char length_bytes[8]{};
        for (int i = 0; i < 8; ++i)
        {
            length_bytes[i] = static_cast<unsigned char>(
                (bit_length >> (56 - 8 * i)) & 0xFFULL);
        }
        Update(length_bytes, 8);
        std::string hex;
        hex.reserve(64);
        static constexpr char kDigits[] = "0123456789abcdef";
        for (std::uint32_t word : state_)
        {
            for (int i = 7; i >= 0; --i)
            {
                hex.push_back(kDigits[(word >> (4 * i)) & 0xFULL]);
            }
        }
        return hex;
    }

private:
    void Compress()
    {
        static constexpr std::uint32_t kTable[64] = {0x428a2f98, 0x71374491,
            0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1,
            0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
            0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
            0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354,
            0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585,
            0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee,
            0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb,
            0xbef9a3f7, 0xc67178f2};
        std::uint32_t w[64]{};
        for (int i = 0; i < 16; ++i)
        {
            w[i] = (static_cast<std::uint32_t>(block_[4 * i]) << 24) |
                (static_cast<std::uint32_t>(block_[4 * i + 1]) << 16) |
                (static_cast<std::uint32_t>(block_[4 * i + 2]) << 8) |
                static_cast<std::uint32_t>(block_[4 * i + 3]);
        }
        for (int i = 16; i < 64; ++i)
        {
            const std::uint32_t s0 = (w[i - 15] >> 7 | w[i - 15] << 25) ^
                (w[i - 15] >> 18 | w[i - 15] << 14) ^ (w[i - 15] >> 3);
            const std::uint32_t s1 = (w[i - 2] >> 17 | w[i - 2] << 15) ^
                (w[i - 2] >> 19 | w[i - 2] << 13) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        std::uint32_t a = state_[0];
        std::uint32_t b = state_[1];
        std::uint32_t c = state_[2];
        std::uint32_t d = state_[3];
        std::uint32_t e = state_[4];
        std::uint32_t f = state_[5];
        std::uint32_t g = state_[6];
        std::uint32_t h = state_[7];
        for (int i = 0; i < 64; ++i)
        {
            const std::uint32_t s1 =
                (e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25 | e << 7);
            const std::uint32_t ch = (e & f) ^ (~e & g);
            const std::uint32_t t1 = h + s1 + ch + kTable[i] + w[i];
            const std::uint32_t s0 =
                (a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22 | a << 10);
            const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t t2 = s0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }

    std::array<std::uint32_t, 8> state_{};
    std::array<unsigned char, 64> block_{};
    std::uint64_t total_ = 0;
    std::size_t buffered_ = 0;
};

// Minimal JSON value model for the fixed manifest schema.
struct JsonValue
{
    enum class Type
    {
        Null,
        Bool,
        Number,
        String,
        Array,
        Object,
    };
    Type type = Type::Null;
    bool boolean = false;
    std::string text; // Number literal or String payload (UTF-8)
    std::vector<JsonValue> items;
    std::map<std::string, JsonValue> fields;
};

class JsonParser
{
public:
    explicit JsonParser(const std::string& text) : text_(text) {}

    bool Parse(JsonValue& out_value, std::string& out_error)
    {
        SkipSpace();
        if (!ParseValue(out_value, out_error))
        {
            return false;
        }
        SkipSpace();
        if (pos_ != text_.size())
        {
            out_error = "trailing content";
            return false;
        }
        return true;
    }

private:
    void SkipSpace()
    {
        while (pos_ < text_.size())
        {
            const char ch = text_[pos_];
            if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r')
            {
                ++pos_;
            }
            else
            {
                break;
            }
        }
    }

    bool Expect(char want, std::string& out_error)
    {
        if (pos_ >= text_.size() || text_[pos_] != want)
        {
            out_error = "expected delimiter";
            return false;
        }
        ++pos_;
        return true;
    }

    bool ParseValue(JsonValue& out_value, std::string& out_error)
    {
        if (pos_ >= text_.size())
        {
            out_error = "unexpected end";
            return false;
        }
        const char ch = text_[pos_];
        if (ch == '{')
        {
            return ParseObject(out_value, out_error);
        }
        if (ch == '[')
        {
            return ParseArray(out_value, out_error);
        }
        if (ch == '"')
        {
            out_value.type = JsonValue::Type::String;
            return ParseString(out_value.text, out_error);
        }
        if (ch == 't' || ch == 'f')
        {
            return ParseBool(out_value, out_error);
        }
        if (ch == 'n')
        {
            return ParseNull(out_value, out_error);
        }
        if (ch == '-' || (ch >= '0' && ch <= '9'))
        {
            return ParseNumber(out_value, out_error);
        }
        out_error = "unexpected character";
        return false;
    }

    bool ParseObject(JsonValue& out_value, std::string& out_error)
    {
        out_value.type = JsonValue::Type::Object;
        ++pos_;
        SkipSpace();
        if (pos_ < text_.size() && text_[pos_] == '}')
        {
            ++pos_;
            return true;
        }
        while (true)
        {
            SkipSpace();
            if (pos_ >= text_.size() || text_[pos_] != '"')
            {
                out_error = "object key must be a string";
                return false;
            }
            std::string key;
            if (!ParseString(key, out_error))
            {
                return false;
            }
            SkipSpace();
            if (!Expect(':', out_error))
            {
                return false;
            }
            SkipSpace();
            JsonValue member;
            if (!ParseValue(member, out_error))
            {
                return false;
            }
            const auto inserted = out_value.fields.emplace(
                std::move(key), std::move(member));
            if (!inserted.second)
            {
                out_error = "duplicate object key";
                return false;
            }
            SkipSpace();
            if (pos_ >= text_.size())
            {
                out_error = "unterminated object";
                return false;
            }
            if (text_[pos_] == ',')
            {
                ++pos_;
                continue;
            }
            if (text_[pos_] == '}')
            {
                ++pos_;
                return true;
            }
            out_error = "expected ',' or '}'";
            return false;
        }
    }

    bool ParseArray(JsonValue& out_value, std::string& out_error)
    {
        out_value.type = JsonValue::Type::Array;
        ++pos_;
        SkipSpace();
        if (pos_ < text_.size() && text_[pos_] == ']')
        {
            ++pos_;
            return true;
        }
        while (true)
        {
            SkipSpace();
            JsonValue item;
            if (!ParseValue(item, out_error))
            {
                return false;
            }
            out_value.items.push_back(std::move(item));
            SkipSpace();
            if (pos_ >= text_.size())
            {
                out_error = "unterminated array";
                return false;
            }
            if (text_[pos_] == ',')
            {
                ++pos_;
                continue;
            }
            if (text_[pos_] == ']')
            {
                ++pos_;
                return true;
            }
            out_error = "expected ',' or ']'";
            return false;
        }
    }

    void AppendUtf8(std::string& out, unsigned int code)
    {
        if (code < 0x80)
        {
            out.push_back(static_cast<char>(code));
        }
        else if (code < 0x800)
        {
            out.push_back(static_cast<char>(0xC0 | (code >> 6)));
            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        }
        else
        {
            out.push_back(static_cast<char>(0xE0 | (code >> 12)));
            out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        }
    }

    bool ParseHex4(unsigned int& out_word, std::string& out_error)
    {
        if (pos_ + 4 > text_.size())
        {
            out_error = "bad unicode escape";
            return false;
        }
        unsigned int word = 0;
        for (int i = 0; i < 4; ++i)
        {
            const char ch = text_[pos_ + i];
            word *= 16;
            if (ch >= '0' && ch <= '9')
            {
                word += static_cast<unsigned int>(ch - '0');
            }
            else if (ch >= 'a' && ch <= 'f')
            {
                word += static_cast<unsigned int>(ch - 'a' + 10);
            }
            else if (ch >= 'A' && ch <= 'F')
            {
                word += static_cast<unsigned int>(ch - 'A' + 10);
            }
            else
            {
                out_error = "bad unicode escape";
                return false;
            }
        }
        pos_ += 4;
        out_word = word;
        return true;
    }

    bool ParseString(std::string& out_text, std::string& out_error)
    {
        ++pos_;
        out_text.clear();
        while (pos_ < text_.size())
        {
            const char ch = text_[pos_++];
            if (ch == '"')
            {
                return true;
            }
            if (ch == '\\')
            {
                if (pos_ >= text_.size())
                {
                    break;
                }
                const char esc = text_[pos_++];
                switch (esc)
                {
                case '"':
                    out_text.push_back('"');
                    break;
                case '\\':
                    out_text.push_back('\\');
                    break;
                case '/':
                    out_text.push_back('/');
                    break;
                case 'b':
                    out_text.push_back('\b');
                    break;
                case 'f':
                    out_text.push_back('\f');
                    break;
                case 'n':
                    out_text.push_back('\n');
                    break;
                case 'r':
                    out_text.push_back('\r');
                    break;
                case 't':
                    out_text.push_back('\t');
                    break;
                case 'u': {
                    unsigned int word = 0;
                    if (!ParseHex4(word, out_error))
                    {
                        return false;
                    }
                    if (word >= 0xD800 && word <= 0xDBFF &&
                        pos_ + 2 <= text_.size() && text_[pos_] == '\\' &&
                        text_[pos_ + 1] == 'u')
                    {
                        pos_ += 2;
                        unsigned int low = 0;
                        if (!ParseHex4(low, out_error))
                        {
                            return false;
                        }
                        if (low < 0xDC00 || low > 0xDFFF)
                        {
                            out_error = "bad surrogate pair";
                            return false;
                        }
                        const unsigned int full = 0x10000 +
                            ((word - 0xD800) << 10) + (low - 0xDC00);
                        out_text.push_back(static_cast<char>(
                            0xF0 | (full >> 18)));
                        out_text.push_back(static_cast<char>(
                            0x80 | ((full >> 12) & 0x3F)));
                        out_text.push_back(static_cast<char>(
                            0x80 | ((full >> 6) & 0x3F)));
                        out_text.push_back(static_cast<char>(
                            0x80 | (full & 0x3F)));
                    }
                    else if (word >= 0xD800 && word <= 0xDFFF)
                    {
                        out_error = "lone surrogate";
                        return false;
                    }
                    else
                    {
                        AppendUtf8(out_text, word);
                    }
                    break;
                }
                default:
                    out_error = "bad escape";
                    return false;
                }
                continue;
            }
            if (static_cast<unsigned char>(ch) < 0x20)
            {
                out_error = "unescaped control character";
                return false;
            }
            out_text.push_back(ch);
        }
        out_error = "unterminated string";
        return false;
    }

    bool ParseBool(JsonValue& out_value, std::string& out_error)
    {
        if (text_.compare(pos_, 4, "true") == 0)
        {
            out_value.type = JsonValue::Type::Bool;
            out_value.boolean = true;
            pos_ += 4;
            return true;
        }
        if (text_.compare(pos_, 5, "false") == 0)
        {
            out_value.type = JsonValue::Type::Bool;
            out_value.boolean = false;
            pos_ += 5;
            return true;
        }
        out_error = "bad literal";
        return false;
    }

    bool ParseNull(JsonValue& out_value, std::string& out_error)
    {
        if (text_.compare(pos_, 4, "null") == 0)
        {
            out_value.type = JsonValue::Type::Null;
            pos_ += 4;
            return true;
        }
        out_error = "bad literal";
        return false;
    }

    bool ParseNumber(JsonValue& out_value, std::string& out_error)
    {
        const std::size_t start = pos_;
        if (pos_ < text_.size() && text_[pos_] == '-')
        {
            ++pos_;
        }
        bool digits = false;
        while (pos_ < text_.size() && text_[pos_] >= '0' &&
            text_[pos_] <= '9')
        {
            ++pos_;
            digits = true;
        }
        if (!digits)
        {
            out_error = "bad number";
            return false;
        }
        if (pos_ < text_.size() && text_[pos_] == '.')
        {
            ++pos_;
            bool frac = false;
            while (pos_ < text_.size() && text_[pos_] >= '0' &&
                text_[pos_] <= '9')
            {
                ++pos_;
                frac = true;
            }
            if (!frac)
            {
                out_error = "bad number";
                return false;
            }
        }
        if (pos_ < text_.size() && (text_[pos_] == 'e' || text_[pos_] == 'E'))
        {
            ++pos_;
            if (pos_ < text_.size() &&
                (text_[pos_] == '+' || text_[pos_] == '-'))
            {
                ++pos_;
            }
            bool exp = false;
            while (pos_ < text_.size() && text_[pos_] >= '0' &&
                text_[pos_] <= '9')
            {
                ++pos_;
                exp = true;
            }
            if (!exp)
            {
                out_error = "bad number";
                return false;
            }
        }
        out_value.type = JsonValue::Type::Number;
        out_value.text = text_.substr(start, pos_ - start);
        return true;
    }

    const std::string& text_;
    std::size_t pos_ = 0;
};

const JsonValue* FindField(
    const JsonValue& object, const char* name) noexcept
{
    if (object.type != JsonValue::Type::Object)
    {
        return nullptr;
    }
    const auto it = object.fields.find(name);
    return it == object.fields.end() ? nullptr : &it->second;
}

// Accepts a JSON number literal or a decimal string (managed evidence
// convention). Rejects negatives, fractions, and overflow.
bool ReadUint64(const JsonValue& value, std::uint64_t& out_number)
{
    if (value.type != JsonValue::Type::Number &&
        value.type != JsonValue::Type::String)
    {
        return false;
    }
    const std::string& text = value.text;
    if (text.empty())
    {
        return false;
    }
    std::uint64_t number = 0;
    for (char ch : text)
    {
        if (ch < '0' || ch > '9')
        {
            return false;
        }
        const auto digit = static_cast<std::uint64_t>(ch - '0');
        if (number > (UINT64_MAX - digit) / 10ULL)
        {
            return false;
        }
        number = number * 10ULL + digit;
    }
    out_number = number;
    return true;
}

bool ReadString(const JsonValue& value, std::string& out_text)
{
    if (value.type != JsonValue::Type::String)
    {
        return false;
    }
    out_text = value.text;
    return true;
}

bool ReadOptionalString(
    const JsonValue& object, const char* name, std::string& out_text)
{
    const JsonValue* field = FindField(object, name);
    if (field == nullptr || field->type == JsonValue::Type::Null)
    {
        out_text.clear();
        return true;
    }
    return ReadString(*field, out_text);
}

bool IsLinkOrReparsePoint(const fs::path& path, std::error_code& out_error)
{
    out_error.clear();
    const auto status = fs::symlink_status(path, out_error);
    if (out_error || fs::is_symlink(status))
    {
        return !out_error;
    }
#if defined(_WIN32)
    const DWORD attributes = ::GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        out_error = std::error_code(
            static_cast<int>(::GetLastError()), std::system_category());
        return false;
    }
    return (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
    return false;
#endif
}

bool ValidateManifestPath(const fs::path& path, std::string& out_error)
{
    std::error_code ec;
    if (IsLinkOrReparsePoint(path, ec))
    {
        out_error = "ManifestSymlinkRefused";
        return false;
    }
    if (ec)
    {
        out_error = "ManifestUnreachable: " + ec.message();
        return false;
    }

    fs::path ancestor = fs::absolute(path, ec).parent_path();
    if (ec || ancestor.empty())
    {
        out_error = "ManifestUnreachable: " +
            (ec ? ec.message() : std::string("missing parent"));
        return false;
    }
    for (std::size_t depth = 0; depth < 64; ++depth)
    {
        if (IsLinkOrReparsePoint(ancestor, ec))
        {
            out_error = "ManifestSymlinkedParentRefused";
            return false;
        }
        if (ec)
        {
            out_error = "ManifestUnreachable: " + ec.message();
            return false;
        }
        const fs::path parent = ancestor.parent_path();
        if (parent.empty() || parent == ancestor)
        {
            return true;
        }
        ancestor = parent;
    }
    out_error = "ManifestPathTooDeep";
    return false;
}

bool NormalizeRequiredCheckpointXids(
    const std::vector<std::uint64_t>& xids,
    std::uint64_t maximum_xid,
    std::vector<std::uint64_t>& out_xids,
    std::string& out_error)
{
    out_xids = xids;
    for (const std::uint64_t xid : out_xids)
    {
        if (xid == 0)
        {
            out_error = "RequiredCheckpointXidZero";
            return false;
        }
        if (xid > maximum_xid)
        {
            out_error = "RequiredCheckpointXidFuture: xid=" +
                std::to_string(xid) + " checkpoint=" +
                std::to_string(maximum_xid);
            return false;
        }
    }
    std::sort(out_xids.begin(), out_xids.end());
    if (std::adjacent_find(out_xids.begin(), out_xids.end()) != out_xids.end())
    {
        out_error = "RequiredCheckpointXidDuplicate";
        return false;
    }
    return true;
}

} // namespace

struct ContainerMountCoordinator::SessionState
{
    std::uint64_t volume_object_id = 0;
    std::string mount_point;
    std::string recovery_identity;
    bool requested_write = false;
    bool use_canonical_transaction = false;
    std::unique_ptr<MetadataStore> store;
};

struct ContainerMountCoordinator::ScopedCommitDiagnostics
{
    ContainerMountCoordinator& owner;
    std::uint64_t volume_object_id;
    const ContainerCommitResult& result;
    std::chrono::steady_clock::time_point started;
    std::chrono::steady_clock::time_point acquired;

    ~ScopedCommitDiagnostics()
    {
        const auto finished = std::chrono::steady_clock::now();
        const auto wait_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(acquired - started).count());
        const auto hold_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(finished - acquired).count());
        const auto record = [&](ContainerCommitDiagnostics& counters)
        {
            ++counters.commit_attempts;
            // Read only scalar members: return-value movement may have already
            // moved result.error before this scope is destroyed without NRVO.
            if (result.committed && result.commit_status_code ==
                static_cast<int>(MetadataStore::CommitStatus::Committed))
                ++counters.commit_successes;
            else if (result.committed && result.commit_status_code ==
                static_cast<int>(MetadataStore::CommitStatus::NothingToCommit))
                ++counters.commit_noops;
            else
                ++counters.commit_failures;
            counters.commit_wait_total_us += wait_us;
            counters.commit_hold_total_us += hold_us;
            counters.commit_total_us += wait_us + hold_us;
            counters.commit_max_us = std::max(counters.commit_max_us, wait_us + hold_us);
        };
        std::lock_guard<std::mutex> guard(owner.mutex_);
        record(owner.diagnostics_);
        if (auto* counters = owner.FindVolumeDiagnosticsNoLock(volume_object_id)) record(*counters);
    }
};

struct ContainerMountCoordinator::ScopedReloadDiagnostics
{
    ContainerMountCoordinator& owner;
    std::uint64_t volume_object_id;
    ReloadReason reason;
    std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now();
    bool succeeded = false;

    ~ScopedReloadDiagnostics()
    {
        const auto elapsed_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - started).count());
        const auto record = [&](ContainerCommitDiagnostics& counters)
        {
            ++counters.reload_attempts;
            if (!succeeded) ++counters.reload_failures;
            counters.reload_total_us += elapsed_us;
            counters.reload_max_us = std::max(counters.reload_max_us, elapsed_us);
            switch (reason)
            {
            case ReloadReason::BeforeCommit: ++counters.precommit_reload_attempts; break;
            case ReloadReason::Rollback: ++counters.rollback_reload_attempts; break;
            case ReloadReason::Recovery: ++counters.recovery_reload_attempts; break;
            }
        };
        std::lock_guard<std::mutex> guard(owner.mutex_);
        record(owner.diagnostics_);
        if (auto* counters = owner.FindVolumeDiagnosticsNoLock(volume_object_id)) record(*counters);
    }
};

bool ParseContainerManifest(
    const std::string& manifest_path,
    ContainerManifest& out_manifest,
    std::string& out_error)
{
    out_manifest = ContainerManifest{};
    out_error.clear();
    const fs::path path(manifest_path);
    if (!ValidateManifestPath(path, out_error))
    {
        return false;
    }
    std::error_code ec;
    const auto symlink_state = fs::symlink_status(path, ec);
    if (!fs::is_regular_file(symlink_state))
    {
        out_error = "ManifestNotRegularFile";
        return false;
    }
    constexpr std::uintmax_t kMaxManifestBytes = 1024u * 1024u;
    const auto manifest_bytes = fs::file_size(path, ec);
    if (ec)
    {
        out_error = "ManifestUnreachable: " + ec.message();
        return false;
    }
    if (manifest_bytes > kMaxManifestBytes)
    {
        out_error = "ManifestTooLarge";
        return false;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input)
    {
        out_error = "ManifestUnreadable";
        return false;
    }
    std::string document;
    document.reserve(static_cast<std::size_t>(manifest_bytes));
    std::array<char, 8192> chunk{};
    while (input)
    {
        input.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
        const auto read = input.gcount();
        if (read <= 0)
        {
            break;
        }
        if (document.size() > kMaxManifestBytes -
                static_cast<std::size_t>(read))
        {
            out_error = "ManifestTooLarge";
            return false;
        }
        document.append(chunk.data(), static_cast<std::size_t>(read));
    }
    if (input.bad())
    {
        out_error = "ManifestUnreadable";
        return false;
    }
    JsonValue root;
    std::string parse_error;
    JsonParser parser(document);
    if (!parser.Parse(root, parse_error))
    {
        out_error = "ManifestSchemaViolation: " + parse_error;
        return false;
    }
    const JsonValue* format = FindField(root, "format");
    const JsonValue* version = FindField(root, "version");
    const JsonValue* container = FindField(root, "containerUuid");
    const JsonValue* device = FindField(root, "device");
    const JsonValue* offset = FindField(root, "deviceOffsetBytes");
    const JsonValue* checksum = FindField(root, "manifestSha256");
    const JsonValue* volumes = FindField(root, "volumes");
    std::string format_text;
    std::uint64_t version_number = 0;
    std::string container_uuid;
    std::string device_text;
    std::uint64_t offset_bytes = 0;
    std::string checksum_text;
    if (format == nullptr || !ReadString(*format, format_text) ||
        format_text != "apfs-access-container-manifest")
    {
        out_error = "ManifestSchemaViolation: format";
        return false;
    }
    if (version == nullptr || !ReadUint64(*version, version_number) ||
        version_number != 1)
    {
        out_error = "ManifestSchemaViolation: version";
        return false;
    }
    if (container == nullptr || !ReadString(*container, container_uuid) ||
        !IsHex32(container_uuid))
    {
        out_error = "ManifestSchemaViolation: containerUuid";
        return false;
    }
    if (device == nullptr || !ReadString(*device, device_text) ||
        device_text.empty())
    {
        out_error = "ManifestSchemaViolation: device";
        return false;
    }
    if (offset == nullptr || !ReadUint64(*offset, offset_bytes))
    {
        out_error = "ManifestSchemaViolation: deviceOffsetBytes";
        return false;
    }
    if (checksum == nullptr || !ReadString(*checksum, checksum_text) ||
        !IsHex64(checksum_text))
    {
        out_error = "ManifestSchemaViolation: manifestSha256";
        return false;
    }
    if (volumes == nullptr || volumes->type != JsonValue::Type::Array ||
        volumes->items.empty())
    {
        out_error = "ManifestSchemaViolation: volumes";
        return false;
    }
    ContainerManifest manifest;
    manifest.container_uuid_hex = LowerHex(container_uuid);
    manifest.manifest_sha256 = LowerHex(checksum_text);
    manifest.device_path = device_text;
    manifest.device_offset_bytes = offset_bytes;
    for (const JsonValue& entry : volumes->items)
    {
        std::uint64_t oid = 0;
        std::string member_uuid;
        std::string name;
        std::string mount;
        std::string recovery;
        const JsonValue* oid_field = FindField(entry, "objectId");
        const JsonValue* member_field = FindField(entry, "containerUuid");
        const JsonValue* mount_field = FindField(entry, "mount");
        const JsonValue* write_field = FindField(entry, "requestedWrite");
        if (entry.type != JsonValue::Type::Object || oid_field == nullptr ||
            !ReadUint64(*oid_field, oid) || oid == 0 ||
            member_field == nullptr ||
            !ReadString(*member_field, member_uuid) ||
            LowerHex(member_uuid) != manifest.container_uuid_hex ||
            !ReadOptionalString(entry, "name", name) ||
            mount_field == nullptr || !ReadString(*mount_field, mount) ||
            mount.empty() || write_field == nullptr ||
            write_field->type != JsonValue::Type::Bool ||
            !ReadOptionalString(entry, "recoveryIdentity", recovery))
        {
            out_error = "ManifestSchemaViolation: volume entry";
            return false;
        }
        if (write_field->boolean && recovery.empty())
        {
            out_error = "ManifestWritableRecoveryIdentityMissing";
            return false;
        }
        const std::string mount_key = NormalizeWindowsMountKey(mount);
        for (const ManifestVolumeEntry& seen : manifest.volumes)
        {
            if (seen.object_id == oid)
            {
                out_error = "ManifestDuplicateVolume";
                return false;
            }
            if (NormalizeWindowsMountKey(seen.mount_point) == mount_key)
            {
                out_error = "ManifestDuplicateMount";
                return false;
            }
            // Recovery/journal/spool state is keyed per volume: sharing one
            // identity across volumes would corrupt crash recovery.
            if (!recovery.empty() && seen.recovery_identity == recovery)
            {
                out_error = "ManifestDuplicateRecoveryIdentity";
                return false;
            }
        }
        ManifestVolumeEntry volume{};
        volume.object_id = oid;
        volume.container_uuid_hex = manifest.container_uuid_hex;
        volume.name_utf8 = name;
        volume.mount_point = mount;
        volume.requested_write = write_field->boolean;
        volume.recovery_identity = recovery;
        manifest.volumes.push_back(std::move(volume));
    }
    // Section 7 checksum over the canonical serialization excluding itself.
    std::ostringstream canonical;
    canonical << "manifest-check-v1\n"
              << manifest.container_uuid_hex << "\n"
              << manifest.device_path << "\n"
              << manifest.device_offset_bytes << "\n";
    for (const ManifestVolumeEntry& volume : manifest.volumes)
    {
        canonical << volume.object_id << "\n"
                  << volume.container_uuid_hex << "\n"
                  << volume.name_utf8 << "\n"
                  << volume.mount_point << "\n"
                  << (volume.requested_write ? "W" : "R") << "\n"
                  << volume.recovery_identity << "\n";
    }
    Sha256Self sha;
    const std::string canonical_text = canonical.str();
    sha.Update(canonical_text.data(), canonical_text.size());
    if (sha.FinalHex() != LowerHex(checksum_text))
    {
        out_error = "ManifestChecksumMismatch";
        return false;
    }
    out_manifest = std::move(manifest);
    return true;
}

std::unique_ptr<ContainerMountCoordinator> ContainerMountCoordinator::Open(
    const std::string& device_path,
    std::uint64_t device_offset_bytes,
    std::string& out_error,
    CatalogLoadPolicy catalog_load_policy,
    bool require_writable_lease,
    bool require_checkpoint_census)
{
    out_error.clear();
    if (device_path.empty())
    {
        out_error = "ContainerDevicePathEmpty";
        return nullptr;
    }
    const std::wstring wide_path = WidenUtf8(device_path);
    if (wide_path.empty())
    {
        out_error = "ContainerDevicePathInvalid";
        return nullptr;
    }
    auto lease =
        std::make_shared<BlockDevice>(wide_path, device_offset_bytes);
    if (require_writable_lease && !lease->IsWritable())
    {
        out_error = "ContainerWritableLeaseUnavailable";
        return nullptr;
    }
    ApfsContainerCatalog catalog;
    std::wstring catalog_error;
    if (!ApfsContainerCatalog::TryLoadDevice(
            *lease, catalog, catalog_error, catalog_load_policy))
    {
        out_error = "ContainerCatalogLoadFailed: " + NarrowLossy(catalog_error);
        return nullptr;
    }
    if (catalog.Containers().size() != 1)
    {
        out_error = "ContainerCountNotOne";
        return nullptr;
    }
    auto coordinator = std::unique_ptr<ContainerMountCoordinator>(
        new ContainerMountCoordinator());
    coordinator->device_ = std::move(lease);
    coordinator->writable_lease_required_ = require_writable_lease;
    coordinator->catalog_load_policy_ = catalog_load_policy;
    coordinator->device_offset_bytes_ = device_offset_bytes;
    coordinator->container_uuid_hex_ =
        LowerHex(catalog.Containers()[0].container_uuid_hex);
    if (!IsHex32(coordinator->container_uuid_hex_))
    {
        out_error = "ContainerUuidInvalid";
        return nullptr;
    }
    coordinator->container_volume_oids_.reserve(
        catalog.Containers()[0].volumes.size());
    for (const auto& volume : catalog.Containers()[0].volumes)
    {
        if (volume.object_id != 0)
        {
            coordinator->container_volume_oids_.push_back(volume.object_id);
        }
    }
    std::sort(
        coordinator->container_volume_oids_.begin(),
        coordinator->container_volume_oids_.end());
    coordinator->container_volume_oids_.erase(
        std::unique(
            coordinator->container_volume_oids_.begin(),
            coordinator->container_volume_oids_.end()),
        coordinator->container_volume_oids_.end());
    if (coordinator->container_volume_oids_.empty())
    {
        out_error = "ContainerHasNoVolumes";
        return nullptr;
    }
    coordinator->require_checkpoint_census_ = require_checkpoint_census;
    coordinator->checkpoint_census_initialized_ = !require_checkpoint_census;
    coordinator->volume_checkpoint_pins_.reserve(
        coordinator->container_volume_oids_.size());
    coordinator->volume_diagnostics_.reserve(
        coordinator->container_volume_oids_.size());
    for (const std::uint64_t volume_object_id :
         coordinator->container_volume_oids_)
    {
        coordinator->volume_checkpoint_pins_.push_back(
            {volume_object_id, {}});
        coordinator->volume_diagnostics_.push_back({volume_object_id, {}});
    }
    coordinator->checkpoint_xid_.store(
        catalog.Containers()[0].checkpoint_xid, std::memory_order_relaxed);
#if defined(_WIN32)
    coordinator->owner_process_id_ =
        static_cast<std::uint64_t>(::GetCurrentProcessId());
#else
    coordinator->owner_process_id_ =
        static_cast<std::uint64_t>(::getpid());
#endif
    return coordinator;
}

ContainerMountCoordinator::~ContainerMountCoordinator() = default;

bool ContainerMountCoordinator::CheckpointCensusRequired() const noexcept
{
    return require_checkpoint_census_;
}

std::vector<VolumeCheckpointPins> ContainerMountCoordinator::CheckpointCensusSnapshot() const
{
    std::lock_guard<std::timed_mutex> commit_guard(commit_mutex_);
    return volume_checkpoint_pins_;
}

bool ContainerMountCoordinator::InitializeRequiredCheckpointCensus(
    const std::vector<VolumeCheckpointPins>& volume_pins,
    std::string& out_error)
{
    out_error.clear();
    std::lock_guard<std::timed_mutex> commit_guard(commit_mutex_);
    if (!require_checkpoint_census_)
    {
        out_error = "RequiredCheckpointCensusNotRequired";
        return false;
    }
    if (checkpoint_census_initialized_)
    {
        out_error = "RequiredCheckpointCensusAlreadyInitialized";
        return false;
    }

    std::vector<VolumeCheckpointPins> normalized;
    normalized.reserve(volume_pins.size());
    const std::uint64_t maximum_xid =
        checkpoint_xid_.load(std::memory_order_relaxed);
    for (const VolumeCheckpointPins& entry : volume_pins)
    {
        if (!std::binary_search(
                container_volume_oids_.begin(),
                container_volume_oids_.end(),
                entry.volume_object_id))
        {
            out_error = "RequiredCheckpointCensusVolumeUnknown: oid=" +
                std::to_string(entry.volume_object_id);
            return false;
        }
        std::vector<std::uint64_t> normalized_xids;
        if (!NormalizeRequiredCheckpointXids(
                entry.required_checkpoint_xids,
                maximum_xid,
                normalized_xids,
                out_error))
        {
            return false;
        }
        if (entry.unapplied_accepted_work && normalized_xids.empty())
        {
            out_error = "RequiredCheckpointUnappliedSourceMissing";
            return false;
        }
        normalized.push_back(
            {entry.volume_object_id, std::move(normalized_xids), entry.unapplied_accepted_work});
    }
    std::sort(
        normalized.begin(),
        normalized.end(),
        [](const VolumeCheckpointPins& left, const VolumeCheckpointPins& right)
        {
            return left.volume_object_id < right.volume_object_id;
        });
    if (std::adjacent_find(
            normalized.begin(),
            normalized.end(),
            [](const VolumeCheckpointPins& left, const VolumeCheckpointPins& right)
            {
                return left.volume_object_id == right.volume_object_id;
            }) != normalized.end())
    {
        out_error = "RequiredCheckpointCensusVolumeDuplicate";
        return false;
    }
    if (normalized.size() != container_volume_oids_.size())
    {
        out_error = "RequiredCheckpointCensusIncomplete: expected=" +
            std::to_string(container_volume_oids_.size()) + " actual=" +
            std::to_string(normalized.size());
        return false;
    }
    for (std::size_t index = 0; index < normalized.size(); ++index)
    {
        if (normalized[index].volume_object_id != container_volume_oids_[index])
        {
            out_error = "RequiredCheckpointCensusIncomplete: missing oid=" +
                std::to_string(container_volume_oids_[index]);
            return false;
        }
    }

    volume_checkpoint_pins_ = std::move(normalized);
    checkpoint_census_initialized_ = true;
    return true;
}

bool ContainerMountCoordinator::UpdateRequiredCheckpointXids(
    std::uint64_t volume_object_id,
    const std::vector<std::uint64_t>& required_checkpoint_xids,
    std::string& out_error,
    bool unapplied_accepted_work)
{
    out_error.clear();
    std::lock_guard<std::timed_mutex> commit_guard(commit_mutex_);
    if (require_checkpoint_census_ && !checkpoint_census_initialized_)
    {
        out_error = "RequiredCheckpointCensusIncomplete";
        return false;
    }
    VolumeCheckpointPins* pins =
        FindVolumeCheckpointPinsNoLock(volume_object_id);
    if (pins == nullptr)
    {
        out_error = "RequiredCheckpointVolumeUnknown: oid=" +
            std::to_string(volume_object_id);
        return false;
    }
    std::vector<std::uint64_t> normalized_xids;
    if (!NormalizeRequiredCheckpointXids(
            required_checkpoint_xids,
            checkpoint_xid_.load(std::memory_order_relaxed),
            normalized_xids,
            out_error))
    {
        return false;
    }
    if (unapplied_accepted_work && normalized_xids.empty())
    {
        out_error = "RequiredCheckpointUnappliedSourceMissing";
        return false;
    }
    pins->required_checkpoint_xids = std::move(normalized_xids);
    pins->unapplied_accepted_work = unapplied_accepted_work;
    return true;
}

bool ContainerMountCoordinator::MountVolume(
    const ContainerVolumeSession& session, std::string& out_error)
{
    out_error.clear();
    std::lock_guard<std::timed_mutex> commit_guard(commit_mutex_);
    std::lock_guard<std::mutex> guard(mutex_);
    if (draining_)
    {
        out_error = "ContainerDraining";
        return false;
    }
    if (session.volume_object_id == 0)
    {
        out_error = "VolumeOidInvalid";
        return false;
    }
    if (LowerHex(session.container_uuid_hex) != container_uuid_hex_)
    {
        out_error = "VolumeContainerMismatch";
        return false;
    }
    for (const auto& existing : sessions_)
    {
        if (existing->volume_object_id == session.volume_object_id)
        {
            out_error = "VolumeAlreadyMounted";
            return false;
        }
    }
    ApfsContainerCatalog catalog;
    std::wstring catalog_error;
    if (!ApfsContainerCatalog::TryLoadDevice(
            *device_, catalog, catalog_error, catalog_load_policy_))
    {
        out_error = "ContainerCatalogReloadFailed";
        return false;
    }
    catalog::ResolvedMountVolume resolved{};
    std::string resolve_error;
    if (!catalog.TryResolveVolume(
            container_uuid_hex_, session.volume_object_id, resolved,
            resolve_error))
    {
        out_error = "VolumeUnknownInContainer: " + resolve_error;
        return false;
    }
    MetadataStore::VolumeContext context = session.metadata_context;
    context.device_path = device_->Path();
    context.device_offset_bytes = device_offset_bytes_;
    context.volume_name = WidenUtf8(resolved.name_utf8);
    context.volume_object_id = resolved.object_id;
    context.incompatible_features = resolved.incompatible_features;
    context.shared_container_session = true;
    const auto slot_it = std::lower_bound(
        container_volume_oids_.begin(),
        container_volume_oids_.end(),
        resolved.object_id);
    if (slot_it == container_volume_oids_.end() ||
        *slot_it != resolved.object_id)
    {
        out_error = "VolumeSlotIdentityMissing";
        return false;
    }
    context.container_volume_slot_index = static_cast<std::size_t>(
        std::distance(container_volume_oids_.begin(), slot_it));
    context.container_volume_slot_count = container_volume_oids_.size();
    context.container_uuid_hex = container_uuid_hex_;
    context.volume_uuid_hex = LowerHex(resolved.volume_uuid_hex);
    auto store =
        std::make_unique<MetadataStore>(std::move(context), device_);
    if (!store->LoadContainerState())
    {
        out_error = "VolumeStateLoadFailed: " +
            NarrowLossy(store->RecoveryReason());
        return false;
    }
    if (session.use_canonical_transaction)
    {
        if (!store->LoadCanonicalState())
        {
            out_error = "VolumeCanonicalStateLoadFailed: " +
                NarrowLossy(store->RecoveryReason());
            return false;
        }
    }
    else if (!store->LoadVolumeState())
    {
        out_error = "VolumeStateLoadFailed: " +
            NarrowLossy(store->RecoveryReason());
        return false;
    }
    if (session.requested_write && !store->PrepareNativeWritePath())
    {
        out_error = "VolumeWritePathNotReady";
        return false;
    }
    if (const auto xid = store->CheckpointXid(); xid.has_value())
    {
        std::uint64_t prior = checkpoint_xid_.load(std::memory_order_relaxed);
        while (xid.value() > prior &&
            !checkpoint_xid_.compare_exchange_weak(
                prior, xid.value(), std::memory_order_relaxed))
        {
        }
    }
    auto state = std::make_unique<SessionState>();
    state->volume_object_id = resolved.object_id;
    state->mount_point = session.mount_point;
    state->recovery_identity = session.recovery_identity;
    state->requested_write = session.requested_write;
    state->use_canonical_transaction = session.use_canonical_transaction;
    state->store = std::move(store);
    sessions_.push_back(std::move(state));
    return true;
}

bool ContainerMountCoordinator::UnmountVolume(
    std::uint64_t volume_object_id, std::string& out_error)
{
    out_error.clear();
    std::lock_guard<std::timed_mutex> commit_guard(commit_mutex_);
    std::lock_guard<std::mutex> guard(mutex_);
    if (draining_)
    {
        out_error = "ContainerDraining";
        return false;
    }
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it)
    {
        if ((*it)->volume_object_id == volume_object_id)
        {
            sessions_.erase(it);
            return true;
        }
    }
    out_error = "VolumeNotMounted";
    return false;
}

ContainerCommitResult ContainerMountCoordinator::Commit(
    std::uint64_t volume_object_id,
    const std::vector<MetadataStore::MutationRequest>& mutations,
    const ContainerPrepublicationHook& prepublication_hook,
    const ContainerMutationStagingHook& mutation_staging_hook,
    const ContainerRetentionCleanupHook& retention_cleanup_hook,
    bool accepted_replay,
    std::optional<std::uint64_t> expected_replay_preimage,
    const ContainerMutationPreparationHook& mutation_preparation_hook,
    const ContainerPostpublicationVerifierHook& postpublication_verifier_hook)
{
    const auto commit_started = std::chrono::steady_clock::now();
    ContainerCommitResult result{};
    std::unique_lock<std::timed_mutex> commit_guard(
        commit_mutex_, std::defer_lock);
    commit_guard.lock();
    ScopedCommitDiagnostics diagnostics_scope{*this, volume_object_id, result,
        commit_started, std::chrono::steady_clock::now()};
    {
        std::lock_guard<std::mutex> guard(mutex_);
        if (draining_)
        {
            result.error = "ContainerDraining";
            return result;
        }
        if (recovery_required_)
        {
            result.error = "ContainerRecoveryRequired: " + recovery_reason_;
            result.commit_recovery_required = true;
            result.commit_recovery_reason = WidenUtf8(recovery_reason_);
            return result;
        }
    }
    SessionState* session = nullptr;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        for (const auto& candidate : sessions_)
        {
            if (candidate->volume_object_id == volume_object_id)
            {
                session = candidate.get();
                break;
            }
        }
    }
    if (session == nullptr)
    {
        result.error = "VolumeNotMounted";
        return result;
    }
    const auto native_staging_clean = [&]() {
        const auto& store = *session->store;
        return store.IsNativeWriteReady() && !store.IsRecoveryRequired() &&
            store.PendingMutationCount() == 0 && store.PendingAllocationCount() == 0 &&
            store.PendingDeallocationCount() == 0 && store.PendingObjectMapUpdateCount() == 0 &&
            store.PendingBtreeRecordCount() == 0 && store.PendingPayloadByteEstimate() == 0;
    };
    if (!session->requested_write)
    {
        result.commit_status_code = static_cast<int>(
            MetadataStore::CommitStatus::NotWritable);
        result.error = "VolumeNotWritable";
        return result;
    }
    if (require_checkpoint_census_ && !checkpoint_census_initialized_)
    {
        result.commit_status_code = static_cast<int>(
            MetadataStore::CommitStatus::NotReady);
        result.error = "RequiredCheckpointCensusIncomplete";
        return result;
    }
    if (require_checkpoint_census_)
    {
        const auto* replay_target =
            FindVolumeCheckpointPinsNoLock(volume_object_id);
        const bool accepted_replay_authorized = accepted_replay &&
            replay_target != nullptr &&
            replay_target->unapplied_accepted_work;
        for (const auto& pins : volume_checkpoint_pins_)
        {
            if (!pins.unapplied_accepted_work ||
                accepted_replay_authorized) continue;
            result.error = (pins.volume_object_id == volume_object_id
                    ? "VolumeAcceptedRecoveryPending: oid=" : "SiblingAcceptedRecoveryPending: oid=") +
                std::to_string(pins.volume_object_id);
            result.commit_status_code = static_cast<int>(MetadataStore::CommitStatus::RetentionBlocked);
            result.commit_stage = "awaiting-accepted-recovery";
            // This attempt has not touched staging or called any hooks. Do not
            // certify an already dirty selected store as a clean refusal.
            result.clean_prepublication_refusal = !accepted_replay && native_staging_clean();
            return result;
        }
    }
    const std::uint64_t in_flight =
        in_flight_commits_.fetch_add(1, std::memory_order_relaxed) + 1;
    struct InFlightGuard
    {
        std::atomic<std::uint64_t>& counter;
        ~InFlightGuard()
        {
            counter.fetch_sub(1, std::memory_order_relaxed);
        }
    } in_flight_guard{in_flight_commits_};
    std::uint64_t observed = max_commit_concurrency_.load(std::memory_order_relaxed);
    while (in_flight > observed &&
        !max_commit_concurrency_.compare_exchange_weak(
            observed, in_flight, std::memory_order_relaxed))
    {
    }
    // Funnel invariant: nothing may be pre-staged outside Commit (staging
    // outside the container mutex admits stale-view allocation overlap).
    if (session->store->PendingMutationCount() != 0)
    {
        result.commit_status_code = static_cast<int>(
            MetadataStore::CommitStatus::InvariantFailed);
        result.error = "CommitUnexpectedPendingState";
        return result;
    }
    // Every per-volume store must reload the latest shared container
    // checkpoint before it chooses a target XID or allocates extents. A
    // spaceman-only refresh leaves the checkpoint slot and XID stale.
    // Do not elide this based on XID/readiness: borrowed stores have no
    // mutation epoch, image handles share write access, and publication
    // guards are captured during planning rather than retained from this load.
    std::string reload_error;
    if (!ReloadSessionForCommitNoLock(*session, reload_error, ReloadReason::BeforeCommit))
    {
        result.error = "CommitCommitterReloadFailed: " + reload_error;
        return result;
    }
    const std::optional<std::uint64_t> preimage_checkpoint_xid =
        session->store->CheckpointXid();
    if (expected_replay_preimage && (!accepted_replay ||
        preimage_checkpoint_xid != expected_replay_preimage))
    {
        result.commit_status_code = static_cast<int>(MetadataStore::CommitStatus::NotReady);
        result.error = "AcceptedReplayPreimageAdvanced";
        return result;
    }
    if ((prepublication_hook || mutation_preparation_hook) && !preimage_checkpoint_xid.has_value())
    {
        result.commit_status_code = static_cast<int>(
            MetadataStore::CommitStatus::InvariantFailed);
        result.error = "CommitPreimageCheckpointMissing";
        return result;
    }
    result.checkpoint_xid = preimage_checkpoint_xid.value_or(
        checkpoint_xid_.load(std::memory_order_relaxed));
    auto staged_requests = mutations;
    if (mutation_preparation_hook)
    {
        // The public surface is const. Also reject observable staging or
        // identity changes through an improperly captured borrowed store.
        // Copy values, never references into a view that a reload can replace.
        const auto capture_context = [&]() {
            const auto& context = session->store->Context();
            return std::make_tuple(
                context.device_path, context.device_offset_bytes, context.volume_name,
                context.container_uuid_hex, context.volume_uuid_hex,
                context.volume_object_id, context.shared_container_session,
                context.container_volume_slot_index, context.container_volume_slot_count,
                context.incompatible_features, context.allow_raw_physical_write,
                context.integrity_check_on_mount, context.crash_replay_mode,
                context.allow_legacy_scaffold_for_fixtures,
                context.disallow_scaffold_commit_on_non_fixture,
                context.reject_scaffold_replay_blob_on_non_fixture,
                context.require_canonical_replay_candidate_on_non_fixture,
                context.allow_legacy_private_checkpoint_writer_for_tests);
        };
        const auto capture = [&]() {
            const auto& store = *session->store;
            const auto* checkpoint = store.AuthoritativeAppleCheckpointView();
            return std::make_tuple(
                store.CheckpointXid(), store.LastCommittedXid(), capture_context(),
                checkpoint != nullptr,
                checkpoint ? checkpoint->container.superblock.xid : 0,
                checkpoint ? checkpoint->container.superblock.uuid_hex : std::string{},
                checkpoint ? checkpoint->container.superblock_physical_block : 0,
                checkpoint ? checkpoint->container.superblock_bytes : std::vector<std::byte>{},
                store.PendingMutationCount(), store.PendingAllocationCount(),
                store.PendingDeallocationCount(), store.PendingObjectMapUpdateCount(),
                store.PendingBtreeRecordCount(), store.PendingPayloadByteEstimate(),
                store.DebugWorkingInodeCount(), store.DebugWorkingFreeExtentCount(),
                store.DebugWorkingFreeExtentTotalBytes(), store.IsNativeWriteReady(),
                store.IsRecoveryRequired(),
                apfsaccess::rw::CheckpointDeltaCodec::Encode(store.DebugBuildPendingCheckpointDelta()));
        };
        std::string preparation_error;
        bool prepared = false;
        bool identity_changed = false;
        try
        {
            const auto context_before = capture_context();
            const auto before = capture();
            try
            {
                prepared = mutation_preparation_hook(*session->store, staged_requests, preparation_error);
            }
            catch (...)
            {
                preparation_error = "MutationPreparationHookException";
            }
            identity_changed = capture_context() != context_before;
            if (capture() != before || session->store->CheckpointXid() != preimage_checkpoint_xid)
            {
                prepared = false;
                preparation_error = "MutationPreparationStoreChanged";
            }
            std::size_t inline_bytes = 0;
            bool bounded = !staged_requests.empty() &&
                staged_requests.size() <= ContainerPreparedMutationLimit;
            for (const auto& request : staged_requests)
            {
                if (!bounded) break;
                bounded = request.path.size() <= ContainerPreparedPathCharLimit &&
                    request.secondary_path.size() <= ContainerPreparedPathCharLimit &&
                    request.inline_payload.size() <= ContainerPreparedInlineByteLimit - inline_bytes;
                if (bounded) inline_bytes += request.inline_payload.size();
            }
            if (prepared && preparation_error.empty() && !bounded)
            {
                prepared = false;
                preparation_error = "MutationPreparationBatchOutOfBounds";
            }
        }
        catch (...)
        {
            prepared = false;
            preparation_error = "MutationPreparationSnapshotException";
        }
        if (!prepared || !preparation_error.empty())
        {
            result.commit_status_code = static_cast<int>(MetadataStore::CommitStatus::InvariantFailed);
            result.commit_stage = "mutation-preparation-hook";
            result.error = "CommitMutationPreparationHookFailed";
            if (!preparation_error.empty()) result.error += ": " + preparation_error;
            if (identity_changed)
            {
                // Reloading a store whose routing identity was tampered with
                // could select a different source. Leave it closed for recovery.
                std::lock_guard<std::mutex> guard(mutex_);
                recovery_required_ = true;
                recovery_volume_object_id_ = session->volume_object_id;
                recovery_reason_ = "MutationPreparationIdentityChanged";
                result.commit_recovery_required = true;
                result.commit_recovery_reason = WidenUtf8(recovery_reason_);
                return result;
            }
            // No WAL acceptance has run: preserve the existing pin census and
            // caller-owned evidence. Discard only local scratch/illegal staging.
            std::string rollback_error;
            if (!ReloadSessionForCommitNoLock(*session, rollback_error))
            {
                std::lock_guard<std::mutex> guard(mutex_);
                recovery_required_ = true;
                recovery_volume_object_id_ = session->volume_object_id;
                recovery_reason_ = "MutationPreparationRollbackFailed: " + rollback_error;
                result.error += " | " + recovery_reason_;
                result.commit_recovery_required = true;
                result.commit_recovery_reason = WidenUtf8(recovery_reason_);
            }
            else
            {
                result.clean_prepublication_refusal = !accepted_replay && native_staging_clean() &&
                    session->store->CheckpointXid() == preimage_checkpoint_xid;
            }
            return result;
        }
    }
    for (std::size_t mutation_index = 0;
         mutation_index < staged_requests.size();
         ++mutation_index)
    {
        MetadataStore::MutationRequest& request =
            staged_requests[mutation_index];
        MetadataStore::PayloadIdentity staged_identity{};
        std::optional<apfsaccess::rw::UnlinkOutcome> unlink_outcome;
        const auto stage =
            session->store->StageMutation(request, &staged_identity, &unlink_outcome);
        if (stage != MetadataStore::MutationStatus::Applied)
        {
            result.mutation_staging_status = stage;
            result.commit_stage = "mutation-staging";
            result.error = "CommitStageFailed: status=" +
                std::to_string(static_cast<int>(stage)) + " | " +
                NarrowLossy(session->store->RecoveryReason());
            result.staged_identities.clear();
            std::string rollback_error;
            if (!ReloadSessionForCommitNoLock(*session, rollback_error))
            {
                std::lock_guard<std::mutex> guard(mutex_);
                recovery_required_ = true;
                recovery_volume_object_id_ = session->volume_object_id;
                recovery_reason_ = "PartialStageRollbackFailed: " +
                    rollback_error;
                result.error += " | " + recovery_reason_;
                result.commit_recovery_required = true;
                result.commit_recovery_reason =
                    WidenUtf8(recovery_reason_);
            }
            else
            {
                // A caller staging hook may own external evidence; certify
                // only the native-only staging path before the WAL binder.
                result.clean_prepublication_refusal =
                    !accepted_replay && !mutation_staging_hook && native_staging_clean() &&
                    session->store->CheckpointXid() == preimage_checkpoint_xid;
            }
            return result;
        }
        result.staged_identities.push_back(staged_identity);
        request.expected_unlink_outcome = std::move(unlink_outcome);
        if (mutation_staging_hook)
        {
            std::string hook_error;
            bool hook_succeeded = false;
            try
            {
                hook_succeeded = mutation_staging_hook(
                    mutation_index,
                    request,
                    result.staged_identities.back(),
                    hook_error);
            }
            catch (...)
            {
                hook_error = "MutationStagingHookException";
            }
            if (!hook_succeeded)
            {
                result.commit_status_code = static_cast<int>(
                    MetadataStore::CommitStatus::InvariantFailed);
                result.commit_stage = "mutation-staging-hook";
                result.error = "CommitMutationStagingHookFailed";
                if (!hook_error.empty())
                {
                    result.error += ": " + hook_error;
                }
                result.staged_identities.clear();
                std::string rollback_error;
                if (!ReloadSessionForCommitNoLock(*session, rollback_error))
                {
                    std::lock_guard<std::mutex> guard(mutex_);
                    recovery_required_ = true;
                    recovery_volume_object_id_ = session->volume_object_id;
                    recovery_reason_ = "MutationStagingHookRollbackFailed: " +
                        rollback_error;
                    result.error += " | " + recovery_reason_;
                    result.commit_recovery_required = true;
                    result.commit_recovery_reason =
                        WidenUtf8(recovery_reason_);
                }
                return result;
            }
        }
    }
    if (prepublication_hook)
    {
        std::string hook_error;
        bool hook_succeeded = false;
        VolumeCheckpointPins* volume_pins =
            FindVolumeCheckpointPinsNoLock(session->volume_object_id);
        std::vector<std::uint64_t> refreshed_pins = volume_pins != nullptr
            ? volume_pins->required_checkpoint_xids
            : std::vector<std::uint64_t>{};
        try
        {
            hook_succeeded = prepublication_hook(
                staged_requests,
                result.staged_identities,
                preimage_checkpoint_xid.value(),
                refreshed_pins,
                hook_error);
        }
        catch (...)
        {
            hook_error = "PrepublicationHookException";
        }
        // In required mode a hook failure may occur after WAL acceptance but
        // before its rescan can refresh the output. Retaining the exact source
        // generation is safe even when the failure happened before acceptance;
        // only the explicit post-cleanup update may release it.
        if (require_checkpoint_census_ && !hook_succeeded &&
            std::find(
                refreshed_pins.begin(),
                refreshed_pins.end(),
                preimage_checkpoint_xid.value()) == refreshed_pins.end())
        {
            refreshed_pins.push_back(preimage_checkpoint_xid.value());
        }
        std::vector<std::uint64_t> normalized_pins;
        std::string pins_error;
        const bool pins_valid = volume_pins != nullptr &&
            NormalizeRequiredCheckpointXids(
                refreshed_pins,
                preimage_checkpoint_xid.value(),
                normalized_pins,
                pins_error);
        if (pins_valid)
        {
            std::vector<std::uint64_t> retained_pins;
            retained_pins.reserve(
                volume_pins->required_checkpoint_xids.size() +
                normalized_pins.size());
            std::set_union(
                volume_pins->required_checkpoint_xids.begin(),
                volume_pins->required_checkpoint_xids.end(),
                normalized_pins.begin(),
                normalized_pins.end(),
                std::back_inserter(retained_pins));
            volume_pins->required_checkpoint_xids = std::move(retained_pins);
            volume_pins->unapplied_accepted_work |= !staged_requests.empty() || !hook_succeeded;
        }
        else
        {
            hook_succeeded = false;
            hook_error = "PrepublicationPinsInvalid: " +
                (pins_error.empty()
                    ? std::string("RequiredCheckpointVolumeMissing")
                    : pins_error);
            std::lock_guard<std::mutex> guard(mutex_);
            recovery_required_ = true;
            recovery_volume_object_id_ = session->volume_object_id;
            recovery_reason_ = hook_error;
            result.commit_recovery_required = true;
            result.commit_recovery_reason = WidenUtf8(recovery_reason_);
        }
        if (!hook_succeeded)
        {
            result.commit_status_code = static_cast<int>(
                MetadataStore::CommitStatus::InvariantFailed);
            result.commit_stage = "before-checkpoint-publication";
            result.error = "CommitPrepublicationHookFailed";
            if (!hook_error.empty())
            {
                result.error += ": " + hook_error;
            }
            std::string rollback_error;
            if (!ReloadSessionForCommitNoLock(*session, rollback_error))
            {
                std::lock_guard<std::mutex> guard(mutex_);
                recovery_required_ = true;
                recovery_volume_object_id_ = session->volume_object_id;
                recovery_reason_ = "PrepublicationRollbackFailed: " +
                    rollback_error;
                result.error += " | " + recovery_reason_;
                result.commit_recovery_required = true;
                result.commit_recovery_reason = WidenUtf8(recovery_reason_);
            }
            return result;
        }
    }
    const apfsaccess::rw::CheckpointDelta pending =
        session->store->DebugBuildPendingCheckpointDelta();
    std::vector<ExtentRange> ranges;
    ranges.reserve(pending.spaceman_allocations.size());
    for (const auto& extent : pending.spaceman_allocations)
    {
        if (extent.bytes == 0)
        {
            continue;
        }
        ExtentRange range{};
        range.address = extent.physical_address;
        range.bytes = extent.bytes;
        ranges.push_back(range);
    }
    std::vector<ExtentRange> deallocations;
    deallocations.reserve(pending.spaceman_deallocations.size());
    for (const auto& extent : pending.spaceman_deallocations)
    {
        if (extent.bytes == 0)
        {
            continue;
        }
        deallocations.push_back({extent.physical_address, extent.bytes});
    }
    const std::vector<std::uint64_t> required_checkpoint_xids =
        RequiredCheckpointXidUnionNoLock();
    // Allocate the fallback before publication: latching a thrown verifier
    // must not depend on allocating an exception/error message.
    std::string verifier_recovery_reason = postpublication_verifier_hook
        ? "CommitPostpublicationVerificationFailed" : std::string{};
    auto status = session->use_canonical_transaction
        ? session->store->CommitCanonicalTransaction(required_checkpoint_xids)
        : session->store->CommitTransaction(required_checkpoint_xids);
    std::string retention_cleanup_failure;
    if (status == MetadataStore::CommitStatus::RetentionBlocked &&
        session->use_canonical_transaction && retention_cleanup_hook)
    {
        auto* volume_pins = FindVolumeCheckpointPinsNoLock(volume_object_id);
        auto refreshed_pins = volume_pins != nullptr
            ? volume_pins->required_checkpoint_xids : std::vector<std::uint64_t>{};
        bool census_valid = false;
        try { census_valid = retention_cleanup_hook(refreshed_pins, retention_cleanup_failure); }
        catch (...) { retention_cleanup_failure = "RetentionCleanupHookException"; }
        std::vector<std::uint64_t> normalized_pins;
        if (!census_valid || !retention_cleanup_failure.empty() || volume_pins == nullptr ||
            !NormalizeRequiredCheckpointXids(refreshed_pins,
                preimage_checkpoint_xid.value_or(0), normalized_pins, retention_cleanup_failure))
        {
            if (retention_cleanup_failure.empty()) retention_cleanup_failure = "RetentionCleanupRefused";
        }
        else if (!std::includes(volume_pins->required_checkpoint_xids.begin(),
                     volume_pins->required_checkpoint_xids.end(), normalized_pins.begin(), normalized_pins.end()) ||
                 (!staged_requests.empty() && !std::binary_search(normalized_pins.begin(), normalized_pins.end(),
                     preimage_checkpoint_xid.value_or(0))))
        {
            retention_cleanup_failure = "RetentionCleanupPinsInvalid";
        }
        else if (normalized_pins != volume_pins->required_checkpoint_xids)
        {
            // RetentionBlocked preserves staging and guarantees no device I/O.
            // Keep identities/source and global ownership intact; do not rerun
            // staging or the WAL acceptance hook on this single retry.
            volume_pins->required_checkpoint_xids = std::move(normalized_pins);
            status = session->store->CommitCanonicalTransaction(RequiredCheckpointXidUnionNoLock());
            if (status == MetadataStore::CommitStatus::NothingToCommit && !staged_requests.empty())
                retention_cleanup_failure = "RetentionRetryLostPendingMutation";
        }
        if (!retention_cleanup_failure.empty()) status = MetadataStore::CommitStatus::InvariantFailed;
    }
    result.commit_status_code = static_cast<int>(status);
    result.commit_stage = retention_cleanup_failure.empty()
        ? session->store->LastCommitStage() : "retention-cleanup";
    if (const auto committed_xid = session->store->LastCommittedXid();
        committed_xid.has_value())
    {
        result.committed_xid = committed_xid.value();
    }
    result.commit_recovery_reason = retention_cleanup_failure.empty()
        ? session->store->RecoveryReason() : WidenUtf8("RetentionCleanupFailed: " + retention_cleanup_failure);
    result.commit_recovery_required = session->store->IsRecoveryRequired();
    if (status != MetadataStore::CommitStatus::Committed &&
        status != MetadataStore::CommitStatus::NothingToCommit)
    {
        result.error =
            (status == MetadataStore::CommitStatus::RetentionBlocked
                ? "CommitRetentionBlocked: status="
                : "CommitPersistFailed: status=") +
            std::to_string(static_cast<int>(status)) +
            " stage=" + session->store->LastCommitStage() + " | " +
            NarrowLossy(session->store->LastCommitFailureReason()) + " | " +
            NarrowLossy(session->store->RecoveryReason()) + " | " +
            NarrowLossy(session->store->LastCommitFailureDetail());
        if (!retention_cleanup_failure.empty()) result.error += " | " + retention_cleanup_failure;
        {
            std::lock_guard<std::mutex> guard(mutex_);
            diagnostics_.last_failure_stage = result.commit_stage;
            diagnostics_.last_failure_detail = result.error;
            if (auto* counters = FindVolumeDiagnosticsNoLock(session->volume_object_id))
            {
                counters->last_failure_stage = result.commit_stage;
                counters->last_failure_detail = result.error;
            }
        }
        if (session->store->IsRecoveryRequired())
        {
            std::lock_guard<std::mutex> guard(mutex_);
            recovery_required_ = true;
            recovery_volume_object_id_ = session->volume_object_id;
            recovery_reason_ = "SessionCommitRecoveryRequired: " +
                NarrowLossy(session->store->RecoveryReason());
        }
        else
        {
            std::string rollback_error;
            if (!ReloadSessionForCommitNoLock(*session, rollback_error))
            {
                std::lock_guard<std::mutex> guard(mutex_);
                recovery_required_ = true;
                recovery_volume_object_id_ = session->volume_object_id;
                recovery_reason_ = "CleanCommitRollbackFailed: " +
                    rollback_error;
                result.error += " | " + recovery_reason_;
                result.commit_recovery_required = true;
                result.commit_recovery_reason =
                    WidenUtf8(recovery_reason_);
            }
        }
        return result;
    }
    if (const auto xid = session->store->CheckpointXid(); xid.has_value())
    {
        std::uint64_t prior = checkpoint_xid_.load(std::memory_order_relaxed);
        while (xid.value() > prior &&
            !checkpoint_xid_.compare_exchange_weak(
                prior, xid.value(), std::memory_order_relaxed))
        {
        }
        result.checkpoint_xid = checkpoint_xid_.load(std::memory_order_relaxed);
    }
    // Canonical commits reserve against the container's authoritative Apple
    // spaceman under this same commit lock. The compatibility ledger contains
    // per-store synthetic addresses and is valid only for the legacy writer.
    if (!session->use_canonical_transaction)
    {
        std::lock_guard<std::mutex> guard(mutex_);
        std::string ledger_error;
        if (!RecordCommitRangesNoLock(
                ranges, deallocations, ledger_error))
        {
            recovery_required_ = true;
            recovery_volume_object_id_ = session->volume_object_id;
            recovery_reason_ = ledger_error;
            result.error = "CommitLedgerOverlap: " + ledger_error;
            result.committed = true;
            result.commit_status_code = static_cast<int>(
                MetadataStore::CommitStatus::InvariantFailed);
            result.commit_recovery_required = true;
            result.commit_recovery_reason = WidenUtf8(recovery_reason_);
            return result;
        }
    }
    if (status == MetadataStore::CommitStatus::Committed && postpublication_verifier_hook)
    {
        // Committed means native publication and the store's reload finished.
        // Account for the actual checkpoint/ledger above even if verification
        // fails. Keep accepted work unresolved until verification succeeds.
        std::string verification_error;
        bool verified = false;
        bool verifier_threw = false;
        const bool published_view_matches = result.committed_xid != 0 &&
            session->store->CheckpointXid() == result.committed_xid &&
            !session->store->IsRecoveryRequired();
        try
        {
            if (published_view_matches)
                verified = postpublication_verifier_hook(
                    *session->store, result.committed_xid, verification_error);
        }
        catch (...)
        {
            verifier_threw = true;
        }
        if (!verified || verifier_threw || !verification_error.empty())
        {
            // Latch before formatting diagnostics, so even an allocation
            // exception while reporting failure cannot admit a sibling writer.
            std::lock_guard<std::mutex> guard(mutex_);
            recovery_required_ = true;
            recovery_volume_object_id_ = session->volume_object_id;
            recovery_reason_.swap(verifier_recovery_reason);
            result.committed = true;
            result.commit_status_code = static_cast<int>(MetadataStore::CommitStatus::InvariantFailed);
            result.commit_recovery_required = true;
            result.commit_stage = "postpublication-verifier";
            result.error = recovery_reason_;
            if (verifier_threw) result.error += ": PostpublicationVerifierException";
            else if (!published_view_matches) result.error += ": PublishedCheckpointMismatch";
            else if (!verification_error.empty()) result.error += ": " + verification_error;
            else result.error += ": PostpublicationVerifierRefused";
            result.commit_recovery_reason = WidenUtf8(result.error);
            diagnostics_.last_failure_stage = result.commit_stage;
            diagnostics_.last_failure_detail = result.error;
            if (auto* counters = FindVolumeDiagnosticsNoLock(session->volume_object_id))
            {
                counters->last_failure_stage = result.commit_stage;
                counters->last_failure_detail = result.error;
            }
            return result;
        }
    }
    if (status == MetadataStore::CommitStatus::Committed && !accepted_replay)
    {
        // Normal publication resolves its staged acceptance. Replay may be
        // split across commits, so only its explicit WAL cleanup census update
        // may clear the pending flag. Retention pins remain until cleanup.
        if (auto* pins = FindVolumeCheckpointPinsNoLock(volume_object_id))
            pins->unapplied_accepted_work = false;
    }
    result.committed = true;
    return result;
}

bool ContainerMountCoordinator::RefreshSessionForRecovery(
    std::uint64_t volume_object_id, std::string& out_error)
{
    out_error.clear();
    std::lock_guard<std::timed_mutex> commit_guard(commit_mutex_);
    SessionState* selected = nullptr;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        if (draining_ || recovery_required_)
        {
            out_error = "ContainerRecoveryRefreshUnavailable";
            return false;
        }
        for (const auto& session : sessions_)
            if (session->volume_object_id == volume_object_id) { selected = session.get(); break; }
    }
    if (selected)
    {
        if (selected->store->PendingMutationCount() != 0)
        {
            out_error = "RecoveryRefreshUnexpectedPendingState";
            return false;
        }
        return ReloadSessionForCommitNoLock(*selected, out_error, ReloadReason::Recovery);
    }
    out_error = "VolumeNotMounted";
    return false;
}

bool ContainerMountCoordinator::RefreshCheckpointFromSession(
    std::uint64_t volume_object_id, std::string& out_error)
{
    out_error.clear();
    std::lock_guard<std::timed_mutex> commit_guard(commit_mutex_);
    std::lock_guard<std::mutex> guard(mutex_);
    for (const auto& session : sessions_)
    {
        if (session->volume_object_id != volume_object_id)
        {
            continue;
        }
        if (const auto xid = session->store->CheckpointXid();
            xid.has_value())
        {
            std::uint64_t prior =
                checkpoint_xid_.load(std::memory_order_relaxed);
            while (xid.value() > prior &&
                !checkpoint_xid_.compare_exchange_weak(
                    prior, xid.value(), std::memory_order_relaxed))
            {
            }
        }
        return true;
    }
    out_error = "VolumeNotMounted";
    return false;
}

ContainerShutdownResult ContainerMountCoordinator::DrainAndStop(
    std::chrono::milliseconds timeout)
{
    ContainerShutdownResult result{};
    const auto deadline =
        std::chrono::steady_clock::now() + timeout;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        draining_ = true;
    }
    std::unique_lock<std::timed_mutex> commit_guard(
        commit_mutex_, std::defer_lock);
    if (!commit_guard.try_lock_until(deadline))
    {
        result.error = "ContainerDrainTimeout";
        return result;
    }
    {
        std::lock_guard<std::mutex> guard(mutex_);
        sessions_.clear();
        committed_ranges_.clear();
        device_.reset();
    }
    result.clean = true;
    return result;
}

std::uint64_t ContainerMountCoordinator::OwnerProcessId() const noexcept
{
    return owner_process_id_;
}

bool ContainerMountCoordinator::RawLeaseHeld() const noexcept
{
    std::lock_guard<std::mutex> guard(mutex_);
    return device_ != nullptr &&
        (!writable_lease_required_ || device_->HasWriteHandle());
}

std::size_t ContainerMountCoordinator::MountedVolumeCount() const
{
    std::lock_guard<std::mutex> guard(mutex_);
    return sessions_.size();
}

std::uint64_t ContainerMountCoordinator::CheckpointXid() const noexcept
{
    return checkpoint_xid_.load(std::memory_order_relaxed);
}

const std::string& ContainerMountCoordinator::ContainerUuidHex() const noexcept
{
    return container_uuid_hex_;
}

const BlockDevice& ContainerMountCoordinator::Device() const noexcept
{
    return *device_;
}

MetadataStore* ContainerMountCoordinator::FindSessionStore(
    std::uint64_t volume_object_id) noexcept
{
    std::lock_guard<std::mutex> guard(mutex_);
    for (const auto& session : sessions_)
    {
        if (session->volume_object_id == volume_object_id)
        {
            return session->store.get();
        }
    }
    return nullptr;
}

bool ContainerMountCoordinator::IsRecoveryRequired() const noexcept
{
    std::lock_guard<std::mutex> guard(mutex_);
    return recovery_required_;
}

std::optional<std::uint64_t>
ContainerMountCoordinator::RecoveryVolumeObjectId() const noexcept
{
    std::lock_guard<std::mutex> guard(mutex_);
    return recovery_volume_object_id_;
}

std::string ContainerMountCoordinator::RecoveryReason() const
{
    std::lock_guard<std::mutex> guard(mutex_);
    return recovery_reason_;
}

std::uint64_t ContainerMountCoordinator::MaxObservedCommitConcurrency()
    const noexcept
{
    return max_commit_concurrency_.load(std::memory_order_relaxed);
}

ContainerCommitDiagnostics ContainerMountCoordinator::DiagnosticsSnapshot(
    std::optional<std::uint64_t> volume_object_id) const
{
    std::lock_guard<std::mutex> guard(mutex_);
    if (!volume_object_id) return diagnostics_;
    for (const auto& volume : volume_diagnostics_)
        if (volume.volume_object_id == *volume_object_id) return volume.counters;
    return {};
}

std::string ContainerMountCoordinator::DevicePerformanceJson() const
{
    std::lock_guard<std::mutex> guard(mutex_);
    return device_ ? device_->PerformanceJson() : "null";
}

ContainerCommitDiagnostics* ContainerMountCoordinator::FindVolumeDiagnosticsNoLock(
    std::uint64_t volume_object_id) noexcept
{
    const auto found = std::lower_bound(volume_diagnostics_.begin(), volume_diagnostics_.end(),
        volume_object_id, [](const VolumeDiagnostics& volume, std::uint64_t oid)
        {
            return volume.volume_object_id < oid;
        });
    return found != volume_diagnostics_.end() && found->volume_object_id == volume_object_id
        ? &found->counters : nullptr;
}

VolumeCheckpointPins*
ContainerMountCoordinator::FindVolumeCheckpointPinsNoLock(
    std::uint64_t volume_object_id) noexcept
{
    const auto found = std::lower_bound(
        volume_checkpoint_pins_.begin(),
        volume_checkpoint_pins_.end(),
        volume_object_id,
        [](const VolumeCheckpointPins& pins, std::uint64_t oid)
        {
            return pins.volume_object_id < oid;
        });
    return found != volume_checkpoint_pins_.end() &&
            found->volume_object_id == volume_object_id
        ? &*found
        : nullptr;
}

const VolumeCheckpointPins*
ContainerMountCoordinator::FindVolumeCheckpointPinsNoLock(
    std::uint64_t volume_object_id) const noexcept
{
    const auto found = std::lower_bound(
        volume_checkpoint_pins_.begin(),
        volume_checkpoint_pins_.end(),
        volume_object_id,
        [](const VolumeCheckpointPins& pins, std::uint64_t oid)
        {
            return pins.volume_object_id < oid;
        });
    return found != volume_checkpoint_pins_.end() &&
            found->volume_object_id == volume_object_id
        ? &*found
        : nullptr;
}

std::vector<std::uint64_t>
ContainerMountCoordinator::RequiredCheckpointXidUnionNoLock() const
{
    std::vector<std::uint64_t> required_checkpoint_xids;
    for (const VolumeCheckpointPins& pins : volume_checkpoint_pins_)
    {
        required_checkpoint_xids.insert(
            required_checkpoint_xids.end(),
            pins.required_checkpoint_xids.begin(),
            pins.required_checkpoint_xids.end());
    }
    std::sort(
        required_checkpoint_xids.begin(), required_checkpoint_xids.end());
    required_checkpoint_xids.erase(
        std::unique(
            required_checkpoint_xids.begin(), required_checkpoint_xids.end()),
        required_checkpoint_xids.end());
    return required_checkpoint_xids;
}

bool ContainerMountCoordinator::ReloadSessionForCommitNoLock(
    SessionState& session, std::string& out_error, ReloadReason reason)
{
    ScopedReloadDiagnostics diagnostics_scope{*this, session.volume_object_id, reason};
    out_error.clear();
    if (!session.store->PrepareNativeWritePath())
    {
        out_error = "VolumeWritePathReloadFailed: " +
            NarrowLossy(session.store->RecoveryReason());
        return false;
    }
    diagnostics_scope.succeeded = true;
    return true;
}

bool ContainerMountCoordinator::RecordCommitRangesNoLock(
    const std::vector<ExtentRange>& allocations,
    const std::vector<ExtentRange>& deallocations,
    std::string& out_error)
{
    return ApplyExtentDelta(
        committed_ranges_, allocations, deallocations, out_error);
}

bool ContainerMountCoordinator::ApplyExtentDelta(
    std::vector<ExtentRange>& ledger,
    const std::vector<ExtentRange>& allocations,
    const std::vector<ExtentRange>& deallocations,
    std::string& out_error)
{
    out_error.clear();
    auto working = ledger;
    const auto valid_range = [](const ExtentRange& range)
    {
        return range.bytes == 0 ||
            range.address <= UINT64_MAX - range.bytes;
    };
    const auto normalize = [&](std::vector<ExtentRange>& ranges)
    {
        ranges.erase(
            std::remove_if(
                ranges.begin(), ranges.end(),
                [](const ExtentRange& range) { return range.bytes == 0; }),
            ranges.end());
        for (const ExtentRange& range : ranges)
        {
            if (!valid_range(range))
            {
                out_error = "ExtentRangeOverflow";
                return false;
            }
        }
        std::sort(
            ranges.begin(), ranges.end(),
            [](const ExtentRange& left, const ExtentRange& right)
            {
                return left.address < right.address;
            });
        std::vector<ExtentRange> normalized;
        normalized.reserve(ranges.size());
        for (const ExtentRange& range : ranges)
        {
            if (normalized.empty())
            {
                normalized.push_back(range);
                continue;
            }
            ExtentRange& prior = normalized.back();
            const std::uint64_t prior_end = prior.address + prior.bytes;
            if (range.address < prior_end)
            {
                out_error = "AllocationOverlapDetected";
                return false;
            }
            if (range.address == prior_end)
            {
                prior.bytes += range.bytes;
            }
            else
            {
                normalized.push_back(range);
            }
        }
        ranges.swap(normalized);
        return true;
    };

    if (!normalize(working))
    {
        return false;
    }
    for (const ExtentRange& released : deallocations)
    {
        if (released.bytes == 0)
        {
            continue;
        }
        if (!valid_range(released))
        {
            out_error = "ExtentRangeOverflow";
            return false;
        }
        const std::uint64_t released_end = released.address + released.bytes;
        std::vector<ExtentRange> retained;
        retained.reserve(working.size() + 1);
        for (const ExtentRange& existing : working)
        {
            const std::uint64_t existing_end =
                existing.address + existing.bytes;
            if (released_end <= existing.address ||
                existing_end <= released.address)
            {
                retained.push_back(existing);
                continue;
            }
            if (existing.address < released.address)
            {
                retained.push_back(
                    {existing.address, released.address - existing.address});
            }
            if (released_end < existing_end)
            {
                retained.push_back(
                    {released_end, existing_end - released_end});
            }
        }
        working.swap(retained);
    }
    for (const ExtentRange& allocated : allocations)
    {
        if (allocated.bytes == 0)
        {
            continue;
        }
        if (!valid_range(allocated))
        {
            out_error = "ExtentRangeOverflow";
            return false;
        }
        for (const ExtentRange& existing : working)
        {
            if (RangesOverlap(allocated, existing))
            {
                out_error = "AllocationOverlapDetected";
                return false;
            }
        }
        working.push_back(allocated);
    }
    if (!normalize(working))
    {
        return false;
    }
    ledger.swap(working);
    return true;
}

bool ContainerMountCoordinator::RangesOverlap(
    const ExtentRange& left, const ExtentRange& right) noexcept
{
    if (left.bytes == 0 || right.bytes == 0)
    {
        return false;
    }
    if (left.address > UINT64_MAX - left.bytes ||
        right.address > UINT64_MAX - right.bytes)
    {
        return true;
    }
    const std::uint64_t left_end = left.address + left.bytes;
    const std::uint64_t right_end = right.address + right.bytes;
    return left.address < right_end && right.address < left_end;
}

} // namespace apfsaccess::catalog
