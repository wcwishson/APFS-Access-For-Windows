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
#include <map>
#include <sstream>
#include <thread>
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
    bool require_writable_lease)
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
    const ContainerPrepublicationHook& prepublication_hook)
{
    ContainerCommitResult result{};
    std::unique_lock<std::timed_mutex> commit_guard(
        commit_mutex_, std::defer_lock);
    commit_guard.lock();
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
    if (!session->requested_write)
    {
        result.commit_status_code = static_cast<int>(
            MetadataStore::CommitStatus::NotWritable);
        result.error = "VolumeNotWritable";
        return result;
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
    std::string reload_error;
    if (!ReloadSessionForCommitNoLock(*session, reload_error))
    {
        result.error = "CommitCommitterReloadFailed: " + reload_error;
        return result;
    }
    result.checkpoint_xid = checkpoint_xid_.load(std::memory_order_relaxed);
    for (const MetadataStore::MutationRequest& request : mutations)
    {
        MetadataStore::PayloadIdentity staged_identity{};
        const auto stage =
            session->store->StageMutation(request, &staged_identity);
        if (stage != MetadataStore::MutationStatus::Applied)
        {
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
            return result;
        }
        result.staged_identities.push_back(staged_identity);
    }
    if (prepublication_hook)
    {
        std::string hook_error;
        bool hook_succeeded = false;
        try
        {
            hook_succeeded = prepublication_hook(
                mutations, result.staged_identities, hook_error);
        }
        catch (...)
        {
            hook_error = "PrepublicationHookException";
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
    const auto status = session->use_canonical_transaction
        ? session->store->CommitCanonicalTransaction()
        : session->store->CommitTransaction();
    result.commit_status_code = static_cast<int>(status);
    result.commit_stage = session->store->LastCommitStage();
    if (const auto committed_xid = session->store->LastCommittedXid();
        committed_xid.has_value())
    {
        result.committed_xid = committed_xid.value();
    }
    result.commit_recovery_reason = session->store->RecoveryReason();
    result.commit_recovery_required = session->store->IsRecoveryRequired();
    if (status != MetadataStore::CommitStatus::Committed &&
        status != MetadataStore::CommitStatus::NothingToCommit)
    {
        result.error = "CommitPersistFailed: status=" +
            std::to_string(static_cast<int>(status)) +
            " stage=" + session->store->LastCommitStage() + " | " +
            NarrowLossy(session->store->LastCommitFailureReason()) + " | " +
            NarrowLossy(session->store->RecoveryReason());
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
    result.committed = true;
    return result;
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

bool ContainerMountCoordinator::ReloadSessionForCommitNoLock(
    SessionState& session, std::string& out_error)
{
    out_error.clear();
    if (!session.store->PrepareNativeWritePath())
    {
        out_error = "VolumeWritePathReloadFailed: " +
            NarrowLossy(session.store->RecoveryReason());
        return false;
    }
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
