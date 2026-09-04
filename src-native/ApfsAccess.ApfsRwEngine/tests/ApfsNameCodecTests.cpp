#include "ApfsNameCodec.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <iostream>
#include <random>
#include <set>
#include <span>
#include <string>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace
{
using apfsaccess::rw::ApfsCaseMode;
using apfsaccess::rw::ApfsNameCodec;
using apfsaccess::rw::ApfsNameError;
using apfsaccess::rw::ApfsNamePolicy;
using apfsaccess::rw::ApfsNormalizationMode;

constexpr std::uint64_t kCaseInsensitive = 0x1;
constexpr std::uint64_t kNormalizationInsensitive = 0x8;

int g_failures = 0;

bool Require(bool condition, const std::string& message)
{
    if (!condition)
    {
        std::cerr << "[FAIL] " << message << std::endl;
        ++g_failures;
        return false;
    }
    return true;
}

std::vector<std::byte> Bytes(std::initializer_list<std::uint8_t> values)
{
    std::vector<std::byte> result;
    result.reserve(values.size());
    for (const auto value : values)
    {
        result.push_back(static_cast<std::byte>(value));
    }
    return result;
}

std::vector<std::byte> Bytes(const std::string& value)
{
    const auto* begin = reinterpret_cast<const std::byte*>(value.data());
    return {begin, begin + value.size()};
}

std::string String(const std::vector<std::byte>& value)
{
    return {reinterpret_cast<const char*>(value.data()), value.size()};
}

std::string LookupString(const apfsaccess::rw::ApfsName& name)
{
    return {reinterpret_cast<const char*>(name.lookup_key.data()), name.lookup_key.size()};
}

bool EqualsOrdinalIgnoreCase(std::wstring_view left, std::wstring_view right)
{
#ifdef _WIN32
    return CompareStringOrdinal(
               left.data(), static_cast<int>(left.size()),
               right.data(), static_cast<int>(right.size()), TRUE) == CSTR_EQUAL;
#else
    if (left.size() != right.size())
    {
        return false;
    }
    for (std::size_t index = 0; index < left.size(); ++index)
    {
        auto lhs = left[index];
        auto rhs = right[index];
        if (lhs >= L'A' && lhs <= L'Z') lhs = static_cast<wchar_t>(lhs - L'A' + L'a');
        if (rhs >= L'A' && rhs <= L'Z') rhs = static_cast<wchar_t>(rhs - L'A' + L'a');
        if (lhs != rhs)
        {
            return false;
        }
    }
    return true;
#endif
}

std::uint32_t IndependentCrc32c(std::span<const std::uint32_t> scalars)
{
    std::uint32_t crc = 0xffffffffu;
    for (const auto scalar : scalars)
    {
        for (unsigned int shift = 0; shift < 32; shift += 8)
        {
            crc ^= (scalar >> shift) & 0xffu;
            for (int bit = 0; bit < 8; ++bit)
            {
                crc = (crc >> 1) ^ ((crc & 1u) != 0 ? 0x82f63b78u : 0u);
            }
        }
    }
    return crc & 0x3fffffu;
}

bool RoundTrips(
    const std::vector<std::byte>& raw,
    const ApfsNamePolicy& policy,
    const std::string& label)
{
    const auto decoded = ApfsNameCodec::Decode(raw, policy);
    if (!Require(decoded.ok(), label + " decode"))
    {
        return false;
    }
    const auto encoded = ApfsNameCodec::EncodeWindowsName(decoded.value->windows_display);
    return Require(encoded.ok(), label + " encode") &&
           Require(*encoded.value == String(raw), label + " byte round-trip");
}

bool TestPolicyDerivation()
{
    bool ok = true;
    const auto exact = ApfsNamePolicy::FromIncompatibleFeatures(0);
    ok &= Require(exact.case_mode == ApfsCaseMode::Sensitive,
                  "unflagged APFS is case-sensitive");
    ok &= Require(exact.normalization_mode == ApfsNormalizationMode::Sensitive,
                  "unflagged APFS is normalization-sensitive");
    ok &= Require(!exact.UsesHashedDirectoryKeys(),
                  "unflagged APFS uses unhashed directory keys");

    const auto normalized = ApfsNamePolicy::FromIncompatibleFeatures(
        kNormalizationInsensitive);
    ok &= Require(normalized.case_mode == ApfsCaseMode::Sensitive,
                  "normalization-insensitive APFS can remain case-sensitive");
    ok &= Require(normalized.normalization_mode == ApfsNormalizationMode::Insensitive,
                  "normalization flag enables canonical decomposition");
    ok &= Require(normalized.UsesHashedDirectoryKeys(),
                  "normalization-insensitive APFS uses hashed directory keys");

    for (const auto flags : {kCaseInsensitive,
                             kCaseInsensitive | kNormalizationInsensitive})
    {
        const auto folded = ApfsNamePolicy::FromIncompatibleFeatures(flags);
        ok &= Require(folded.case_mode == ApfsCaseMode::Insensitive,
                      "case-insensitive flag enables case folding");
        ok &= Require(folded.normalization_mode == ApfsNormalizationMode::Insensitive,
                      "case-insensitive APFS is necessarily normalization-insensitive");
        ok &= Require(folded.UsesHashedDirectoryKeys(),
                      "case-insensitive APFS uses hashed directory keys");
    }
    return ok;
}

bool TestUtf8ValidationAndRoundTrip()
{
    bool ok = true;
    const auto exact = ApfsNamePolicy::FromIncompatibleFeatures(0);
    const auto folded = ApfsNamePolicy::FromIncompatibleFeatures(kCaseInsensitive);
    ok &= RoundTrips(Bytes("report.txt"), folded, "ASCII");
    ok &= RoundTrips(Bytes({0xe6, 0x96, 0x87, 0xe4, 0xbb, 0xb6}), folded, "BMP");
    ok &= RoundTrips(Bytes({0xf0, 0x9f, 0x98, 0x80, '.', 't', 'x', 't'}), folded, "non-BMP");

    const std::vector<std::vector<std::byte>> invalid = {
        Bytes({0xc0, 0xaf}),
        Bytes({0xe2, 0x82}),
        Bytes({0xed, 0xa0, 0x80}),
        Bytes({0xf4, 0x90, 0x80, 0x80}),
        Bytes({'a', 0x00, 'b'}),
        Bytes({'a', '/', 'b'}),
    };
    for (std::size_t index = 0; index < invalid.size(); ++index)
    {
        const auto result = ApfsNameCodec::Decode(invalid[index], folded);
        ok &= Require(!result.ok(), "invalid UTF-8/name vector " + std::to_string(index));
    }

    const auto unicode14Only = ApfsNameCodec::Decode(
        Bytes({0xf0, 0x9f, 0xab, 0xa0}), folded);
    ok &= Require(!unicode14Only.ok(), "post-Unicode-9 code point rejected");
    ok &= Require(unicode14Only.error == ApfsNameError::UnassignedCodePoint,
                  "unassigned code point has stable error");

    const auto empty = ApfsNameCodec::Decode({}, exact);
    ok &= Require(!empty.ok() && empty.error == ApfsNameError::InvalidApfsName,
                  "empty APFS component rejected");
    const auto dot = ApfsNameCodec::Decode(Bytes("."), exact);
    const auto dotdot = ApfsNameCodec::Decode(Bytes(".."), exact);
    ok &= Require(!dot.ok() && !dotdot.ok(), "dot components rejected");

    const auto maxName = ApfsNameCodec::Decode(Bytes(std::string(255, 'a')), exact);
    const auto longName = ApfsNameCodec::Decode(Bytes(std::string(256, 'a')), exact);
    ok &= Require(maxName.ok(), "255-byte APFS component accepted");
    ok &= Require(!longName.ok() && longName.error == ApfsNameError::NameTooLong,
                  "256-byte APFS component rejected");
    return ok;
}

bool TestLookupSemantics()
{
    bool ok = true;
    const auto exact = ApfsNamePolicy::FromIncompatibleFeatures(0);
    const auto normalized = ApfsNamePolicy::FromIncompatibleFeatures(
        kNormalizationInsensitive);
    const auto folded = ApfsNamePolicy::FromIncompatibleFeatures(kCaseInsensitive);
    const auto composed = Bytes({0xc3, 0xa9});
    const auto decomposed = Bytes({'e', 0xcc, 0x81});

    const auto composedExact = ApfsNameCodec::Decode(composed, exact);
    const auto decomposedExact = ApfsNameCodec::Decode(decomposed, exact);
    ok &= Require(composedExact.ok() && decomposedExact.ok(),
                  "normalization-sensitive vectors decode");
    if (composedExact.ok() && decomposedExact.ok())
    {
        ok &= Require(composedExact.value->lookup_key != decomposedExact.value->lookup_key,
                      "normalization-sensitive APFS preserves byte-distinct lookup keys");
        ok &= Require(!composedExact.value->directory_hash.has_value() &&
                          !decomposedExact.value->directory_hash.has_value(),
                      "normalization-sensitive APFS has no directory hash");
    }

    const auto composedNormalized = ApfsNameCodec::Decode(composed, normalized);
    const auto decomposedNormalized = ApfsNameCodec::Decode(decomposed, normalized);
    ok &= Require(composedNormalized.ok() && decomposedNormalized.ok() &&
                      composedNormalized.value->lookup_key == decomposedNormalized.value->lookup_key,
                  "normalization-insensitive APFS equates NFC and NFD");
    if (composedNormalized.ok())
    {
        ok &= Require(LookupString(*composedNormalized.value) ==
                          std::string("e\xcc\x81", 3),
                      "normalization-insensitive key is Unicode-9 NFD");
    }

    const auto upperSensitive = ApfsNameCodec::Decode(Bytes("File"), normalized);
    const auto lowerSensitive = ApfsNameCodec::Decode(Bytes("file"), normalized);
    const auto upperInsensitive = ApfsNameCodec::Decode(Bytes("File"), folded);
    const auto lowerInsensitive = ApfsNameCodec::Decode(Bytes("file"), folded);
    ok &= Require(upperSensitive.ok() && lowerSensitive.ok() &&
                      upperSensitive.value->lookup_key != lowerSensitive.value->lookup_key,
                  "case-only siblings remain distinct on case-sensitive APFS");
    ok &= Require(upperInsensitive.ok() && lowerInsensitive.ok() &&
                      upperInsensitive.value->lookup_key == lowerInsensitive.value->lookup_key,
                  "case-only spellings collide on case-insensitive APFS");

    const auto sharpS = ApfsNameCodec::Decode(Bytes({0xe1, 0xba, 0x9e}), folded);
    ok &= Require(sharpS.ok() && LookupString(*sharpS.value) == "ss",
                  "Unicode-9 full fold wins over the simple sharp-S mapping");

    const auto strasse = ApfsNameCodec::Decode(
        Bytes({'S', 't', 'r', 'a', 0xc3, 0x9f, 'e'}), folded);
    const auto uppercase = ApfsNameCodec::Decode(Bytes("STRASSE"), folded);
    ok &= Require(strasse.ok() && uppercase.ok() &&
                      strasse.value->lookup_key == uppercase.value->lookup_key,
                  "German sharp-s uses full case folding");

    const auto sigma = ApfsNameCodec::Decode(Bytes({0xce, 0xa3}), folded);
    const auto finalSigma = ApfsNameCodec::Decode(Bytes({0xcf, 0x82}), folded);
    ok &= Require(sigma.ok() && finalSigma.ok() &&
                      sigma.value->lookup_key == finalSigma.value->lookup_key,
                  "Greek sigma variants fold together");

    const auto latinI = ApfsNameCodec::Decode(Bytes("I"), folded);
    const auto latinSmallI = ApfsNameCodec::Decode(Bytes("i"), folded);
    const auto dottedI = ApfsNameCodec::Decode(Bytes({0xc4, 0xb0}), folded);
    const auto dotlessI = ApfsNameCodec::Decode(Bytes({0xc4, 0xb1}), folded);
    ok &= Require(latinI.ok() && latinSmallI.ok() &&
                      latinI.value->lookup_key == latinSmallI.value->lookup_key,
                  "default Unicode fold is locale independent");
    ok &= Require(dottedI.ok() && dotlessI.ok() &&
                      dottedI.value->lookup_key != latinSmallI.value->lookup_key &&
                      dotlessI.value->lookup_key != latinSmallI.value->lookup_key,
                  "Turkish dotted and dotless I remain distinct under default fold");
    return ok;
}

bool TestDirectoryRecordHashes()
{
    bool ok = true;
    const auto normalized = ApfsNamePolicy::FromIncompatibleFeatures(
        kNormalizationInsensitive);
    const auto folded = ApfsNamePolicy::FromIncompatibleFeatures(kCaseInsensitive);

    const auto hello = ApfsNameCodec::Decode(Bytes("hello"), normalized);
    const auto file = ApfsNameCodec::Decode(Bytes("File"), folded);
    const auto composed = ApfsNameCodec::Decode(Bytes({0xc3, 0xa9}), normalized);
    ok &= Require(hello.ok() && hello.value->directory_hash == 0x31ebb3u,
                  "known APFS hash for hello");
    ok &= Require(file.ok() && file.value->directory_hash == 0x0e7c61u,
                  "known case-folded APFS hash for File");
    ok &= Require(composed.ok() && composed.value->directory_hash == 0x1d765fu,
                  "known decomposed APFS hash for composed e-acute");

    const std::vector<std::uint32_t> helloScalars = {'h', 'e', 'l', 'l', 'o'};
    const std::vector<std::uint32_t> fileScalars = {'f', 'i', 'l', 'e'};
    const std::vector<std::uint32_t> eAcuteScalars = {'e', 0x0301};
    ok &= Require(IndependentCrc32c(helloScalars) == 0x31ebb3u,
                  "independent bitwise CRC confirms hello vector");
    ok &= Require(IndependentCrc32c(fileScalars) == 0x0e7c61u,
                  "independent bitwise CRC confirms File vector");
    ok &= Require(IndependentCrc32c(eAcuteScalars) == 0x1d765fu,
                  "independent bitwise CRC confirms e-acute vector");

    if (hello.ok())
    {
        const auto packed = (0x31ebb3u << 10) | 6u;
        ok &= Require(ApfsNameCodec::MatchesHashedDirectoryKey(*hello.value, packed),
                      "hashed directory key validates hash and NUL-inclusive length");
        ok &= Require(!ApfsNameCodec::MatchesHashedDirectoryKey(*hello.value, packed ^ (1u << 10)),
                      "hashed directory key rejects wrong hash");
        ok &= Require(!ApfsNameCodec::MatchesHashedDirectoryKey(*hello.value, packed + 1u),
                      "hashed directory key rejects wrong length");
    }
    return ok;
}

bool TestWindowsProjection()
{
    bool ok = true;
    const auto exact = ApfsNamePolicy::FromIncompatibleFeatures(0);
    const std::vector<std::vector<std::byte>> escaped = {
        Bytes("CON"),
        Bytes("con.txt"),
        Bytes("CONIN$"),
        Bytes("conout$.log"),
        Bytes({'C', 'O', 'M', 0xc2, 0xb2, '.', 't', 'x', 't'}),
        Bytes("name:stream"),
        Bytes("trailing."),
        Bytes("trailing "),
        Bytes({'c', 't', 'l', 0x01}),
        Bytes("back\\slash"),
        Bytes("wild*card"),
        Bytes("~APFS~literal"),
        Bytes("~apfs~case-insensitive-prefix"),
    };
    for (std::size_t index = 0; index < escaped.size(); ++index)
    {
        const auto decoded = ApfsNameCodec::Decode(escaped[index], exact);
        ok &= Require(decoded.ok(), "escaped vector decodes " + std::to_string(index));
        if (!decoded.ok())
        {
            continue;
        }
        const auto& display = decoded.value->windows_display;
        ok &= Require(display.rfind(ApfsNameCodec::EscapePrefix(), 0) == 0,
                      "unsafe name uses escape prefix " + std::to_string(index));
        const auto encoded = ApfsNameCodec::EncodeWindowsName(display);
        ok &= Require(encoded.ok() && *encoded.value == String(escaped[index]),
                      "unsafe name round-trips " + std::to_string(index));
    }

    const auto safe = ApfsNameCodec::Decode(Bytes("Quarterly Report.txt"), exact);
    ok &= Require(safe.ok() && safe.value->windows_display == L"Quarterly Report.txt",
                  "safe Windows name stays literal");
    const auto middlePrefix = ApfsNameCodec::Decode(Bytes("middle~APFS~literal"), exact);
    ok &= Require(middlePrefix.ok() &&
                      middlePrefix.value->windows_display == L"middle~APFS~literal",
                  "escape marker is reserved only at component start");

    const auto upperDevice = ApfsNameCodec::Decode(Bytes("CON"), exact);
    const auto lowerDevice = ApfsNameCodec::Decode(Bytes("con"), exact);
    ok &= Require(upperDevice.ok() && lowerDevice.ok() &&
                      !EqualsOrdinalIgnoreCase(
                          upperDevice.value->windows_display,
                          lowerDevice.value->windows_display),
                  "case-distinct unsafe names remain distinct to Windows");

    const std::vector<std::wstring> ambiguous = {
        L"~APFS~",
        L"~APFS~GG",
        L"~APFS~\u4e01\u5e40",
        L"~apfs~434f4e",
        L"name:stream",
        L"trailing.",
        L"CON",
        L".",
        L"..",
        L"",
    };
    for (std::size_t index = 0; index < ambiguous.size(); ++index)
    {
        const auto encoded = ApfsNameCodec::EncodeWindowsName(ambiguous[index]);
        ok &= Require(!encoded.ok(), "ambiguous Windows input rejected " + std::to_string(index));
    }

    std::wstring invalidSurrogate;
    invalidSurrogate.push_back(static_cast<wchar_t>(0xd800));
    const auto invalidWide = ApfsNameCodec::EncodeWindowsName(invalidSurrogate);
    ok &= Require(!invalidWide.ok() && invalidWide.error == ApfsNameError::InvalidWindowsName,
                  "unpaired UTF-16 surrogate rejected");

    const auto worstCase = Bytes(std::string(255, ':'));
    const auto projectedWorstCase = ApfsNameCodec::Decode(worstCase, exact);
    ok &= Require(projectedWorstCase.ok() &&
                      projectedWorstCase.value->windows_display.size() <= 255,
                  "maximum APFS name projects within Windows component limit");
    return ok;
}

bool TestProjectedNameInjectivity()
{
    bool ok = true;
    const auto exact = ApfsNamePolicy::FromIncompatibleFeatures(0);
    std::mt19937_64 random(0x415046534e414d45ull);
    std::vector<std::wstring> displays;
    std::unordered_set<std::string> rawNames;

    while (displays.size() < 256)
    {
        constexpr std::string_view kValidPayload =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::string raw = "unsafe:";
        const auto length = 1u + static_cast<unsigned int>(random() % 48u);
        for (unsigned int index = 0; index < length; ++index)
        {
            raw.push_back(kValidPayload[random() % kValidPayload.size()]);
        }
        if (!rawNames.insert(raw).second)
        {
            continue;
        }
        const auto decoded = ApfsNameCodec::Decode(Bytes(raw), exact);
        if (!Require(decoded.ok(), "random projected name decodes"))
        {
            return false;
        }
        const auto encoded = ApfsNameCodec::EncodeWindowsName(decoded.value->windows_display);
        ok &= Require(encoded.ok() && *encoded.value == raw,
                      "random projected name round-trips");
        displays.push_back(decoded.value->windows_display);
    }

    for (std::size_t left = 0; left < displays.size(); ++left)
    {
        for (std::size_t right = left + 1; right < displays.size(); ++right)
        {
            if (EqualsOrdinalIgnoreCase(displays[left], displays[right]))
            {
                ok &= Require(false,
                              "distinct escaped APFS names cannot collide under Windows ordinal ignore-case");
                return ok;
            }
        }
    }
    return ok;
}

bool TestCanonicalPathKeys()
{
    bool ok = true;
    const auto exact = ApfsNamePolicy::FromIncompatibleFeatures(0);
    const auto normalized = ApfsNamePolicy::FromIncompatibleFeatures(
        kNormalizationInsensitive);
    const auto folded = ApfsNamePolicy::FromIncompatibleFeatures(kCaseInsensitive);

    const auto upperExact = ApfsNameCodec::CanonicalWindowsPathKey(
        L"\\Docs\\File.txt", exact);
    const auto lowerExact = ApfsNameCodec::CanonicalWindowsPathKey(
        L"/Docs//file.txt/", exact);
    ok &= Require(upperExact.ok() && lowerExact.ok() &&
                      *upperExact.value != *lowerExact.value,
                  "case-sensitive path keys preserve case-only siblings");

    const auto upperFolded = ApfsNameCodec::CanonicalWindowsPathKey(
        L"\\Docs\\File.txt", folded);
    const auto lowerFolded = ApfsNameCodec::CanonicalWindowsPathKey(
        L"/docs//file.txt/", folded);
    ok &= Require(upperFolded.ok() && lowerFolded.ok() &&
                      *upperFolded.value == *lowerFolded.value,
                  "case-insensitive path keys fold every component");

    const auto composed = ApfsNameCodec::CanonicalWindowsPathKey(
        L"\\caf\u00e9", normalized);
    const auto decomposed = ApfsNameCodec::CanonicalWindowsPathKey(
        L"\\cafe\u0301", normalized);
    ok &= Require(composed.ok() && decomposed.ok() &&
                      *composed.value == *decomposed.value,
                  "normalization-insensitive path keys match NFC and NFD");

    const auto root = ApfsNameCodec::CanonicalWindowsPathKey(L"\\", exact);
    ok &= Require(root.ok() && *root.value == L"\\",
                  "root has one stable canonical key");
    const auto invalid = ApfsNameCodec::CanonicalWindowsPathKey(L"\\CON", exact);
    ok &= Require(!invalid.ok(),
                  "non-projected unsafe Windows component is rejected");
    return ok;
}

bool TestCanonicalWindowsComponentKeys()
{
    bool ok = true;
    const auto exact = ApfsNamePolicy::FromIncompatibleFeatures(0);
    const auto folded = ApfsNamePolicy::FromIncompatibleFeatures(kCaseInsensitive);
    const auto exactUpper = ApfsNameCodec::CanonicalWindowsComponentKey(L"File", exact);
    const auto exactLower = ApfsNameCodec::CanonicalWindowsComponentKey(L"file", exact);
    const auto foldedUpper = ApfsNameCodec::CanonicalWindowsComponentKey(L"File", folded);
    const auto foldedLower = ApfsNameCodec::CanonicalWindowsComponentKey(L"file", folded);
    ok &= Require(exactUpper.ok() && exactLower.ok() &&
                      *exactUpper.value != *exactLower.value,
                  "case-sensitive Windows component keys remain distinct");
    ok &= Require(foldedUpper.ok() && foldedLower.ok() &&
                      *foldedUpper.value == *foldedLower.value,
                  "case-insensitive Windows component keys fold identically");

    const auto reserved = ApfsNameCodec::Decode(Bytes("CON"), exact);
    if (Require(reserved.ok(), "reserved name projects for key test"))
    {
        const auto key = ApfsNameCodec::CanonicalWindowsComponentKey(
            reserved.value->windows_display, exact);
        ok &= Require(key.ok(), "canonical key accepts valid escaped projection");
    }
    return ok;
}
} // namespace

int main()
{
    bool ok = true;
    ok &= TestPolicyDerivation();
    ok &= TestUtf8ValidationAndRoundTrip();
    ok &= TestLookupSemantics();
    ok &= TestDirectoryRecordHashes();
    ok &= TestWindowsProjection();
    ok &= TestProjectedNameInjectivity();
    ok &= TestCanonicalPathKeys();
    ok &= TestCanonicalWindowsComponentKeys();
    if (ok)
    {
        std::cout << "APFS NAME CODEC PASS" << std::endl;
        return 0;
    }
    std::cerr << "APFS NAME CODEC FAIL: " << g_failures << " check(s)" << std::endl;
    return 1;
}
