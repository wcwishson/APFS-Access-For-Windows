#pragma once
#include <Windows.h>
#include <compressapi.h>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace apfsaccess::rw::fusion_continuation {
using Bytes = std::vector<std::byte>;
inline constexpr std::size_t PlainLimit = (8u << 20) - 4096;
inline constexpr std::uint64_t PackedMagic = 0x315a434e4f495346ULL;
inline constexpr std::size_t HeaderSize = 24;

class Codec final {
public:
    Codec() : module_(LoadLibraryExW(L"cabinet.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32)) {
        if (!module_) return;
        create_compressor = Symbol<decltype(create_compressor)>("CreateCompressor");
        close_compressor = Symbol<decltype(close_compressor)>("CloseCompressor");
        compress = Symbol<decltype(compress)>("Compress");
        create_decompressor = Symbol<decltype(create_decompressor)>("CreateDecompressor");
        close_decompressor = Symbol<decltype(close_decompressor)>("CloseDecompressor");
        decompress = Symbol<decltype(decompress)>("Decompress");
    }
    ~Codec() { if (module_) FreeLibrary(module_); }
    Codec(const Codec&) = delete;
    Codec& operator=(const Codec&) = delete;
    bool Available() const {
        return create_compressor && close_compressor && compress &&
            create_decompressor && close_decompressor && decompress;
    }
    decltype(&::CreateCompressor) create_compressor = nullptr;
    decltype(&::CloseCompressor) close_compressor = nullptr;
    decltype(&::Compress) compress = nullptr;
    decltype(&::CreateDecompressor) create_decompressor = nullptr;
    decltype(&::CloseDecompressor) close_decompressor = nullptr;
    decltype(&::Decompress) decompress = nullptr;
private:
    template<class T> T Symbol(const char* name) { return reinterpret_cast<T>(GetProcAddress(module_, name)); }
    HMODULE module_ = nullptr;
};

inline void Put64(Bytes& bytes, std::size_t at, std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) bytes[at + i] = std::byte((value >> (8 * i)) & 255);
}
inline std::uint64_t Get64(std::span<const std::byte> bytes, std::size_t at) {
    std::uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= std::uint64_t(std::to_integer<unsigned>(bytes[at + i])) << (8 * i);
    return value;
}

// Compression changes only the protected representation. Original WAL bytes
// are recovered exactly before the existing certificate decoder sees them.
inline bool Pack(std::span<const std::byte> plain, Bytes& stored) {
    stored.clear();
    if (plain.empty() || plain.size() > PlainLimit) return false;
    const Codec api;
    if (plain.size() > HeaderSize && api.Available()) {
        COMPRESSOR_HANDLE handle = nullptr;
        if (api.create_compressor(COMPRESS_ALGORITHM_XPRESS_HUFF, nullptr, &handle)) {
            stored.resize(plain.size());
            SIZE_T size = 0;
            const bool compressed = api.compress(handle, plain.data(), plain.size(),
                stored.data() + HeaderSize, stored.size() - HeaderSize, &size) != FALSE;
            api.close_compressor(handle);
            if (compressed && size && size < plain.size() - HeaderSize) {
                stored.resize(HeaderSize + size);
                Put64(stored, 0, PackedMagic);
                Put64(stored, 8, plain.size());
                Put64(stored, 16, size);
                return true;
            }
        }
    }
    stored.assign(plain.begin(), plain.end());
    return true;
}

// Called only after every protected frame has authenticated. All allocations
// remain bounded independently of the codec's embedded uncompressed length.
inline bool Unpack(std::span<const std::byte> stored, Bytes& plain) {
    plain.clear();
    if (stored.empty() || stored.size() > PlainLimit) return false;
    if (stored.size() < 8 || Get64(stored, 0) != PackedMagic) {
        plain.assign(stored.begin(), stored.end());
        return true;
    }
    if (stored.size() <= HeaderSize) return false;
    const auto length = Get64(stored, 8), compressed = Get64(stored, 16);
    if (!length || length > PlainLimit || compressed != stored.size() - HeaderSize ||
        stored.size() >= length) return false;
    const Codec api;
    if (!api.Available()) return false;
    DECOMPRESSOR_HANDLE handle = nullptr;
    if (!api.create_decompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, nullptr, &handle)) return false;
    SIZE_T required = 0;
    const bool queried = api.decompress(handle, stored.data() + HeaderSize,
        static_cast<std::size_t>(compressed), nullptr, 0, &required) != FALSE;
    if (queried || GetLastError() != ERROR_INSUFFICIENT_BUFFER || required != length) {
        api.close_decompressor(handle);
        return false;
    }
    plain.resize(static_cast<std::size_t>(length));
    SIZE_T actual = 0;
    const bool decoded = api.decompress(handle, stored.data() + HeaderSize,
        static_cast<std::size_t>(compressed), plain.data(), plain.size(), &actual) != FALSE;
    api.close_decompressor(handle);
    if (decoded && actual == length) return true;
    plain.clear();
    return false;
}
}
