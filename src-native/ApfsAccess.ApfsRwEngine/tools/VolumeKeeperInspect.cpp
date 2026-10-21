#include "VolumeKeeperAdmission.h"
#include <charconv>
#include <iostream>
#include <map>
#include <stdexcept>
using namespace apfsaccess::rw;
int wmain(int argc, wchar_t** argv)
{
    VolumeKeeperAdmission result;
    try {
        std::map<std::wstring, std::wstring> args;
        for (int i = 1; i < argc; ++i) {
            const std::wstring key = argv[i];
            if (++i >= argc || (key != L"--image" && key != L"--offset" && key != L"--journal-directory") ||
                !args.emplace(key, argv[i]).second) throw std::runtime_error("unknown, duplicate or incomplete option");
        }
        if (args.size() != 3) throw std::runtime_error("--image, --offset and --journal-directory required");
        const auto& wide = args.at(L"--offset");
        if (wide.empty() || wide.find_first_not_of(L"0123456789") != std::wstring::npos) throw std::runtime_error("canonical decimal offset required");
        std::string text; for (const auto c : wide) text += static_cast<char>(c); std::uint64_t offset{};
        const auto parsed = std::from_chars(text.data(), text.data() + text.size(), offset);
        if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() || std::to_string(offset) != text)
            throw std::runtime_error("canonical decimal offset required");
        result = InspectVolumeKeeperImage(args.at(L"--image"), offset, args.at(L"--journal-directory"));
    } catch (const std::exception& ex) {
        result.error = std::string("invalid-arguments:") + ex.what(); std::cout << VolumeKeeperAdmissionJson(result) << std::endl; return 2;
    }
    std::cout << VolumeKeeperAdmissionJson(result) << std::endl; return result.admitted ? 0 : 1;
}
