#include "NativeApfsReader.h"
#include "VolumeManagement.h"
#include <iostream>
#include <stdexcept>
using namespace apfsaccess::rw;
int wmain(int argc, wchar_t** argv)
{
    try {
        if (argc != 5) throw std::runtime_error("private root and three completed larger images required");
        unsigned checks = 0;
        for (int i = 2; i < argc; ++i) {
            const std::filesystem::path image(argv[i]);
            const auto observed = ObserveVolumeManagement({image, 0});
            if (!observed.complete || observed.volumes.empty()) throw std::runtime_error("streamed native observation: " + observed.error);
            ++checks; std::string error; auto device = BlockDevice::OpenStableReadOnlyImage(image.wstring(), error);
            if (!device) throw std::runtime_error("fresh ordinary native reader: " + error);
            NativeApfsVolumeProjection view; std::wstring wide_error;
            if (!NativeApfsReader::TryLoadVolumeProjection(*device, observed.volumes.front().oid, view, wide_error))
                throw std::runtime_error("fresh native volume projection refused");
            ++checks;
            if (view.checkpoint_xid != observed.checkpoint_xid || !view.read_extents_by_inode.contains(1030))
                throw std::runtime_error("native inode/checkpoint readback mismatch");
            std::uint64_t read = 0;
            for (const auto& extent : view.read_extents_by_inode.at(1030)) {
                std::vector<std::byte> bytes;
                if (extent.bytes > 8192 || !device->Read(extent.physical_address, static_cast<std::size_t>(extent.bytes), bytes) ||
                    bytes.size() != extent.bytes || !std::all_of(bytes.begin(), bytes.end(), [](auto b) { return b == std::byte{0x59}; }))
                    throw std::runtime_error("fresh native file payload mismatch");
                read += extent.bytes;
            }
            if (read != 8192 || device->HasWriteHandle() || !device->RevalidateStableReadOnlyImage())
                throw std::runtime_error("fresh native stable read scope mismatch");
            ++checks;
        }
        std::cout << "PASS larger image observation and independent native reopen checks=" << checks << '\n'; return 0;
    } catch (const std::exception& ex) { std::cerr << "FAIL " << ex.what() << '\n'; return 1; }
}
