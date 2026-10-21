// Raw-device canonical-commit admission: default-closed gates, typed refusals,
// and the store-relative range predicate. No test touches real hardware: the
// only device paths used are malformed spellings (rejected before any open)
// or a nonexistent unit number (open fails fast, fail-closed).
#include "BlockDevice.h"
#include "MetadataStore.h"
#include <iostream>
#include <limits>
#include <stdexcept>

using namespace apfsaccess::rw;

namespace {
std::size_t assertions = 0;
void Check(bool condition, const char* message) {
    ++assertions;
    if (!condition) throw std::runtime_error(message);
}

void RangePredicateMatrix() {
    const std::uint64_t limit = 134217728ull; // 128 MiB container
    Check(BlockDevice::RawWriteRangeAllowed(limit, 0, 1), "first byte allowed");
    Check(BlockDevice::RawWriteRangeAllowed(limit, 0, limit), "whole range allowed");
    Check(BlockDevice::RawWriteRangeAllowed(limit, limit - 4096, 4096), "last block allowed");
    Check(BlockDevice::RawWriteRangeAllowed(limit, limit, 0), "empty span at end allowed");
    Check(!BlockDevice::RawWriteRangeAllowed(limit, limit, 1), "one past end refused");
    Check(!BlockDevice::RawWriteRangeAllowed(limit, limit - 4095, 4096), "one byte over refused");
    Check(!BlockDevice::RawWriteRangeAllowed(limit, limit + 1, 0), "empty span past end refused");
    Check(!BlockDevice::RawWriteRangeAllowed(0, 0, 0), "zero limit refuses everything");
    Check(!BlockDevice::RawWriteRangeAllowed(limit, 0, limit + 1), "oversize span refused");
    Check(!BlockDevice::RawWriteRangeAllowed(limit,
        (std::numeric_limits<std::uint64_t>::max)(), 1), "offset overflow refused");
    Check(!BlockDevice::RawWriteRangeAllowed(limit,
        (std::numeric_limits<std::uint64_t>::max)(),
        (std::numeric_limits<std::uint64_t>::max)()), "full overflow refused");
    Check(!BlockDevice::RawWriteRangeAllowed(4096, 4096, 4096), "second block past 1-block limit refused");
}

void AdmitRefusesMalformedPaths() {
    std::string error;
    {
        BlockDevice file_image(L"D:\\fixture.apfs", 0);
        Check(!file_image.AdmitExclusiveRawWriter(134217728ull, error), "drive-letter path refused");
        Check(error == "RawWriterPathNotPhysicalDrive", "drive-letter refusal is typed");
        Check(!file_image.IsRawWriterAccepted(), "refused device stays unadmitted");
    }
    {
        BlockDevice empty(L"", 0);
        Check(!empty.AdmitExclusiveRawWriter(134217728ull, error), "empty path refused");
        Check(error == "RawWriterPathNotPhysicalDrive", "empty refusal is typed");
    }
    {
        BlockDevice unc(L"\\\\server\\share\\disk.vhd", 0);
        Check(!unc.AdmitExclusiveRawWriter(134217728ull, error), "UNC path refused");
        Check(error == "RawWriterPathNotPhysicalDrive", "UNC refusal is typed");
    }
    {
        BlockDevice bad_limit(L"\\\\.\\PhysicalDrive7", 0);
        Check(!bad_limit.AdmitExclusiveRawWriter(0, error), "zero limit refused");
        Check(error == "RawWriterLimitInvalid", "zero-limit refusal is typed");
        Check(!bad_limit.AdmitExclusiveRawWriter(1, error), "unaligned limit refused");
        Check(error == "RawWriterLimitInvalid", "unaligned-limit refusal is typed");
    }
}

void AdmitRefusesMissingDevice() {
    // Nonexistent unit: open fails fast; no side effects possible.
    BlockDevice missing(L"\\\\.\\PhysicalDrive4294967295", 0);
    std::string error;
    Check(!missing.AdmitExclusiveRawWriter(134217728ull, error), "missing device refused");
    Check(error.rfind("RawWriterSelectedInterfaceUnavailable:", 0) == 0, "missing-device refusal names selected interface metadata");
    Check(!missing.IsRawWriterAccepted(), "failed admission leaves no grant");
    Check(missing.RawWriteLimitBytes() == 0, "failed admission leaves zero limit");
    Check(!missing.IsWritable(), "failed admission leaves device unwritable");
}

void DefaultClosedOnRawPaths() {
    BlockDevice missing(L"\\\\.\\PhysicalDrive4294967295", 0);
    Check(!missing.IsRegularFile(), "missing device is not a regular file");
    Check(!missing.IsRawWriterAccepted(), "raw grant defaults off");
    Check(!missing.IsWritable(), "raw device defaults unwritable");
}

void StoreGateRefusesWithoutOptIn() {
    MetadataStore::VolumeContext context{
        LR"(\\.\PhysicalDrive4294967295)",
        L"RawAdmissionProbe",
    };
    MetadataStore store(std::move(context));
    Check(!store.PrepareNativeWritePath(), "raw path without opt-in refused");
    Check(store.IsRecoveryRequired(), "refused raw path stays fail-closed");
    Check(store.RecoveryReason() == L"NativeAppleTransactionSourceNotRegularFile",
        "default refusal keeps the historical reason");
}

void StoreGateFailsClosedOnMissingDevice() {
    MetadataStore::VolumeContext context{
        LR"(\\.\PhysicalDrive4294967295)",
        L"RawAdmissionProbe",
    };
    context.allow_raw_device_canonical_commit = true;
    MetadataStore store(std::move(context));
    Check(!store.PrepareNativeWritePath(), "opt-in cannot conjure a missing device");
    Check(store.IsRecoveryRequired(), "missing device stays fail-closed");
    Check(store.RecoveryReason() == L"ContainerStateLoadFailed",
        "missing device fails at container load, never at admission");
}
} // namespace

int main() {
    const std::vector<std::pair<const char*, void(*)()>> tests = {
        {"RangePredicateMatrix", RangePredicateMatrix},
        {"AdmitRefusesMalformedPaths", AdmitRefusesMalformedPaths},
        {"AdmitRefusesMissingDevice", AdmitRefusesMissingDevice},
        {"DefaultClosedOnRawPaths", DefaultClosedOnRawPaths},
        {"StoreGateRefusesWithoutOptIn", StoreGateRefusesWithoutOptIn},
        {"StoreGateFailsClosedOnMissingDevice", StoreGateFailsClosedOnMissingDevice},
    };
    std::size_t failed = 0;
    for (const auto& [name, test] : tests) {
        try { test(); std::cout << "PASS " << name << '\n'; }
        catch (const std::exception& e) { ++failed; std::cerr << "FAIL " << name << ": " << e.what() << '\n'; }
    }
    std::cout << tests.size() - failed << '/' << tests.size() << " cases passed; " << assertions << " assertions\n";
    return failed ? 1 : 0;
}
