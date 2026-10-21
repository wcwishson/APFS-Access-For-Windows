#include "../src/VolumePhysicalInstanceInternal.h"
#include <iostream>
#include <stdexcept>

using namespace apfsaccess::rw::physical_instance;
namespace {
unsigned checks = 0;
void Check(bool value) { ++checks; if (!value) throw std::runtime_error("selected instance admission control failed"); }
}
int wmain(int argc, wchar_t** argv)
{
    try {
        if (argc == 3 && std::wstring_view(argv[1]) == L"--metadata") {
            std::wstring instance;
            if (!Selected(argv[2], instance)) { std::cerr << "SelectedWmiAssociationUnavailable\n"; return 1; }
            std::wcout << instance << L'\n'; return 0;
        }
        Check(argc == 1);
        const std::wstring selected = L"\\\\.\\PhysicalDrive42", pnp = L"USBSTOR\\DISK&VEN_FICTIONAL&PROD_STORAGE\\SERIAL42&0";
        Check(DiskNumber(selected) == 42UL);
        Check(DiskNumber(L"\\\\.\\physicaldrive42") == 42UL);
        for (const auto* bad : {L"", L"\\\\.\\PhysicalDrive042", L"\\\\.\\PhysicalDrive-1", L"\\\\.\\PhysicalDrive42x", L"\\\\.\\PhysicalDrive420000000", L"\\\\?\\PhysicalDrive42", L"\\\\.\\PhysicalDrive42\\Partition1"}) Check(!DiskNumber(bad));
        const auto query = QueryText(42);
        Check(query == L"SELECT DeviceID, Index, PNPDeviceID FROM Win32_DiskDrive WHERE Index = 42 AND DeviceID = '\\\\\\\\.\\\\PhysicalDrive42'");
        auto instance = pnp;
        Check(MatchRow(selected, 42, L"\\\\.\\physicaldrive42", instance) && instance == pnp);
        instance = pnp; Check(!MatchRow(selected, 41, selected, instance));
        instance = pnp; Check(!MatchRow(selected, 42, L"\\\\.\\PhysicalDrive41", instance));
        instance = pnp; Check(!MatchRow(L"\\\\.\\PhysicalDrive042", 42, selected, instance));
        instance = L"usbstor\\disk&ven_fictional&prod_storage\\serial42&0";
        Check(MatchRow(selected, 42, selected, instance) && instance == pnp);
        for (const auto* bad : {L"", L"USBSTOR\\ONE", L"USBSTOR\\\\DISK\\SERIAL", L"\\USBSTOR\\DISK\\SERIAL", L"USBSTOR\\DISK\\SERIAL\\", L"USBSTOR\\DISK\\SER:IAL", L"USBSTOR\\DISK\\SER IAL", L"USBSTOR\\DISK\\SER\nIAL"}) { instance = bad; Check(!MatchRow(selected, 42, selected, instance)); }
        instance = L"USBSTOR\\DISK\\" + std::wstring(400, L'X'); Check(!MatchRow(selected, 42, selected, instance));
        STORAGE_DEVICE_NUMBER number{FILE_DEVICE_DISK, 42, 0};
        Check(WholeDisk(number, sizeof(number), 42));
        number.PartitionNumber = MAXDWORD; Check(WholeDisk(number, sizeof(number), 42));
        number.PartitionNumber = 1; Check(!WholeDisk(number, sizeof(number), 42));
        number.PartitionNumber = 0; Check(!WholeDisk(number, sizeof(number), 41));
        Check(!WholeDisk(number, sizeof(number) - 1, 42)); Check(!WholeDisk(number, sizeof(number) + 1, 42));
        number.DeviceType = FILE_DEVICE_CD_ROM; Check(!WholeDisk(number, sizeof(number), 42));
        std::cout << "PASS checks=" << checks << " metadataQueries=0 diskOpens=0 deviceIo=0\n"; return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL checks=" << checks << ' ' << error.what() << '\n'; return 1; }
}
