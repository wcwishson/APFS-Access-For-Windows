#pragma once
#include <windows.h>
#include <winioctl.h>
#include <wbemidl.h>
#include <algorithm>
#include <optional>
#include <string>
#include <string_view>

namespace apfsaccess::rw::physical_instance
{
template<class T> class Com
{
    T* pointer_ = nullptr;
public:
    Com() = default;
    Com(const Com&) = delete;
    ~Com() { if (pointer_) pointer_->Release(); }
    T* Get() const { return pointer_; }
    T** Put() { return &pointer_; }
    T* operator->() const { return pointer_; }
    explicit operator bool() const { return pointer_ != nullptr; }
    void Attach(T* value) { pointer_ = value; }
};
inline std::optional<DWORD> DiskNumber(std::wstring_view path)
{
    constexpr std::wstring_view prefix = L"\\\\.\\PhysicalDrive";
    if (path.size() <= prefix.size() || path.size() > prefix.size() + 8 ||
        CompareStringOrdinal(path.data(), static_cast<int>(prefix.size()), prefix.data(), static_cast<int>(prefix.size()), TRUE) != CSTR_EQUAL) return {};
    DWORD number = 0;
    for (const auto c : path.substr(prefix.size())) { if (c < L'0' || c > L'9') return {}; number = number * 10 + c - L'0'; }
    if (path.substr(prefix.size()) != std::to_wstring(number)) return {};
    return number;
}
inline bool Normalize(std::wstring& instance)
{
    if (instance.empty() || instance.size() > 400 || instance.front() == L'\\' || instance.back() == L'\\' || instance.find(L':') != instance.npos) return false;
    const auto first = instance.find(L'\\');
    if (first == instance.npos || instance.find(L'\\', first + 1) == instance.npos || instance.find(L"\\\\") != instance.npos) return false;
    for (auto& c : instance) { if (c < 33 || c > 126) return false; if (c >= L'a' && c <= L'z') c -= L'a' - L'A'; }
    return true;
}
inline bool WholeDisk(const STORAGE_DEVICE_NUMBER& number, DWORD bytes, DWORD expected)
{
    return bytes == sizeof(number) && number.DeviceType == FILE_DEVICE_DISK && number.DeviceNumber == expected &&
        (number.PartitionNumber == 0 || number.PartitionNumber == MAXDWORD);
}
inline bool MatchRow(std::wstring_view selected, DWORD index, std::wstring_view device, std::wstring& instance)
{
    const auto expected = DiskNumber(selected), actual = DiskNumber(device);
    return expected && actual && *expected == index && *actual == index && Normalize(instance);
}
inline std::wstring QueryText(DWORD number)
{
    const auto path = L"\\\\.\\PhysicalDrive" + std::to_wstring(number);
    std::wstring escaped;
    for (const auto c : path) { if (c == L'\\') escaped += L'\\'; escaped += c; }
    return L"SELECT DeviceID, Index, PNPDeviceID FROM Win32_DiskDrive WHERE Index = " + std::to_wstring(number) + L" AND DeviceID = '" + escaped + L"'";
}
// WMI associates only the explicitly selected alias. It is metadata, never held-source authority.
inline bool Selected(std::wstring_view selected, std::wstring& instance)
{
    instance.clear();
    const auto number = DiskNumber(selected); if (!number) return false;
    struct Apartment { HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED); ~Apartment() { if (SUCCEEDED(hr)) CoUninitialize(); } } apartment;
    if (FAILED(apartment.hr) && apartment.hr != RPC_E_CHANGED_MODE) return false;
    Com<IWbemLocator> locator; Com<IWbemServices> services; Com<IEnumWbemClassObject> rows;
    if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, reinterpret_cast<void**>(locator.Put())))) return false;
    struct Text { BSTR value; explicit Text(std::wstring_view text) : value(SysAllocStringLen(text.data(), static_cast<UINT>(text.size()))) {} ~Text() { SysFreeString(value); } };
    const Text scope(L"ROOT\\CIMV2"), language(L"WQL"), query(QueryText(*number));
    if (!scope.value || !language.value || !query.value ||
        FAILED(locator->ConnectServer(scope.value, nullptr, nullptr, nullptr, WBEM_FLAG_CONNECT_USE_MAX_WAIT, nullptr, nullptr, services.Put())) ||
        FAILED(CoSetProxyBlanket(services.Get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE)) ||
        FAILED(services->ExecQuery(language.value, query.value, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, rows.Put()))) return false;
    IWbemClassObject* raw[2]{}; ULONG count = 0;
    const auto status = rows->Next(3000, 2, raw, &count);
    Com<IWbemClassObject> first, second; first.Attach(raw[0]); second.Attach(raw[1]);
    if (status != WBEM_S_FALSE || count != 1 || !first) return false;
    struct Value { VARIANT value{}; ~Value() { VariantClear(&value); } } device, index, pnp;
    if (FAILED(first->Get(L"DeviceID", 0, &device.value, nullptr, nullptr)) || device.value.vt != VT_BSTR || !device.value.bstrVal ||
        FAILED(first->Get(L"Index", 0, &index.value, nullptr, nullptr)) ||
        FAILED(first->Get(L"PNPDeviceID", 0, &pnp.value, nullptr, nullptr)) || pnp.value.vt != VT_BSTR || !pnp.value.bstrVal) return false;
    DWORD disk = 0;
    if (index.value.vt == VT_UI4) disk = index.value.ulVal;
    else if (index.value.vt == VT_I4 && index.value.lVal >= 0) disk = static_cast<DWORD>(index.value.lVal);
    else return false;
    if (SysStringLen(device.value.bstrVal) > 64 || SysStringLen(pnp.value.bstrVal) > 400) return false;
    std::wstring candidate(pnp.value.bstrVal, SysStringLen(pnp.value.bstrVal));
    if (!MatchRow(selected, disk, std::wstring_view(device.value.bstrVal, SysStringLen(device.value.bstrVal)), candidate)) return false;
    instance = std::move(candidate); return true;
}
}
