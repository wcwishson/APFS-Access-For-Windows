#pragma once
#include "ApfsFusionStore.h"
#include <sstream>
namespace apfsaccess::fusion_arguments {
struct PublicFailure { const char* name; int exit; };
inline std::uint64_t Number(const std::wstring& text)
{
    if (text.empty()) throw PublicFailure{"InvalidPublicNumber", 2};
    std::uint64_t value = 0;
    for (wchar_t c : text)
    {
        if (c < L'0' || c > L'9' || value > (UINT64_MAX - (c-L'0'))/10)
            throw PublicFailure{"InvalidPublicNumber", 2};
        value = value*10 + c-L'0';
    }
    return value;
}
inline std::string Ascii(const std::wstring& value)
{
    std::string result;
    for (wchar_t c : value)
    {
        if (c < 0x20 || c > 0x7e) throw PublicFailure{"InvalidPublicSelector", 2};
        result.push_back(static_cast<char>(c));
    }
    return result;
}
inline std::string Hex(std::span<const std::byte> bytes) {
    constexpr char digits[]="0123456789abcdef"; std::string out;
    for(auto b:bytes) { const auto n=std::to_integer<unsigned>(b); out+=digits[n>>4];out+=digits[n&15]; } return out;
}
inline std::string Identity(const catalog::FusionImageIdentity& id) {
    return std::to_string(id.volume_serial)+":"+Hex(id.file_id)+":"+std::to_string(id.size_bytes)+":"+
        std::to_string(id.creation_time)+":"+std::to_string(id.write_time);
}
inline catalog::FusionImageIdentity ParseIdentity(const std::wstring& text) {
    std::vector<std::wstring> fields; std::wistringstream input(text); std::wstring part;
    while(std::getline(input,part,L':')) fields.push_back(part);
    if(fields.size()!=5 || text.back()==L':' || fields[1].size()!=32) throw PublicFailure{"InvalidIdentity",2};
    catalog::FusionImageIdentity id;
    id.volume_serial=Number(fields[0]);id.size_bytes=Number(fields[2]);
    id.creation_time=Number(fields[3]);id.write_time=Number(fields[4]);
    auto digit=[](wchar_t c)->unsigned {if(c>=L'0'&&c<=L'9')return c-L'0';if(c>=L'a'&&c<=L'f')return c-L'a'+10;throw PublicFailure{"InvalidIdentity",2};};
    for(unsigned i=0;i<16;++i)id.file_id[i]=std::byte(digit(fields[1][2*i])*16+digit(fields[1][2*i+1]));
    return id;
}
}
