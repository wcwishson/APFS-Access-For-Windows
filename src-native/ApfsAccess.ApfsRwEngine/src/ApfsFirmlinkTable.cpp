#include "ApfsFirmlinkTable.h"
#include <set>
#include <string_view>

namespace apfsaccess::rw
{
bool ParseAppleFirmlinkTable(std::span<const std::byte> bytes,
    std::vector<FirmlinkTablePathPair>& out,std::string& error)
{
    out.clear();error.clear();
    const auto fail=[&](const char* reason){error=reason;return false;};
    if(bytes.empty()||bytes.size()>65536)return fail("FirmlinkTableSizeInvalid");
    const std::string_view text(reinterpret_cast<const char*>(bytes.data()),bytes.size());
    if(text.back()!='\n')return fail("FirmlinkTableLineTerminatorUnsupported");
    const auto path=[](std::string_view value){
        if(value.empty()||value.size()>2048||value.front()=='/'||value.back()=='/')return false;
        std::size_t at=0;unsigned parts=0;
        while(at<value.size()){
            auto end=value.find('/',at);if(end==std::string_view::npos)end=value.size();
            const auto component=value.substr(at,end-at);
            if(++parts>64||component.empty()||component.size()>255||component=="."||component=="..")return false;
            for(unsigned char c:component)if(c<0x21||c>0x7e)return false;
            at=end+1;
        }
        return true;
    };
    std::vector<FirmlinkTablePathPair> pairs;std::set<std::string> sources;
    for(std::size_t at=0;at<text.size();){
        const auto end=text.find('\n',at);const auto line=text.substr(at,end-at);at=end+1;
        const auto tab=line.find('\t');
        if(tab==std::string_view::npos||tab==0||line.find('\t',tab+1)!=std::string_view::npos||line.front()!='/')
            return fail("FirmlinkTableColumnsUnsupported");
        const auto system=line.substr(0,tab),data=line.substr(tab+1);
        if(!path(system.substr(1))||!path(data))return fail("FirmlinkTablePathUnsupported");
        if(system.substr(1)!=data)return fail("FirmlinkTableNonMirroredPathUnsupported");
        if(pairs.size()==1024||!sources.emplace(system).second)return fail("FirmlinkTableDuplicateOrLimit");
        pairs.push_back({std::string(system),std::string(data)});
    }
    out=std::move(pairs);return true;
}
}
