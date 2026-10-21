#pragma once
#include <cstdint>
#include <iterator>
#include <map>
#include <span>
#include <vector>

namespace apfsaccess::rw::fusion_verify {
// Groups already selected verification destinations; routing and source
// identity remain the read callback's responsibility.
template<class Read,class Visit>
bool Ranges(const std::map<std::uint64_t,std::vector<std::byte>>& blocks,Read&& read,Visit&& visit) {
    for(auto first=blocks.begin();first!=blocks.end();) {
        auto end=std::next(first);std::size_t count=1;
        while(end!=blocks.end()&&count<16&&first->first<=UINT64_MAX-count&&end->first==first->first+count){++end;++count;}
        for(auto p=first;p!=end;++p)if(p->second.size()!=4096)return false;
        std::vector<std::byte> actual;
        if(!read(first->first,count,actual)||actual.size()!=count*4096)return false;
        std::size_t index=0;
        for(auto p=first;p!=end;++p,++index)
            if(!visit(p->first,std::span<const std::byte>(p->second),std::span<const std::byte>(actual).subspan(index*4096,4096)))return false;
        first=end;
    }
    return true;
}
}
