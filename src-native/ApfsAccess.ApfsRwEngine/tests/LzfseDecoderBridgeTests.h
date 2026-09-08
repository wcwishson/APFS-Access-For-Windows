#pragma once
#include "apfsaccess_lzfse.h"
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string_view>
#include <utility>
#include <vector>

// Register with: failures += RunLzfseDecoderBridgeTests();
// Frozen FSE fixtures are official-encoder roundtrips, not independent Apple
// corpus. See third_party/lzfse/LZFSE-PROVENANCE.md for exact reproduction.
inline int RunLzfseDecoderBridgeTests()
{
    using B = std::vector<std::uint8_t>;
    int failures = 0;
    auto check = [&](bool ok, const char* label) {
        if (!ok) { ++failures; std::cerr << "[FAIL] LZFSE bridge: " << label << '\n'; }
    };
    auto hex = [](std::string_view h) {
        B b;
        auto nibble = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
        for (std::size_t i = 0; i < h.size(); i += 2)
            b.push_back(static_cast<std::uint8_t>(nibble(h[i])*16+nibble(h[i+1])));
        return b;
    };
    auto u32 = [](B& b, std::size_t p, std::uint32_t n) {
        for (unsigned i=0; i<4; ++i) b.at(p+i)=static_cast<std::uint8_t>(n>>(8*i));
    };
    const B eos = hex("62767824");
    const B raw = hex("6276782d0500000068656c6c6f62767824");
    const B hello = hex("68656c6c6f");
    const B lzvn = hex("6276786e050000000e000000e568656c6c6f060000000000000062767824");
    const B v2 = hex(
        "62767832002000004400e0020005000051b955f7ac110060b00000003cbc400fefc01500000000575700000000f01bbc20bf01000000fc060000000000000000000000000000dc0100000000f0370000000077777777776fc0dddddddd1d0000dcdd01700700777700dc01c01bf006bc013fc3cf7077777777f706dcddbd015fc1dddd1bf006dcbd017777777777000000000000000000000000000000000000000000000000000000000000000000000000c008aa0922b277000e233a59356a0c62b1de7d7f280564d93d6ffaff56dd4e742a2fc2762a345762e42ba5010000000000000000c06ffd7fff7ffcff6062767824");
    B v1 = hex("62767831002000003f00000044000000050000002e00000011000000f9ffffff51016e017503b302ffffffff3c002f00f400");
    v1.resize(772);
    const std::pair<unsigned,unsigned> frequencies[] = {
        {0,38},{1,13},{19,13},{20,13},{39,51},{40,154},{41,51},{56,51},
        {114,15},{136,79},{152,15},{153,15},{154,15},{155,15},{156,15},{157,30},
        {158,15},{159,15},{160,15},{161,15},{162,15},{173,15},{174,15},{180,15},
        {187,15},{188,15},{194,15},{201,30},{202,30},{203,30},{204,75},{205,75},
        {206,15},{207,15},{208,15},{209,15},{210,15},{211,30},{212,15},{213,15},
        {214,30},{215,45},{216,15},{217,15},{218,30},{219,30},{220,15},{221,30},
        {222,15},{223,15},{224,15},{225,15},{226,15}
    };
    for (auto [i,n] : frequencies) { v1[50+2*i]=static_cast<std::uint8_t>(n); v1[51+2*i]=static_cast<std::uint8_t>(n>>8); }
    const B payload = hex("0000c008aa0922b277000e233a59356a0c62b1de7d7f280564d93d6ffaff56dd4e742a2fc2762a345762e42ba5010000000000000000c06ffd7fff7ffcff6062767824");
    v1.insert(v1.end(), payload.begin(), payload.end());
    B plain(8192);
    constexpr std::string_view pattern = "Task5 LZFSE bounded decoder: abcdefghijklmnopqrstuvwxyz 0123456789\n";
    for (std::size_t i=0; i<plain.size(); ++i) plain[i]=static_cast<std::uint8_t>(pattern[i%pattern.size()]);
    const auto stateSize = apfsaccess_lzfse_scratch_size();
    auto decode = [&](const B& input, std::size_t expected, B* output,
                      std::uint64_t work = 1000000, std::size_t stateLimit = 0) {
        B guarded(expected+34, 0xa5), state(stateSize+34, 0x5a);
        const std::uint8_t empty = 0;
        const auto rc = apfsaccess_lzfse_decode_exact(input.empty()? &empty : input.data(),
            input.size(), guarded.data()+17, expected+1, expected, state.data()+17,
            stateLimit ? stateLimit : stateSize, work);
        check(std::all_of(guarded.begin(),guarded.begin()+17,[](auto c){return c==0xa5;}) &&
              std::all_of(guarded.begin()+17+expected,guarded.end(),[](auto c){return c==0xa5;}), "output guards");
        check(std::all_of(state.begin(),state.begin()+17,[](auto c){return c==0x5a;}) &&
              std::all_of(state.begin()+17+stateSize,state.end(),[](auto c){return c==0x5a;}), "unaligned state guards");
        if (output) output->assign(guarded.begin()+17,guarded.begin()+17+expected);
        return rc;
    };
    const std::pair<B,B> cases[] = {{eos,{}},{raw,hello},{lzvn,hello},{v1,plain},{v2,plain}};
    for (const auto& [input,expected] : cases) {
        B result;
        check(decode(input,expected.size(),&result)==APFSACCESS_LZFSE_OK && result==expected,"known bytes");
        for (std::size_t n=0; n<input.size(); ++n)
            check(decode(B(input.begin(),input.begin()+n),expected.size(),nullptr)!=APFSACCESS_LZFSE_OK,"every truncated prefix");
        B trailing=input; trailing.push_back(0);
        check(decode(trailing,expected.size(),nullptr)!=APFSACCESS_LZFSE_OK,"trailing byte");
        trailing=input; trailing.insert(trailing.end(),input.begin(),input.end());
        check(decode(trailing,expected.size(),nullptr)!=APFSACCESS_LZFSE_OK,"concatenated streams");
        check(decode(input,expected.size()+1,nullptr)!=APFSACCESS_LZFSE_OK,"expected size too large");
        if (!expected.empty()) check(decode(input,expected.size()-1,nullptr)!=APFSACCESS_LZFSE_OK,"expected size too small");
        check(decode(input,expected.size(),nullptr,0)==APFSACCESS_LZFSE_LIMIT,"zero work");
        check(decode(input,expected.size(),nullptr,1000000,stateSize-1)==APFSACCESS_LZFSE_LIMIT,"insufficient state");
    }
    check(decode(raw,5,nullptr,7)==APFSACCESS_LZFSE_OK,"exact raw work budget");
    check(decode(raw,5,nullptr,6)==APFSACCESS_LZFSE_LIMIT,"raw work one short");
    check(decode(v2,8192,nullptr,12436)==APFSACCESS_LZFSE_OK,"exact FSE work budget");
    check(decode(v2,8192,nullptr,12435)==APFSACCESS_LZFSE_LIMIT,"FSE work one short");
    B emptyRaw=hex("6276782d0000000062767824");
    check(decode(emptyRaw,0,nullptr)==APFSACCESS_LZFSE_OK,"zero raw block");
    check(decode(hex("6276786e0000000008000000060000000000000062767824"),0,nullptr)==APFSACCESS_LZFSE_OK,"empty LZVN EOS");
    check(decode(hex("6276786e00000000090000000e060000000000000062767824"),0,nullptr)==APFSACCESS_LZFSE_OK,"empty LZVN NOP/EOS");
    B multi=raw; multi.resize(multi.size()-4); multi.insert(multi.end(),lzvn.begin(),lzvn.end());
    B two=hello; two.insert(two.end(),hello.begin(),hello.end()); B actual;
    check(decode(multi,10,&actual)==APFSACCESS_LZFSE_OK && actual==two,"multiple blocks one stream");
    multi=v2; multi.resize(multi.size()-4); multi.insert(multi.end(),v2.begin(),v2.end());
    two=plain; two.insert(two.end(),plain.begin(),plain.end());
    check(decode(multi,two.size(),&actual)==APFSACCESS_LZFSE_OK && actual==two,"consecutive FSE blocks");
    B zeroState(stateSize);
    std::uint8_t zeroDummy=0xa5;
    check(apfsaccess_lzfse_decode_exact(eos.data(),eos.size(),&zeroDummy,0,0,
          zeroState.data(),zeroState.size(),1)==APFSACCESS_LZFSE_OK && zeroDummy==0xa5,
          "EOS with exact zero capacity");
    for (auto length : {0u,31u,32u,753u,0xffffffffu}) {
        B bad=v2; u32(bad,24,length);
        check(decode(bad,8192,nullptr)!=APFSACCESS_LZFSE_OK,"bad v2 header length/tables");
    }
    for (auto offset : {4u,8u,12u,16u,20u,24u,28u,32u,40u,44u,46u,48u,50u,90u,130u,258u}) {
        B bad=v1; u32(bad,offset,offset==40 ? 1u : 0xffffffffu);
        check(decode(bad,8192,nullptr)!=APFSACCESS_LZFSE_OK,"corrupt v1 count/state/frequency");
    }
    B bad=v1; bad[50]=0;
    check(decode(bad,8192,nullptr)!=APFSACCESS_LZFSE_OK,"underfull frequency table");
    bad=v1; u32(bad,4,8191);
    check(decode(bad,8192,nullptr)!=APFSACCESS_LZFSE_OK,"block output mismatch");
    bad=v1; bad[772+46]=1;
    check(decode(bad,8192,nullptr)!=APFSACCESS_LZFSE_OK,"nonzero LMD padding");
    // Structurally valid constant-symbol FSE tables, M=1 without history.
    for (unsigned distanceSymbol : {0u,1u}) {
        B distance(780); u32(distance,0,0x31787662); u32(distance,4,1);
        u32(distance,8,8); u32(distance,16,1); u32(distance,24,8);
        distance[50]=64; distance[50+2*21]=64;
        distance[51+2*(40+distanceSymbol)]=1; distance[51+2*(104+65)]=4;
        distance.insert(distance.end(),eos.begin(),eos.end());
        check(decode(distance,1,nullptr)!=APFSACCESS_LZFSE_OK,"FSE bad previous/forward distance");
    }
    for (const auto h : {"6276786e0100000009000000f1060000000000000062767824",
                          "6276786e030000000a0000000000060000000000000062767824",
                          "6276786e030000000a0000000001060000000000000062767824"})
        check(decode(hex(h),h[9]=='1'?1:3,nullptr)!=APFSACCESS_LZFSE_OK,"LZVN bad match distances");
    B state(stateSize), target(16), source=raw;
    check(apfsaccess_lzfse_decode_exact(source.data(),source.size(),source.data(),source.size(),5,state.data(),stateSize,1000)==APFSACCESS_LZFSE_ARGUMENT,"overlap refused");
    check(apfsaccess_lzfse_decode_exact(source.data(),source.size(),target.data(),4,5,state.data(),stateSize,1000)==APFSACCESS_LZFSE_ARGUMENT,"short output capacity");
    check(apfsaccess_lzfse_decode_exact(source.data(),(std::numeric_limits<std::size_t>::max)(),target.data(),16,5,state.data(),stateSize,1000)==APFSACCESS_LZFSE_ARGUMENT,"size overflow");
    check(apfsaccess_lzfse_decode_exact(nullptr,0,target.data(),16,0,state.data(),stateSize,1000)==APFSACCESS_LZFSE_ARGUMENT,"null input");
    // Mutation sweep checks safety/termination only: this format has no checksum
    // and a changed payload can be a different valid stream.
    for (std::size_t i=0;i<v2.size();++i) for (unsigned bit=0;bit<8;++bit) {
        B mutation=v2; mutation[i]^=static_cast<std::uint8_t>(1u<<bit);
        (void)decode(mutation,8192,nullptr,20000);
    }
    return failures;
}
