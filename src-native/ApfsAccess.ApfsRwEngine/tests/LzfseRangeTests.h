#pragma once

void TestLzfseRanges()
{
    const auto raw = Hex("6276782d0500000068656c6c6f62767824");
    const auto lzvn = Hex("6276786e050000000e000000e568656c6c6f060000000000000062767824");
    for (const auto& block : {raw, lzvn})
    {
        const auto attr = Attribute(11, 5, block);
        Expect(attr, 0, kMax, kHelloPlain);
        Expect(attr, 1, 3, Hex("656c6c"));
        Expect(attr, 5, kMax, {});
        Expect(attr, kMax, kMax, {});
        auto bad = block;
        bad.pop_back();
        Reject(Attribute(11, 5, bad), Status::Corrupt);
        bad = block;
        bad.push_back(std::byte{0});
        Reject(Attribute(11, 5, bad), Status::Corrupt);
        Reject(Attribute(11, 4, block), Status::Corrupt);
        ApfsCompressionLimits limits;
        limits.max_lzfse_work_units = 0;
        Reject(attr, Status::LimitExceeded, {}, limits);
        limits = {};
        limits.max_lzfse_state_bytes = 0;
        Reject(attr, Status::LimitExceeded, {}, limits);
    }
    Expect(Attribute(11, 0, Hex("62767824")), 0, 4, {});
    auto first = Hex("6276782d00000100");
    first.insert(first.end(), 65536, std::byte{'A'});
    const auto eos = Hex("62767824");
    first.insert(first.end(), eos.begin(), eos.end());
    Bytes fork(12);
    U32(fork, 0, 12);
    U32(fork, 4, static_cast<std::uint32_t>(12 + first.size()));
    U32(fork, 8, static_cast<std::uint32_t>(12 + first.size() + raw.size()));
    fork.insert(fork.end(), first.begin(), first.end());
    fork.insert(fork.end(), raw.begin(), raw.end());
    unsigned reads = 0;
    ApfsCompressionResourceReader reader{fork.size(), [&](auto at, auto dst) {
        ++reads;
        std::copy_n(fork.begin() + static_cast<std::size_t>(at), dst.size(), dst.begin());
        return dst.size();
    }};
    const auto attr = Attribute(12, 65541);
    Expect(attr, 65534, 7, Hex("414168656c6c6f"), reader);
    Require(reads == 3, "LZFSE crossing range reads table and exactly two blocks");
    reads = 0;
    Expect(attr, 65537, kMax, Hex("656c6c6f"), reader);
    Require(reads == 2, "LZFSE suffix range skips earlier payload");
    ApfsCompressionLimits limits;
    limits.max_lzfse_work_units = 4096 + 16 * (first.size() + 65536);
    Reject(attr, Status::LimitExceeded, reader, limits);
    auto saved = fork.back();
    fork.back() = std::byte{0};
    Reject(attr, Status::Corrupt, reader);
    fork.back() = saved;
    saved = fork[4];
    fork[4] = std::byte{0};
    Reject(attr, Status::Corrupt, reader);
    fork[4] = saved;
}
