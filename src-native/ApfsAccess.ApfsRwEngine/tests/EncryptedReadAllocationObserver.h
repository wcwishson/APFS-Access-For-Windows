#pragma once
// Include in exactly one test translation unit. No production hook or allocator
// is changed. Inspect live bytes immediately before free; never read freed memory.
#include <algorithm>
#include <stdexcept>
#include <array>
#include <cstdlib>
#include <new>
#include <span>
namespace allocation_observer {
struct Result { unsigned intact = 0, zero = 0, live = 0; bool overflow = false; };
struct State {
    bool armed = false;
    std::size_t size = 0, fail_size = 0;
    unsigned skip_failures = 0, failures = 0;
    std::array<std::byte, 512> expected{};
    std::array<void*, 256> slots{};
    Result result;
};
inline thread_local State state;
inline void Remember(void* p, std::size_t size) noexcept {
    if (!state.armed || size != state.size) return;
    for (auto& slot : state.slots) if (!slot) { slot = p; ++state.result.live; return; }
    state.result.overflow = true;
}
inline void Release(void* p) noexcept {
    if (!p || !state.armed) return;
    for (auto& slot : state.slots) if (slot == p) {
        const auto* bytes = static_cast<const std::byte*>(p);
        bool intact = true, zero = true;
        for (std::size_t i = 0; i < state.size; ++i) {
            intact = intact && bytes[i] == state.expected[i];
            zero = zero && bytes[i] == std::byte{};
        }
        state.result.intact += intact; state.result.zero += zero;
        --state.result.live; slot = nullptr; return;
    }
}
class Watch {
public:
    explicit Watch(std::span<const std::byte> expected) {
        if (state.armed || expected.empty() || expected.size() > state.expected.size())
            throw std::logic_error("invalid allocation observation scope");
        state = {}; state.size = expected.size();
        std::copy(expected.begin(), expected.end(), state.expected.begin()); state.armed = true;
    }
    void FailAllocation(std::size_t size, unsigned skip) noexcept
    { state.fail_size = size; state.skip_failures = skip; }
    unsigned Failures() const noexcept { return state.failures; }
    ~Watch() { state.armed = false; }
    Result Stop() { state.armed = false; return state.result; }
};
}
void* operator new(std::size_t size) {
    auto& watch = allocation_observer::state;
    if (watch.armed && size == watch.fail_size) {
        if (watch.skip_failures) --watch.skip_failures;
        else { watch.fail_size = 0; ++watch.failures; throw std::bad_alloc(); }
    }
    void* p = std::malloc(size ? size : 1);
    if (!p) throw std::bad_alloc();
    allocation_observer::Remember(p, size); return p;
}
void operator delete(void* p) noexcept { allocation_observer::Release(p); std::free(p); }
void operator delete(void* p, std::size_t) noexcept { allocation_observer::Release(p); std::free(p); }
