#pragma once
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <ostream>

// Diagnostic-only fixed storage. Writers never wait for the exporter, allocate,
// format strings, or perform I/O. Names must be static JSON-safe ASCII literals.
// Begin loss is explicit; contended End is retired by the next collector.
class LatencyTrace
{
public:
    static constexpr std::size_t ActiveLimit = 128, HistoryLimit = 512;
    struct Event
    {
        std::uint64_t id = 0, parent = 0, thread = 0, start = 0, end = 0;
        const char* name = "";
        std::array<std::uint64_t, 6> args{};
    };
    struct Snapshot
    {
        std::array<Event, ActiveLimit> active{};
        std::array<Event, HistoryLimit> history{};
        std::uint64_t dropped = 0, completed = 0, tick = 0;
    };
    static std::uint64_t Now() noexcept
    {
        return std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
    std::uint64_t Begin(const char* name, std::uint64_t parent, std::uint64_t thread,
        const std::array<std::uint64_t, 6>& args = {}) noexcept
    {
        std::unique_lock lock(mutex_, std::try_to_lock);
        if (lock.owns_lock())
            for (std::size_t i = 0; i != ActiveLimit; ++i)
                if (!active_[i].id)
                {
                    const auto id = ++next_;
                    active_[i] = {id, parent, thread, Now(), 0, name, args};
                    ended_[i].store(0, std::memory_order_relaxed);
                    return (id << 8) | i;
                }
        dropped_.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
    void End(std::uint64_t token) noexcept
    {
        if (!token) return;
        const auto slot = token & 255;
        // A slot is not reusable until End has published and a locked collector
        // has retired it. This remains exact even when the exporter owns mutex_.
        ended_[slot].store(Now(), std::memory_order_release);
        std::unique_lock lock(mutex_, std::try_to_lock);
        if (lock.owns_lock()) Retire();
    }
    bool Capture(Snapshot& result) noexcept
    {
        std::unique_lock lock(mutex_, std::try_to_lock);
        if (!lock.owns_lock()) return false;
        Retire();
        result = {active_, history_, dropped_.load(std::memory_order_relaxed), completed_, Now()};
        return true;
    }
    static void Write(std::ostream& out, const Snapshot& s)
    {
        out << "{\"schemaVersion\":1,\"clock\":\"steady-us\",\"tickUs\":" << s.tick
            << ",\"activeLimit\":" << ActiveLimit << ",\"historyLimit\":" << HistoryLimit
            << ",\"droppedBegins\":" << s.dropped << ",\"completed\":" << s.completed;
        const auto events = [&](const char* key, const auto& values) {
            out << ",\"" << key << "\":[";
            bool first = true;
            for (const auto& e : values) if (e.id)
            {
                if (!first) out << ',';
                first = false;
                out << "{\"id\":" << e.id << ",\"parent\":" << e.parent << ",\"thread\":" << e.thread
                    << ",\"name\":\"" << e.name << "\",\"startUs\":" << e.start << ",\"endUs\":" << e.end
                    << ",\"args\":[";
                for (std::size_t i = 0; i != e.args.size(); ++i) { if (i) out << ','; out << e.args[i]; }
                out << "]}";
            }
            out << ']';
        };
        events("active", s.active); events("history", s.history); out << '}';
    }
private:
    void Retire() noexcept
    {
        for (std::size_t i = 0; i != ActiveLimit; ++i)
            if (active_[i].id)
                if (const auto end = ended_[i].load(std::memory_order_acquire))
                {
                    active_[i].end = end;
                    history_[completed_++ % HistoryLimit] = active_[i];
                    active_[i] = {};
                }
    }
    std::mutex mutex_;
    std::array<Event, ActiveLimit> active_{};
    std::array<std::atomic<std::uint64_t>, ActiveLimit> ended_{};
    std::array<Event, HistoryLimit> history_{};
    std::atomic<std::uint64_t> dropped_{0};
    std::uint64_t next_ = 0, completed_ = 0;
};

inline thread_local LatencyTrace* latency_parent_trace = nullptr;
inline thread_local std::uint64_t latency_parent_id = 0;
class LatencySpan
{
public:
    LatencySpan(LatencyTrace* trace, const char* name,
        const std::array<std::uint64_t, 6>& args = {}) noexcept : trace_(trace)
    {
        if (trace_) token_ = trace_->Begin(name,
            trace_ == latency_parent_trace ? latency_parent_id : 0, GetCurrentThreadId(), args);
    }
    ~LatencySpan() { if (trace_) trace_->End(token_); }
    LatencySpan(const LatencySpan&) = delete;
    LatencySpan& operator=(const LatencySpan&) = delete;
    std::uint64_t Id() const noexcept { return token_ >> 8; }
private:
    LatencyTrace* trace_;
    std::uint64_t token_ = 0;
};

class CallbackLatency
{
public:
    CallbackLatency(LatencyTrace* trace, const char* name) noexcept
        : previous_trace_(latency_parent_trace), previous_id_(latency_parent_id), span_(trace, name)
    { if (trace) { latency_parent_trace = trace; latency_parent_id = span_.Id(); } }
    ~CallbackLatency() { latency_parent_trace = previous_trace_; latency_parent_id = previous_id_; }
private:
    LatencyTrace* previous_trace_;
    std::uint64_t previous_id_;
    LatencySpan span_;
};
