/**
 * @file test_timer.cpp
 * @brief TimerWheel tests: ordered firing, cancellation, live count.
 */

#include <xtcp/core/timer.h>

#include <cstdio>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

static void TestOrderedFire() {
    xtcp::core::TimerWheel wheel;
    std::vector<UInt64> order;

    wheel.Add(1000, [&]() { order.push_back(1000); });
    wheel.Add(500,  [&]() { order.push_back(500); });
    wheel.Add(500,  [&]() { order.push_back(501); });

    CHECK(3 == wheel.Size());
    CHECK(0 == wheel.AdvanceTo(499));       // nothing due
    CHECK(2 == wheel.AdvanceTo(500));       // both 500s fire
    CHECK(0 == wheel.AdvanceTo(999));
    CHECK(1 == wheel.AdvanceTo(1000));      // 1000 fires

    CHECK(3 == order.size());
    CHECK(500 == order[0]);
    CHECK(501 == order[1]);
    CHECK(1000 == order[2]);
    CHECK(0 == wheel.Size());
}

static void TestCancel() {
    xtcp::core::TimerWheel wheel;
    bool cancelled_fired = false;
    bool live_fired = false;

    xtcp::core::TimerId id = wheel.Add(100, [&]() { cancelled_fired = true; });
    wheel.Add(200, [&]() { live_fired = true; });

    CHECK(2 == wheel.Size());
    wheel.Remove(id);
    CHECK(1 == wheel.Size());

    wheel.AdvanceTo(300);
    CHECK(!cancelled_fired);    // cancelled timer must not fire
    CHECK(live_fired);          // live timer fires normally
    CHECK(0 == wheel.Size());
}

static void TestCancelNonTop() {
    xtcp::core::TimerWheel wheel;
    std::vector<UInt64> order;

    wheel.Add(100, [&]() { order.push_back(100); });
    xtcp::core::TimerId id2 = wheel.Add(200, [&]() { order.push_back(200); });
    wheel.Add(300, [&]() { order.push_back(300); });

    wheel.Remove(id2);                      // cancel middle entry
    wheel.AdvanceTo(400);

    CHECK(2 == order.size());
    CHECK(100 == order[0]);
    CHECK(300 == order[1]);
    CHECK(0 == wheel.Size());
}

static void TestIdle() {
    xtcp::core::TimerWheel wheel;
    CHECK(0 == wheel.AdvanceTo(999999));
    CHECK(0 == wheel.Size());
}

int main() {
    TestOrderedFire();
    TestCancel();
    TestCancelNonTop();
    TestIdle();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_timer: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_timer: all passed\n");
    return 0;
}
