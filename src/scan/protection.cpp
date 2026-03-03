#include "scan/protection.h"
#include "core/security.h"
#include "core/logger.h"
#include "ui/notifier.h"
#include <windows.h>
#include <mutex>
#include <deque>
#include <thread>

static std::mutex g_mu;
static Config g_cfg;
static bool g_active = false;
static uint64_t g_active_until = 0;
static std::deque<uint64_t> g_events;

static uint64_t NowMs() { return GetTickCount64(); }

void InitProtection(const Config& cfg) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_cfg = cfg;
    g_active = false;
    g_active_until = 0;
    g_events.clear();
}

static void SetLockdown(bool enable) {
    for (const auto& dir : g_cfg.watch_paths) {
        SetDirectoryLockdown(dir, enable);
    }
}

static void MaybeDeactivate() {
    if (g_active && NowMs() > g_active_until) {
        g_active = false;
        SetLockdown(false);
        LogWarn(L"lockdown lifted.");
    }
}

void StartProtectionThread() {
    std::thread([]() {
        while (true) {
            Sleep(60000);
            std::lock_guard<std::mutex> lock(g_mu);
            MaybeDeactivate();
        }
    }).detach();
}

void RecordFileEvent(const std::wstring& path) {
    (void)path;
    std::lock_guard<std::mutex> lock(g_mu);
    uint64_t now = NowMs();
    uint64_t window_ms = (uint64_t)g_cfg.mass_change_window_seconds * 1000;

    g_events.push_back(now);
    while (!g_events.empty() && now - g_events.front() > window_ms) g_events.pop_front();

    if (!g_active && g_events.size() >= g_cfg.mass_change_threshold) {
        g_active = true;
        g_active_until = now + (uint64_t)g_cfg.lockdown_cooldown_minutes * 60 * 1000;
        LogError(L"mass-change pattern detected. enabling lockdown.");
        NotifyAlert(L"avresearch alert", L"mass-change detected. lockdown enabled.");
        SetLockdown(true);
    }

    MaybeDeactivate();
}

bool IsMassChangeActive() {
    std::lock_guard<std::mutex> lock(g_mu);
    return g_active;
}
