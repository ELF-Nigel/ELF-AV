#include "core/logger.h"
#include <mutex>
#include <chrono>
#include <ctime>
#include <windows.h>

static std::mutex g_mu;
static HANDLE g_eventSrc = nullptr;

static std::wstring NowTs() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_s(&tm, &t);
    wchar_t buf[64];
    wcsftime(buf, 64, L"%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

void InitLogger(const std::wstring& log_path) {
    (void)log_path;
    if (!g_eventSrc) {
        g_eventSrc = RegisterEventSourceW(nullptr, L"avresearch");
    }
}

static void LogLine(const std::wstring& level, const std::wstring& msg) {
    std::lock_guard<std::mutex> lock(g_mu);
    std::wstring line = L"[" + NowTs() + L"] [" + level + L"] " + msg;
    OutputDebugStringW((line + L"\n").c_str());
    if (g_eventSrc) {
        LPCWSTR strings[1] = { line.c_str() };
        WORD type = EVENTLOG_INFORMATION_TYPE;
        if (level == L"WARN") type = EVENTLOG_WARNING_TYPE;
        if (level == L"ERROR") type = EVENTLOG_ERROR_TYPE;
        ReportEventW(g_eventSrc, type, 0, 0x1000, nullptr, 1, 0, strings, nullptr);
    }
}

void LogInfo(const std::wstring& msg) { LogLine(L"info", msg); }
void LogWarn(const std::wstring& msg) { LogLine(L"warn", msg); }
void LogError(const std::wstring& msg) { LogLine(L"error", msg); }
