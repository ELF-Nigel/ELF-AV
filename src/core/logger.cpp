#include "core/logger.h"
#include <mutex>
#include <chrono>
#include <ctime>
#include <windows.h>
#include <shlobj.h>

static std::mutex g_mu;
static HANDLE g_eventSrc = nullptr;
static HANDLE g_logFile = INVALID_HANDLE_VALUE;
static std::wstring g_logPath;
static bool g_verbose = false;

static std::wstring NowTs() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_s(&tm, &t);
    wchar_t buf[64];
    wcsftime(buf, 64, L"%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

static std::wstring DefaultLogPath() {
    PWSTR path = nullptr;
    std::wstring out = L"C:\\ProgramData\\AVResearch\\logs\\avresearch.log";
    if (SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &path) == S_OK) {
        out = std::wstring(path) + L"\\AVResearch\\logs\\avresearch.log";
        CoTaskMemFree(path);
    }
    return out;
}

static void EnsureLogFile() {
    if (g_logFile != INVALID_HANDLE_VALUE) return;
    if (g_logPath.empty()) g_logPath = DefaultLogPath();
    size_t pos = g_logPath.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        std::wstring dir = g_logPath.substr(0, pos);
        CreateDirectoryW(dir.c_str(), nullptr);
        size_t pos2 = dir.find_last_of(L"\\/");
        if (pos2 != std::wstring::npos) {
            CreateDirectoryW(dir.substr(0, pos2).c_str(), nullptr);
        }
    }
    g_logFile = CreateFileW(g_logPath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
}

void InitLogger(const std::wstring& log_path) {
    (void)log_path;
    if (!g_eventSrc) {
        g_eventSrc = RegisterEventSourceW(nullptr, L"avresearch");
    }
    if (!log_path.empty()) {
        g_logPath = log_path;
    }
    if (GetEnvironmentVariableW(L"AVRESEARCH_VERBOSE", nullptr, 0) > 0) {
        g_verbose = true;
    }
    EnsureLogFile();
}

const std::wstring& GetLogFilePath() {
    if (g_logPath.empty()) g_logPath = DefaultLogPath();
    return g_logPath;
}

void SetVerboseLogging(bool enabled) { g_verbose = enabled; }
bool IsVerboseLogging() { return g_verbose; }

static void LogLine(const std::wstring& level, const std::wstring& msg) {
    std::lock_guard<std::mutex> lock(g_mu);
    std::wstring line = L"[" + NowTs() + L"] [" + level + L"] " + msg;
    OutputDebugStringW((line + L"\n").c_str());
    EnsureLogFile();
    if (g_logFile != INVALID_HANDLE_VALUE) {
        std::wstring out = line + L"\r\n";
        DWORD bytes = (DWORD)(out.size() * sizeof(wchar_t));
        WriteFile(g_logFile, out.c_str(), bytes, &bytes, nullptr);
    }
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
