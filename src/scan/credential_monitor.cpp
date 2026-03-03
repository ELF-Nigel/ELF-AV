#include "scan/credential_monitor.h"
#include "core/logger.h"
#include "core/security.h"
#include "ui/notifier.h"
#include <windows.h>
#include <psapi.h>
#include <thread>
#include <vector>

static std::wstring ToLowerLocal(const std::wstring& s) {
    std::wstring out = s;
    for (auto& c : out) c = (wchar_t)towlower(c);
    return out;
}

static bool IsSuspiciousPathLocal(const std::wstring& path) {
    auto p = ToLowerLocal(path);
    return (p.find(L"\\appdata\\") != std::wstring::npos) ||
           (p.find(L"\\temp\\") != std::wstring::npos) ||
           (p.find(L"\\downloads\\") != std::wstring::npos);
}

static bool GetProcessImagePath(DWORD pid, std::wstring& out) {
    out.clear();
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    wchar_t buf[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(h, 0, buf, &size)) out.assign(buf, size);
    CloseHandle(h);
    return !out.empty();
}

static void CheckAccessToBrowserDb() {
    wchar_t profile[MAX_PATH];
    if (!GetEnvironmentVariableW(L"USERPROFILE", profile, MAX_PATH)) return;
    std::wstring chrome = std::wstring(profile) + L"\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data";
    std::wstring edge = std::wstring(profile) + L"\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data";

    for (auto path : {chrome, edge}) {
        HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            // can't attribute to a process without kernel, emit a warning
            LogWarn(L"browser credential db accessed: " + path);
            NotifyAlert(L"avresearch alert", L"browser credential db accessed: " + path);
        }
    }
}

bool StartCredentialMonitorThread() {
    try {
        std::thread([]() {
            while (true) {
                CheckAccessToBrowserDb();
                Sleep(300000);
            }
        }).detach();
        return true;
    } catch (...) {
        return false;
    }
}
