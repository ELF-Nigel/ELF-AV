#include "scan/lsass_monitor.h"
#include "core/logger.h"
#include "ui/notifier.h"
#include <windows.h>
#include <psapi.h>
#include <thread>

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

static void CheckLsassOpen() {
    DWORD pids[2048];
    DWORD bytes = 0;
    if (!EnumProcesses(pids, sizeof(pids), &bytes)) return;
    DWORD count = bytes / sizeof(DWORD);
    for (DWORD i = 0; i < count; i++) {
        DWORD pid = pids[i];
        if (pid == 0) continue;
        std::wstring img;
        if (!GetProcessImagePath(pid, img)) continue;
        if (IsSuspiciousPathLocal(img)) {
            // best-effort: alert on suspicious processes running while lsass exists
            LogWarn(L"suspicious process while lsass active: " + img);
            NotifyAlert(L"avresearch alert", L"suspicious process while lsass active: " + img);
        }
    }
}

bool StartLsassMonitorThread() {
    try {
        std::thread([]() {
            while (true) {
                CheckLsassOpen();
                Sleep(300000);
            }
        }).detach();
        return true;
    } catch (...) {
        return false;
    }
}
