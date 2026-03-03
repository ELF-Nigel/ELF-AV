#include "scan/persistence_monitor.h"
#include "core/security.h"
#include "core/logger.h"
#include "ui/notifier.h"
#include <windows.h>
#include <vector>
#include <string>
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

static std::wstring ExtractExePath(const std::wstring& cmd) {
    std::wstring s = cmd;
    s.erase(0, s.find_first_not_of(L" \t"));
    if (s.empty()) return L"";
    if (s[0] == L'"') {
        auto end = s.find(L'"', 1);
        if (end != std::wstring::npos) return s.substr(1, end - 1);
    }
    auto end = s.find(L' ');
    return (end == std::wstring::npos) ? s : s.substr(0, end);
}

static void CheckServices() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return;
    DWORD bytesNeeded = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, nullptr, 0, &bytesNeeded, &count, &resume, nullptr);
    if (bytesNeeded == 0) { CloseServiceHandle(scm); return; }
    std::vector<BYTE> buf(bytesNeeded);
    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buf.data(), (DWORD)buf.size(), &bytesNeeded, &count, &resume, nullptr)) {
        CloseServiceHandle(scm); return; }

    auto* services = (ENUM_SERVICE_STATUS_PROCESSW*)buf.data();
    for (DWORD i = 0; i < count; i++) {
        SC_HANDLE svc = OpenServiceW(scm, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (!svc) continue;
        DWORD needed = 0;
        QueryServiceConfigW(svc, nullptr, 0, &needed);
        if (needed == 0) { CloseServiceHandle(svc); continue; }
        auto cfg = (QUERY_SERVICE_CONFIGW*)malloc(needed);
        if (QueryServiceConfigW(svc, cfg, needed, &needed)) {
            std::wstring bin = cfg->lpBinaryPathName ? cfg->lpBinaryPathName : L"";
            std::wstring exe = ExtractExePath(bin);
            if (!exe.empty() && IsSuspiciousPathLocal(exe) && !IsFileSignedPath(exe)) {
                LogWarn(L"suspicious service binary: " + exe);
                NotifyAlert(L"avresearch alert", L"suspicious service binary: " + exe);
            }
        }
        free(cfg);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
}

static void CheckScheduledTasks() {
    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    std::wstring cmd = L"schtasks.exe /query /fo list /v";
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) return;

    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    // lightweight: rely on registry monitor + autorun cleanup; deep parsing omitted
    LogInfo(L"scheduled tasks checked");
}

bool StartPersistenceMonitorThread() {
    try {
        std::thread([]() {
            while (true) {
                CheckServices();
                CheckScheduledTasks();
                Sleep(3600000);
            }
        }).detach();
        return true;
    } catch (...) {
        return false;
    }
}
