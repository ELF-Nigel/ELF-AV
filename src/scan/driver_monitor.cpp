#include "scan/driver_monitor.h"
#include "core/logger.h"
#include "core/security.h"
#include "ui/notifier.h"
#include <windows.h>
#include <thread>
#include <vector>
#include <string>

static std::wstring ToLowerLocal(const std::wstring& s) {
    std::wstring out = s;
    for (auto& c : out) c = (wchar_t)towlower(c);
    return out;
}

static std::wstring NormalizeDriverImagePath(const std::wstring& in) {
    if (in.empty()) return in;
    std::wstring p = in;
    if (!p.empty() && p.front() == L'"') {
        auto end = p.find(L'"', 1);
        if (end != std::wstring::npos) p = p.substr(1, end - 1);
    }
    auto lower = ToLowerLocal(p);
    auto pos = lower.find(L".sys");
    if (pos != std::wstring::npos) p = p.substr(0, pos + 4);
    if (p.rfind(L"\\SystemRoot\\", 0) == 0) {
        p = L"C:\\Windows\\" + p.substr(12);
    }
    if (p.rfind(L"\\??\\", 0) == 0) {
        p = p.substr(4);
    }
    wchar_t buf[MAX_PATH];
    DWORD n = ExpandEnvironmentStringsW(p.c_str(), buf, MAX_PATH);
    if (n > 0 && n < MAX_PATH) p = buf;
    return p;
}

static void CheckDrivers() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return;
    DWORD bytesNeeded = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_STATE_ALL, nullptr, 0, &bytesNeeded, &count, &resume, nullptr);
    if (bytesNeeded == 0) { CloseServiceHandle(scm); return; }
    std::vector<BYTE> buf(bytesNeeded);
    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_STATE_ALL, buf.data(), (DWORD)buf.size(), &bytesNeeded, &count, &resume, nullptr)) {
        CloseServiceHandle(scm); return; }

    auto* services = (ENUM_SERVICE_STATUS_PROCESSW*)buf.data();
    for (DWORD i = 0; i < count; i++) {
        if (services[i].ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING) {
            std::wstring svcName = services[i].lpServiceName ? services[i].lpServiceName : L"";
            LogInfo(L"driver loaded: " + svcName);
            SC_HANDLE svc = OpenServiceW(scm, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
            if (!svc) continue;
            DWORD needed = 0;
            QueryServiceConfigW(svc, nullptr, 0, &needed);
            if (needed) {
                std::vector<BYTE> cbuf(needed);
                auto* cfg = (QUERY_SERVICE_CONFIGW*)cbuf.data();
                if (QueryServiceConfigW(svc, cfg, (DWORD)cbuf.size(), &needed)) {
                    std::wstring img = NormalizeDriverImagePath(cfg->lpBinaryPathName ? cfg->lpBinaryPathName : L"");
                    if (!img.empty()) {
                        bool signedOk = IsFileSignedPath(img);
                        if (!signedOk) {
                            LogWarn(L"unsigned driver image: " + img);
                            NotifyAlert(L"avresearch alert", L"unsigned driver image: " + img);
                        }
                        if (IsUserWritablePath(img)) {
                            LogWarn(L"driver from user-writable path: " + img);
                            NotifyAlert(L"avresearch alert", L"driver from user-writable path: " + img);
                        }
                    }
                }
            }
            CloseServiceHandle(svc);
        }
    }
    CloseServiceHandle(scm);
}

bool StartDriverMonitorThread() {
    try {
        std::thread([]() {
            while (true) {
                CheckDrivers();
                Sleep(3600000);
            }
        }).detach();
        return true;
    } catch (...) {
        return false;
    }
}
