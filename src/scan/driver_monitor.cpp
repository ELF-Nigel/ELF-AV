#include "scan/driver_monitor.h"
#include "core/logger.h"
#include "ui/notifier.h"
#include <windows.h>
#include <thread>

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
            LogInfo(L"driver loaded: " + std::wstring(services[i].lpServiceName));
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
