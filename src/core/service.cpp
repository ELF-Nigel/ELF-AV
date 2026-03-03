#include "core/config.h"
#include "core/logger.h"
#include "scan/scanner.h"
#include "scan/watcher.h"
#include "core/security.h"
#include "scan/telemetry.h"
#include "scan/scan_utils.h"
#include "scan/protection.h"
#include "scan/canary.h"
#include "scan/net_monitor.h"
#include "scan/registry_monitor.h"
#include "scan/removable_monitor.h"
#include "scan/process_monitor.h"
#include "scan/persistence_monitor.h"
#include "scan/system_tamper.h"
#include "scan/credential_monitor.h"
#include "scan/lsass_monitor.h"
#include "scan/driver_monitor.h"
#include "scan/dns_monitor.h"
#include "scan/hosts_monitor.h"
#include "scan/task_monitor.h"
#include <windows.h>
#include <atomic>
#include <thread>

static SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
static std::atomic<bool> g_serviceRunning{false};

static void ReportStatus(DWORD state, DWORD win32Exit = NO_ERROR) {
    SERVICE_STATUS status{};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwControlsAccepted = (state == SERVICE_RUNNING) ? SERVICE_ACCEPT_STOP : 0;
    status.dwWin32ExitCode = win32Exit;
    status.dwWaitHint = 2000;
    if (g_statusHandle) SetServiceStatus(g_statusHandle, &status);
}

static void RunCore() {
    Config cfg = DefaultConfig();
    if (!VerifySelfSignature()) {
        LogError(L"signature check failed. stopping service.");
        return;
    }
    {
        wchar_t exePath[MAX_PATH] = {0};
        if (GetModuleFileNameW(nullptr, exePath, MAX_PATH)) {
            if (IsUserWritablePath(exePath)) {
                LogWarn(L"binary running from user-writable path: " + std::wstring(exePath));
            }
        }
    }
    HardenDirectoryAcl(cfg.quarantine_dir);
    EnsureProcessAuditEnabled();
    CleanSuspiciousAutoruns();
    EnsureScheduledTask();
    HardenInstallDir();

    g_serviceRunning = true;

    SignatureDB sigs;
    sigs.LoadEmbedded();

    InitProtection(cfg);
    StartProtectionThread();

    StartNetworkMonitorThread();
    StartRegistryMonitorThread();
    StartRemovableMonitorThread(cfg, sigs);
    StartProcessMonitorThread();
    StartPersistenceMonitorThread();
    StartSystemTamperThread();
    StartCredentialMonitorThread();
    StartLsassMonitorThread();
    StartDriverMonitorThread();
    StartDnsMonitorThread();
    StartHostsMonitorThread();
    StartTaskMonitorThread();

    for (const auto& dir : cfg.watch_paths) {
        if (!StartWatchThread(dir, [&](const std::wstring& p) { ProcessFileEvent(p, cfg, sigs); })) {
            LogError(L"failed to start watcher for: " + dir);
        } else {
            LogInfo(L"watching: " + dir);
        }
    }

    if (!StartProcessTelemetryThread([&](const std::wstring& p) { ProcessFileEvent(p, cfg, sigs); })) {
        LogWarn(L"process telemetry not started.");
    } else {
        LogInfo(L"process telemetry started.");
    }

    std::wstring baseline;
    if (GetSelfSha256(baseline)) {
        std::thread([baseline]() {
            while (g_serviceRunning) {
                Sleep(60000);
                std::wstring cur;
                if (!GetSelfSha256(cur) || cur != baseline || !VerifySelfSignature()) {
                    LogError(L"integrity check failed. stopping service.");
                    g_serviceRunning = false;
                }
            }
        }).detach();
    }

    std::thread([]() {
        while (g_serviceRunning) {
            Sleep(3600000);
            CleanSuspiciousAutoruns();
        }
    }).detach();

    std::thread([]() {
        while (g_serviceRunning) {
            Sleep(3600000);
            LogInfo(L"health check ok");
        }
    }).detach();

    if (cfg.periodic_scan_minutes > 0) {
        std::thread([cfg, &sigs]() {
            while (g_serviceRunning) {
                Sleep(cfg.periodic_scan_minutes * 60 * 1000);
                for (const auto& drive : GetFixedDrives()) {
                    ScanPathRecursiveNoRecord(drive, cfg, sigs);
                }
                ScanStartupFolders(cfg, sigs);
            }
        }).detach();
    }

    std::thread([&cfg, &sigs]() {
        for (const auto& drive : GetFixedDrives()) {
            ScanPathRecursiveNoRecord(drive, cfg, sigs);
        }
        ScanStartupFolders(cfg, sigs);
        ScanRemovableDrivesOnce(cfg, sigs);
    }).detach();

    InitCanaries(GetFixedDrives());
    std::thread([]() {
        while (g_serviceRunning) {
            Sleep(120000);
            CheckCanaries();
        }
    }).detach();

    while (g_serviceRunning) Sleep(1000);
}

static void WINAPI ServiceCtrlHandler(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP) {
        g_serviceRunning = false;
        ReportStatus(SERVICE_STOP_PENDING);
    }
}

static void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_statusHandle = RegisterServiceCtrlHandlerW(L"AVResearch", ServiceCtrlHandler);
    if (!g_statusHandle) return;

    ReportStatus(SERVICE_START_PENDING);
    ReportStatus(SERVICE_RUNNING);

    RunCore();

    ReportStatus(SERVICE_STOPPED);
}

bool RunAsService() {
    SERVICE_TABLE_ENTRYW table[] = {
        { (LPWSTR)L"AVResearch", ServiceMain },
        { nullptr, nullptr }
    };
    return StartServiceCtrlDispatcherW(table) != 0;
}

bool InstallService(const std::wstring& binPath) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return false;

    SC_HANDLE svc = CreateServiceW(
        scm,
        L"AVResearch",
        L"AVResearch",
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        binPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr
    );

    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }
    SERVICE_DESCRIPTIONW desc{};
    desc.lpDescription = (LPWSTR)L"avresearch real-time protection service";
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &desc);

    SC_ACTION actions[3] = {
        { SC_ACTION_RESTART, 5000 },
        { SC_ACTION_RESTART, 5000 },
        { SC_ACTION_RESTART, 5000 }
    };
    SERVICE_FAILURE_ACTIONSW fa{};
    fa.dwResetPeriod = 86400;
    fa.cActions = 3;
    fa.lpsaActions = actions;
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}

bool UninstallService() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceW(scm, L"AVResearch", DELETE);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }
    bool ok = DeleteService(svc) != 0;
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

bool EnsureServiceRunning() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceW(scm, L"AVResearch", SERVICE_QUERY_STATUS | SERVICE_START);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS_PROCESS ssp{};
    DWORD bytesNeeded = 0;
    bool ok = (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded) != 0);
    if (ok && ssp.dwCurrentState != SERVICE_RUNNING && ssp.dwCurrentState != SERVICE_START_PENDING) {
        StartServiceW(svc, 0, nullptr);
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}
