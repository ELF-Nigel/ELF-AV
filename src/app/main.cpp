#include "core/config.h"
#include "core/logger.h"
#include "scan/scanner.h"
#include "scan/watcher.h"
#include "core/security.h"
#include "core/service.h"
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
#include "ui/notifier.h"
#include "core/utils.h"
#include <windows.h>
#include <iostream>
#include <atomic>
#include <thread>

static std::atomic<bool> g_running{true};

static void ListQuarantine(const std::wstring& qdir) {
    std::wstring pattern = qdir + L"\\*";
    WIN32_FIND_DATAW f{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &f);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (!(f.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::wcout << f.cFileName << L"\n";
        }
    } while (FindNextFileW(h, &f));
    FindClose(h);
}

static bool FindQuarantineFile(const std::wstring& qdir, const std::wstring& sha256, std::wstring& outPath) {
    std::wstring pattern = qdir + L"\\*";
    WIN32_FIND_DATAW f{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &f);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool found = false;
    do {
        if (f.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::wstring name = f.cFileName;
        auto pos = name.rfind(L"." + sha256 + L".q");
        if (pos != std::wstring::npos) {
            outPath = qdir + L"\\" + name;
            found = true;
            break;
        }
    } while (FindNextFileW(h, &f));
    FindClose(h);
    return found;
}

static void StartPeriodicScanThread(const Config& cfg, const SignatureDB& sigs) {
    if (cfg.periodic_scan_minutes == 0) return;
    std::thread([cfg, &sigs]() {
        while (g_running) {
            Sleep(cfg.periodic_scan_minutes * 60 * 1000);
            for (const auto& drive : GetFixedDrives()) {
                ScanPathRecursiveNoRecord(drive, cfg, sigs);
            }
        }
    }).detach();
}

int wmain(int argc, wchar_t** argv) {
    if (argc > 1) {
        std::wstring arg = argv[1];
        if (arg == L"--service") return RunAsService() ? 0 : 1;
        if (arg == L"--install") {
            wchar_t path[MAX_PATH] = {0};
            GetModuleFileNameW(nullptr, path, MAX_PATH);
            return InstallService(path) ? 0 : 1;
        }
        if (arg == L"--uninstall") return UninstallService() ? 0 : 1;
        if (arg == L"--import-sigs" && argc > 2) {
            return SaveSignatureBlobToRegistry(argv[2]) ? 0 : 1;
        }
        if (arg == L"--clean-autoruns") {
            return CleanSuspiciousAutoruns() ? 0 : 1;
        }
    }

    Config cfg = DefaultConfig();
    InitLogger(L"");
    InitNotifier();
    LogInfo(L"av research prototype starting");
    if (!VerifySelfSignature()) {
        LogError(L"signature check failed. exiting.");
        return 1;
    }
    HardenDirectoryAcl(cfg.quarantine_dir);
    EnsureProcessAuditEnabled();
    CleanSuspiciousAutoruns();
    EnsureServiceRunning();
    EnsureScheduledTask();

    SignatureDB sigs;
    sigs.LoadEmbedded();

    if (argc > 2 && std::wstring(argv[1]) == L"--scan") {
        ScanPathRecursiveNoRecord(argv[2], cfg, sigs);
        return 0;
    }
    if (argc > 2 && std::wstring(argv[1]) == L"--quarantine") {
        std::wstring cmd = argv[2];
        if (cmd == L"list") {
            ListQuarantine(cfg.quarantine_dir);
            return 0;
        }
        if (cmd == L"list-details") {
            std::wstring pattern = cfg.quarantine_dir + L"\\*";
            WIN32_FIND_DATAW f{};
            HANDLE h = FindFirstFileW(pattern.c_str(), &f);
            if (h != INVALID_HANDLE_VALUE) {
                do {
                    if (f.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                    std::wstring name = f.cFileName;
                    auto dot = name.rfind(L".");
                    auto dot2 = name.rfind(L".q");
                    if (dot != std::wstring::npos && dot2 != std::wstring::npos && dot2 > dot) {
                        std::wstring sha = name.substr(dot + 1, dot2 - dot - 1);
                        std::wstring orig;
                        if (LoadQuarantineMeta(sha, orig)) {
                            std::wcout << sha << L" | " << orig << L"\n";
                        }
                    }
                } while (FindNextFileW(h, &f));
                FindClose(h);
            }
            return 0;
        }
        if (cmd == L"restore-all") {
            std::wstring pattern = cfg.quarantine_dir + L"\\*";
            WIN32_FIND_DATAW f{};
            HANDLE h = FindFirstFileW(pattern.c_str(), &f);
            if (h != INVALID_HANDLE_VALUE) {
                do {
                    if (f.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                    std::wstring name = f.cFileName;
                    auto dot = name.rfind(L".");
                    auto dot2 = name.rfind(L".q");
                    if (dot != std::wstring::npos && dot2 != std::wstring::npos && dot2 > dot) {
                        std::wstring sha = name.substr(dot + 1, dot2 - dot - 1);
                        std::wstring orig;
                        if (LoadQuarantineMeta(sha, orig)) {
                            std::wstring qfile = cfg.quarantine_dir + L"\\" + name;
                            MoveFileExW(qfile.c_str(), orig.c_str(), MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING);
                            DeleteQuarantineMeta(sha);
                        }
                    }
                } while (FindNextFileW(h, &f));
                FindClose(h);
            }
            return 0;
        }
        if (cmd == L"delete" && argc > 3) {
            std::wstring qfile;
            if (FindQuarantineFile(cfg.quarantine_dir, argv[3], qfile)) {
                DeleteFileW(qfile.c_str());
                DeleteQuarantineMeta(argv[3]);
            }
            return 0;
        }
        if (cmd == L"restore" && argc > 3) {
            std::wstring orig;
            if (!LoadQuarantineMeta(argv[3], orig)) return 1;
            std::wstring qfile;
            if (!FindQuarantineFile(cfg.quarantine_dir, argv[3], qfile)) return 1;
            MoveFileExW(qfile.c_str(), orig.c_str(), MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING);
            DeleteQuarantineMeta(argv[3]);
            return 0;
        }
    }

    for (const auto& dir : cfg.watch_paths) {
        if (!StartWatchThread(dir, [&](const std::wstring& p) { ProcessFileEvent(p, cfg, sigs); })) {
            LogError(L"failed to start watcher for: " + dir);
        } else {
            LogInfo(L"watching: " + dir);
        }
    }

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

    if (!StartProcessTelemetryThread([&](const std::wstring& p) { ProcessFileEvent(p, cfg, sigs); })) {
        LogWarn(L"process telemetry not started.");
    } else {
        LogInfo(L"process telemetry started.");
    }

    std::wstring baseline;
    if (GetSelfSha256(baseline)) {
        std::thread([baseline]() {
            while (g_running) {
                Sleep(60000);
                std::wstring cur;
                if (!GetSelfSha256(cur) || cur != baseline || !VerifySelfSignature()) {
                    LogError(L"integrity check failed. exiting.");
                    ExitProcess(1);
                }
            }
        }).detach();
    }

    std::thread([]() {
        while (g_running) {
            Sleep(3600000);
            CleanSuspiciousAutoruns();
            EnsureServiceRunning();
        }
    }).detach();

    StartPeriodicScanThread(cfg, sigs);
    std::thread([&cfg, &sigs]() {
        for (const auto& drive : GetFixedDrives()) {
            ScanPathRecursiveNoRecord(drive, cfg, sigs);
        }
        ScanStartupFolders(cfg, sigs);
        ScanRemovableDrivesOnce(cfg, sigs);
    }).detach();

    InitCanaries(GetFixedDrives());
    std::thread([]() {
        while (g_running) {
            Sleep(120000);
            CheckCanaries();
        }
    }).detach();

    std::wcout << L"running. press ctrl+c to stop.\n";
    while (g_running) {
        Sleep(1000);
    }
    return 0;
}
