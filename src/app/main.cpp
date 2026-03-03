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
#include <vector>

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

static int ShowMenu() {
    std::wcout << L"\nselect an option:\n";
    std::wcout << L"1) scan path\n";
    std::wcout << L"2) scan full system\n";
    std::wcout << L"3) quarantine list\n";
    std::wcout << L"4) quarantine list-details\n";
    std::wcout << L"5) quarantine restore\n";
    std::wcout << L"6) quarantine restore-all\n";
    std::wcout << L"7) quarantine delete\n";
    std::wcout << L"8) clean autoruns\n";
    std::wcout << L"9) full install (service + folders)\n";
    std::wcout << L"10) full uninstall\n";
    std::wcout << L"11) show recent logs\n";
    std::wcout << L"12) toggle verbose logging\n";
    std::wcout << L"0) exit\n";
    std::wcout << L"> ";
    int choice = -1;
    std::wcin >> choice;
    return choice;
}

static void ShowRecentLogs(size_t maxLines) {
    std::wstring path = GetLogFilePath();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        std::wcout << L"no log file found\n";
        return;
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h, &size) || size.QuadPart == 0) {
        CloseHandle(h);
        std::wcout << L"log is empty\n";
        return;
    }
    const DWORD maxBytes = 128 * 1024;
    LONGLONG offset = size.QuadPart > maxBytes ? (size.QuadPart - maxBytes) : 0;
    if (offset % 2 != 0) offset++;
    LARGE_INTEGER off{};
    off.QuadPart = offset;
    SetFilePointerEx(h, off, nullptr, FILE_BEGIN);
    LONGLONG toRead = size.QuadPart - offset;
    if (toRead > maxBytes) toRead = maxBytes;
    std::vector<BYTE> buf((size_t)toRead);
    DWORD read = 0;
    if (!ReadFile(h, buf.data(), (DWORD)buf.size(), &read, nullptr)) {
        CloseHandle(h);
        std::wcout << L"failed to read log\n";
        return;
    }
    CloseHandle(h);
    std::wstring data((wchar_t*)buf.data(), read / sizeof(wchar_t));
    std::vector<std::wstring> lines;
    size_t start = 0;
    while (start < data.size()) {
        size_t end = data.find(L'\n', start);
        if (end == std::wstring::npos) end = data.size();
        std::wstring line = data.substr(start, end - start);
        if (!line.empty() && line.back() == L'\r') line.pop_back();
        if (!line.empty()) lines.push_back(line);
        start = end + 1;
    }
    size_t begin = (lines.size() > maxLines) ? (lines.size() - maxLines) : 0;
    for (size_t i = begin; i < lines.size(); i++) {
        std::wcout << lines[i] << L"\n";
    }
}

static void LogChoice(int choice) {
    LogInfo(L"menu choice: " + std::to_wstring(choice));
}

int wmain(int argc, wchar_t** argv) {
    if (argc > 1) {
        std::wstring arg = argv[1];
        if (arg == L"--service") return RunAsService() ? 0 : 1;
        if (arg == L"--install") {
            wchar_t path[MAX_PATH] = {0};
            GetModuleFileNameW(nullptr, path, MAX_PATH);
            LogInfo(L"installing service");
            return InstallService(path) ? 0 : 1;
        }
        if (arg == L"--uninstall") return UninstallService() ? 0 : 1;
        if (arg == L"--import-sigs" && argc > 2) {
            LogInfo(L"importing signatures");
            return SaveSignatureBlobToRegistry(argv[2]) ? 0 : 1;
        }
        if (arg == L"--clean-autoruns") {
            LogInfo(L"cleaning autoruns");
            return CleanSuspiciousAutoruns() ? 0 : 1;
        }
    }

    Config cfg = DefaultConfig();
    InitLogger(L"");
    InitNotifier();
    LogInfo(L"av research prototype starting");
    if (!VerifySelfSignature()) {
        if (!AllowUnsignedOverride()) {
            MessageBoxW(nullptr, L"signature check failed. set AVRESEARCH_ALLOW_UNSIGNED=1 or registry AllowUnsigned=1 to run for testing.", L"avresearch", MB_OK | MB_ICONERROR | MB_TOPMOST);
            LogError(L"signature check failed. exiting.");
            return 1;
        }
        LogWarn(L"signature check failed. override enabled for testing.");
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
    EnsureServiceRunning();
    EnsureScheduledTask();
    HardenInstallDir();
    HardenRegistryAcl();

    SignatureDB sigs;
    sigs.LoadEmbedded();

    if (argc > 2 && std::wstring(argv[1]) == L"--scan") {
        std::wcout << L"scanning: " << argv[2] << L"\n";
        ScanPathRecursiveNoRecord(argv[2], cfg, sigs);
        std::wcout << L"scan complete\n";
        return 0;
    }
    if (argc > 1 && std::wstring(argv[1]) == L"--scan-all") {
        std::wcout << L"scanning full system\n";
        for (const auto& drive : GetFixedDrives()) {
            ScanPathRecursiveNoRecord(drive, cfg, sigs);
        }
        std::wcout << L"scan complete\n";
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
                    auto dot2 = name.rfind(L".q");
                    auto dot = (dot2 == std::wstring::npos) ? std::wstring::npos : name.rfind(L'.', dot2 - 1);
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
                    auto dot2 = name.rfind(L".q");
                    auto dot = (dot2 == std::wstring::npos) ? std::wstring::npos : name.rfind(L'.', dot2 - 1);
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

    if (argc == 1) {
        for (;;) {
            int choice = ShowMenu();
            LogChoice(choice);
            if (choice == 0) return 0;
            if (choice == 1) {
                std::wcout << L"path: ";
                std::wstring p; std::wcin >> p;
                LogInfo(L"menu: scan path requested: " + p);
                std::wcout << L"scanning: " << p << L"\n";
                ScanPathRecursiveNoRecord(p, cfg, sigs);
                std::wcout << L"scan complete\n";
                LogInfo(L"menu: scan path complete");
            } else if (choice == 2) {
                LogInfo(L"menu: full system scan requested");
                std::wcout << L"scanning full system\n";
                for (const auto& drive : GetFixedDrives()) {
                    ScanPathRecursiveNoRecord(drive, cfg, sigs);
                }
                std::wcout << L"scan complete\n";
                LogInfo(L"menu: full system scan complete");
            } else if (choice == 3) {
                LogInfo(L"menu: quarantine list requested");
                ListQuarantine(cfg.quarantine_dir);
            } else if (choice == 4) {
                LogInfo(L"menu: quarantine list-details requested");
                std::wcout << L"listing details\n";
                std::wstring pattern = cfg.quarantine_dir + L"\\*";
                WIN32_FIND_DATAW f{};
                HANDLE h = FindFirstFileW(pattern.c_str(), &f);
                if (h != INVALID_HANDLE_VALUE) {
                    do {
                        if (f.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                        std::wstring name = f.cFileName;
                        auto dot2 = name.rfind(L".q");
                        auto dot = (dot2 == std::wstring::npos) ? std::wstring::npos : name.rfind(L'.', dot2 - 1);
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
            } else if (choice == 5) {
                std::wcout << L"sha256: ";
                std::wstring sha; std::wcin >> sha;
                LogInfo(L"menu: quarantine restore requested: " + sha);
                std::wstring orig;
                if (!LoadQuarantineMeta(sha, orig)) { std::wcout << L"not found\n"; continue; }
                std::wstring qfile;
                if (!FindQuarantineFile(cfg.quarantine_dir, sha, qfile)) { std::wcout << L"not found\n"; continue; }
                MoveFileExW(qfile.c_str(), orig.c_str(), MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING);
                DeleteQuarantineMeta(sha);
                LogInfo(L"menu: quarantine restore complete: " + sha);
            } else if (choice == 6) {
                LogInfo(L"menu: quarantine restore-all requested");
                std::wcout << L"restoring all\n";
                std::wstring pattern = cfg.quarantine_dir + L"\\*";
                WIN32_FIND_DATAW f{};
                HANDLE h = FindFirstFileW(pattern.c_str(), &f);
                if (h != INVALID_HANDLE_VALUE) {
                    do {
                        if (f.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                        std::wstring name = f.cFileName;
                        auto dot2 = name.rfind(L".q");
                        auto dot = (dot2 == std::wstring::npos) ? std::wstring::npos : name.rfind(L'.', dot2 - 1);
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
            } else if (choice == 7) {
                std::wcout << L"sha256: ";
                std::wstring sha; std::wcin >> sha;
                LogInfo(L"menu: quarantine delete requested: " + sha);
                std::wstring qfile;
                if (FindQuarantineFile(cfg.quarantine_dir, sha, qfile)) {
                    DeleteFileW(qfile.c_str());
                    DeleteQuarantineMeta(sha);
                    LogInfo(L"menu: quarantine delete complete: " + sha);
                } else {
                    LogWarn(L"menu: quarantine delete failed (not found): " + sha);
                }
            } else if (choice == 8) {
                LogInfo(L"menu: clean autoruns requested");
                CleanSuspiciousAutoruns();
                LogInfo(L"menu: clean autoruns complete");
            } else if (choice == 9) {
                wchar_t path[MAX_PATH] = {0};
                GetModuleFileNameW(nullptr, path, MAX_PATH);
                LogInfo(L"full install requested");
                CreateDirectoryW(cfg.quarantine_dir.c_str(), nullptr);
                HardenDirectoryAcl(cfg.quarantine_dir);
                HardenInstallDir();
                HardenRegistryAcl();
                if (InstallService(path)) {
                    LogInfo(L"service installed");
                    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
                    if (scm) {
                        SC_HANDLE svc = OpenServiceW(scm, L"AVResearch", SERVICE_START);
                        if (svc) {
                            if (!StartServiceW(svc, 0, nullptr)) {
                                LogError(L"service start failed: " + std::to_wstring(GetLastError()));
                            } else {
                                LogInfo(L"service start requested");
                            }
                            CloseServiceHandle(svc);
                        } else {
                            LogError(L"open service failed: " + std::to_wstring(GetLastError()));
                        }
                        CloseServiceHandle(scm);
                    } else {
                        LogError(L"open scm failed: " + std::to_wstring(GetLastError()));
                    }
                } else {
                    LogError(L"service install failed");
                }
            } else if (choice == 10) {
                LogInfo(L"full uninstall requested");
                if (!UninstallService()) {
                    LogError(L"full uninstall failed");
                } else {
                    LogInfo(L"full uninstall complete");
                }
            } else if (choice == 11) {
                LogInfo(L"menu: show recent logs requested");
                ShowRecentLogs(200);
            } else if (choice == 12) {
                bool now = !IsVerboseLogging();
                SetVerboseLogging(now);
                std::wcout << (now ? L"verbose logging enabled\n" : L"verbose logging disabled\n");
                LogInfo(now ? L"verbose logging enabled" : L"verbose logging disabled");
            }
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

    std::thread([]() {
        while (g_running) {
            Sleep(3600000);
            LogInfo(L"health check ok");
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
