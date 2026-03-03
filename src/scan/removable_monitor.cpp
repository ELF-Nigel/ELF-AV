#include "scan/removable_monitor.h"
#include "scan/scan_utils.h"
#include "core/logger.h"
#include "core/utils.h"
#include "ui/notifier.h"
#include <windows.h>
#include <thread>
#include <unordered_set>
#include <vector>

static std::vector<std::wstring> GetRemovableDrives() {
    std::vector<std::wstring> drives;
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; i++) {
        if (!(mask & (1 << i))) continue;
        wchar_t root[] = { (wchar_t)(L'A' + i), L':', L'\\', L'\0' };
        if (GetDriveTypeW(root) == DRIVE_REMOVABLE) {
            drives.emplace_back(root);
        }
    }
    return drives;
}

bool StartRemovableMonitorThread(const Config& cfg, const SignatureDB& sigs) {
    try {
        std::thread([cfg, &sigs]() {
            std::unordered_set<std::wstring> seen;
            while (true) {
                auto drives = GetRemovableDrives();
                for (const auto& d : drives) {
                    if (seen.insert(d).second) {
                        LogInfo(L"removable drive detected: " + d);
                        NotifyAlert(L"avresearch alert", L"removable drive detected: " + d);
                        ScanPathRecursiveNoRecord(d, cfg, sigs);
                        std::wstring autorun = d + L"autorun.inf";
                        if (FileExists(autorun)) {
                            LogWarn(L"autorun.inf detected: " + autorun);
                            NotifyAlert(L"avresearch alert", L"autorun.inf detected: " + autorun);
                        }
                    }
                }
                Sleep(60000);
            }
        }).detach();
        return true;
    } catch (...) {
        return false;
    }
}
