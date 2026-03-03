#include "scan/system_tamper.h"
#include "core/security.h"
#include "core/logger.h"
#include "ui/notifier.h"
#include <windows.h>
#include <thread>
#include <vector>

static void CheckSystemFilesOnce() {
    const wchar_t* files[] = {
        L"C:\\Windows\\System32\\cmd.exe",
        L"C:\\Windows\\System32\\powershell.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        L"C:\\Windows\\System32\\lsass.exe",
        L"C:\\Windows\\System32\\rundll32.exe"
    };

    for (auto f : files) {
        DWORD attr = GetFileAttributesW(f);
        if (attr == INVALID_FILE_ATTRIBUTES) {
            LogWarn(L"system file missing: " + std::wstring(f));
            NotifyAlert(L"avresearch alert", L"system file missing: " + std::wstring(f));
            continue;
        }
        if (!IsFileSignedPath(f)) {
            LogWarn(L"system file unsigned: " + std::wstring(f));
            NotifyAlert(L"avresearch alert", L"system file unsigned: " + std::wstring(f));
        }
    }
}

bool StartSystemTamperThread() {
    try {
        std::thread([]() {
            while (true) {
                CheckSystemFilesOnce();
                Sleep(3600000);
            }
        }).detach();
        return true;
    } catch (...) {
        return false;
    }
}
