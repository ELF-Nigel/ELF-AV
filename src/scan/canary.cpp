#include "core/utils.h"
#include "core/logger.h"
#include "scan/protection.h"
#include "ui/notifier.h"
#include <windows.h>
#include <vector>

static std::vector<std::wstring> g_canaries;

static std::wstring CanaryPath(const std::wstring& dir) {
    return dir + L"\\.avresearch_canary";
}

void InitCanaries(const std::vector<std::wstring>& roots) {
    g_canaries.clear();
    for (const auto& r : roots) {
        std::wstring p = CanaryPath(r);
        HANDLE h = CreateFileW(p.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            const char* tag = "avresearch canary";
            DWORD wrote = 0;
            WriteFile(h, tag, (DWORD)strlen(tag), &wrote, nullptr);
            CloseHandle(h);
            g_canaries.push_back(p);
        }
    }
}

void CheckCanaries() {
    for (const auto& p : g_canaries) {
        if (!FileExists(p)) {
            LogError(L"canary missing: " + p);
            NotifyAlert(L"avresearch alert", L"canary missing. possible ransomware activity.");
            RecordFileEvent(p);
        }
    }
}
