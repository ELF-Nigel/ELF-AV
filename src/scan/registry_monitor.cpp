#include "scan/registry_monitor.h"
#include "core/logger.h"
#include "ui/notifier.h"
#include <windows.h>
#include <thread>
#include <unordered_map>
#include <string>

static std::wstring ReadRegStr(HKEY root, const std::wstring& key, const std::wstring& name) {
    HKEY h = nullptr;
    if (RegOpenKeyExW(root, key.c_str(), 0, KEY_READ, &h) != ERROR_SUCCESS) return L"";
    DWORD type = 0, size = 0;
    if (RegQueryValueExW(h, name.c_str(), nullptr, &type, nullptr, &size) != ERROR_SUCCESS) {
        RegCloseKey(h);
        return L"";
    }
    std::wstring out;
    out.resize(size / sizeof(wchar_t));
    if (RegQueryValueExW(h, name.c_str(), nullptr, &type, (LPBYTE)out.data(), &size) != ERROR_SUCCESS) {
        RegCloseKey(h);
        return L"";
    }
    RegCloseKey(h);
    return out;
}

static std::wstring SnapshotKey() {
    std::wstring snap;
    snap += ReadRegStr(HKEY_LOCAL_MACHINE, L"software\\microsoft\\windows nt\\currentversion\\winlogon", L"shell");
    snap += L"|";
    snap += ReadRegStr(HKEY_LOCAL_MACHINE, L"software\\microsoft\\windows nt\\currentversion\\winlogon", L"userinit");
    snap += L"|";
    snap += ReadRegStr(HKEY_CURRENT_USER, L"software\\microsoft\\windows\\currentversion\\run", L"*");
    snap += L"|";
    snap += ReadRegStr(HKEY_LOCAL_MACHINE, L"software\\microsoft\\windows\\currentversion\\run", L"*");
    return snap;
}

bool StartRegistryMonitorThread() {
    try {
        std::thread([]() {
            std::wstring baseline = SnapshotKey();
            while (true) {
                Sleep(300000);
                std::wstring cur = SnapshotKey();
                if (!cur.empty() && cur != baseline) {
                    baseline = cur;
                    LogWarn(L"registry change detected in critical keys");
                    NotifyAlert(L"avresearch alert", L"registry change detected in critical keys");
                }
            }
        }).detach();
        return true;
    } catch (...) {
        return false;
    }
}
