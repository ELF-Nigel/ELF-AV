#include "scan/hosts_monitor.h"
#include "core/logger.h"
#include "ui/notifier.h"
#include <windows.h>
#include <thread>
#include <vector>

static uint64_t FileStamp(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) return 0;
    ULARGE_INTEGER size;
    size.HighPart = data.nFileSizeHigh;
    size.LowPart = data.nFileSizeLow;
    FILETIME ft = data.ftLastWriteTime;
    ULARGE_INTEGER t; t.HighPart = ft.dwHighDateTime; t.LowPart = ft.dwLowDateTime;
    return (t.QuadPart ^ size.QuadPart);
}

bool StartHostsMonitorThread() {
    try {
        std::thread([]() {
            std::wstring hosts = L"C:\\Windows\\System32\\drivers\\etc\\hosts";
            uint64_t baseline = FileStamp(hosts);
            while (true) {
                Sleep(300000);
                auto cur = FileStamp(hosts);
                if (cur != 0 && cur != baseline) {
                    baseline = cur;
                    LogWarn(L"hosts file changed");
                    NotifyAlert(L"avresearch alert", L"hosts file changed");
                }
            }
        }).detach();
        return true;
    } catch (...) {
        return false;
    }
}
