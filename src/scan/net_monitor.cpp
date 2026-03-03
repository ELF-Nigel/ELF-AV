#include "scan/net_monitor.h"
#include "core/security.h"
#include "core/logger.h"
#include "ui/notifier.h"
#include <windows.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <thread>
#include <unordered_map>
#include <string>

#pragma comment(lib, "iphlpapi.lib")

static std::wstring ToLowerLocal(const std::wstring& s) {
    std::wstring out = s;
    for (auto& c : out) c = (wchar_t)towlower(c);
    return out;
}

static bool IsSuspiciousPathLocal(const std::wstring& path) {
    auto p = ToLowerLocal(path);
    return (p.find(L"\\appdata\\") != std::wstring::npos) ||
           (p.find(L"\\temp\\") != std::wstring::npos) ||
           (p.find(L"\\downloads\\") != std::wstring::npos);
}

static std::wstring ProcPathFromPid(DWORD pid) {
    std::wstring out;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return out;
    wchar_t buf[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(h, 0, buf, &size)) {
        out.assign(buf, size);
    }
    CloseHandle(h);
    return out;
}

bool StartNetworkMonitorThread() {
    try {
        std::thread([]() {
            std::unordered_map<std::wstring, uint64_t> lastAlert;
            while (true) {
                DWORD size = 0;
                GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                if (size == 0) { Sleep(60000); continue; }
                auto buf = std::unique_ptr<BYTE[]>(new BYTE[size]);
                if (GetExtendedTcpTable(buf.get(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
                    Sleep(60000);
                    continue;
                }

                auto* table = (PMIB_TCPTABLE_OWNER_PID)buf.get();
                for (DWORD i = 0; i < table->dwNumEntries; i++) {
                    auto& row = table->table[i];
                    if (row.dwState != MIB_TCP_STATE_ESTAB) continue;
                    std::wstring path = ProcPathFromPid(row.dwOwningPid);
                    if (path.empty()) continue;

                    bool signedOk = IsFileSignedPath(path);
                    if (!signedOk && IsSuspiciousPathLocal(path)) {
                        std::wstring key = path;
                        uint64_t now = GetTickCount64();
                        if (lastAlert.find(key) == lastAlert.end() || now - lastAlert[key] > 300000) {
                            lastAlert[key] = now;
                            LogWarn(L"suspicious outbound connection: " + path);
                            NotifyAlert(L"avresearch alert", L"suspicious outbound connection: " + path);
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
