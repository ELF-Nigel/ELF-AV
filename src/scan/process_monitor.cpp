#include "scan/process_monitor.h"
#include "core/security.h"
#include "core/logger.h"
#include "ui/notifier.h"
#include <windows.h>
#include <psapi.h>
#include <thread>
#include <unordered_map>
#include <tlhelp32.h>

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

static bool GetMainModulePath(DWORD pid, std::wstring& out) {
    out.clear();
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return false;
    HMODULE hMod = nullptr;
    DWORD needed = 0;
    if (!EnumProcessModules(h, &hMod, sizeof(hMod), &needed) || !hMod) { CloseHandle(h); return false; }
    wchar_t buf[MAX_PATH];
    if (!GetModuleFileNameExW(h, hMod, buf, MAX_PATH)) { CloseHandle(h); return false; }
    out = buf;
    CloseHandle(h);
    return true;
}

static bool GetProcessImagePath(DWORD pid, std::wstring& out) {
    out.clear();
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    wchar_t buf[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(h, 0, buf, &size)) out.assign(buf, size);
    CloseHandle(h);
    return !out.empty();
}

static std::wstring BaseName(const std::wstring& path) {
    auto pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return ToLowerLocal(path);
    return ToLowerLocal(path.substr(pos + 1));
}

static bool GetProcessInfo(DWORD pid, DWORD& ppid, std::wstring& exeName) {
    ppid = 0; exeName.clear();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                ppid = pe.th32ParentProcessID;
                exeName = ToLowerLocal(pe.szExeFile);
                CloseHandle(snap);
                return true;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return false;
}

bool StartProcessMonitorThread() {
    try {
        std::thread([]() {
            std::unordered_map<DWORD, uint64_t> lastAlert;
            while (true) {
                DWORD pids[2048];
                DWORD bytes = 0;
                if (!EnumProcesses(pids, sizeof(pids), &bytes)) { Sleep(60000); continue; }
                DWORD count = bytes / sizeof(DWORD);
                for (DWORD i = 0; i < count; i++) {
                    DWORD pid = pids[i];
                    if (pid == 0) continue;
                    std::wstring img, mod;
                    if (!GetProcessImagePath(pid, img)) continue;
                    GetMainModulePath(pid, mod);

                    auto imgL = ToLowerLocal(img);
                    auto modL = ToLowerLocal(mod);
                    if (!modL.empty() && imgL != modL) {
                        bool signedOk = IsFileSignedPath(img);
                        if (!signedOk && IsSuspiciousPathLocal(img)) {
                            uint64_t now = GetTickCount64();
                            if (lastAlert.find(pid) == lastAlert.end() || now - lastAlert[pid] > 300000) {
                                lastAlert[pid] = now;
                                LogWarn(L"possible process hollowing: " + img);
                                NotifyAlert(L"avresearch alert", L"possible process hollowing: " + img);
                            }
                        }
                    }

                    DWORD ppid = 0; std::wstring exeName;
                    if (GetProcessInfo(pid, ppid, exeName)) {
                        std::wstring parentPath;
                        GetProcessImagePath(ppid, parentPath);
                        auto parentBase = BaseName(parentPath.empty() ? exeName : parentPath);
                        auto base = BaseName(img);

                        bool isScriptHost = (base == L"powershell.exe" || base == L"pwsh.exe" || base == L"cscript.exe" || base == L"wscript.exe" || base == L"mshta.exe");
                        bool parentOffice = (parentBase == L"winword.exe" || parentBase == L"excel.exe" || parentBase == L"outlook.exe" || parentBase == L"powerpnt.exe");
                        if (isScriptHost && parentOffice) {
                            uint64_t now = GetTickCount64();
                            if (lastAlert.find(pid) == lastAlert.end() || now - lastAlert[pid] > 300000) {
                                lastAlert[pid] = now;
                                LogWarn(L"suspicious office -> script host chain: " + img);
                                NotifyAlert(L"avresearch alert", L"suspicious office -> script host chain: " + img);
                            }
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
