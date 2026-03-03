#include "scan/task_monitor.h"
#include "core/logger.h"
#include "ui/notifier.h"
#include <windows.h>
#include <thread>
#include <vector>
#include <string>

static std::wstring RunAndCapture(const std::wstring& cmd) {
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE readPipe = nullptr, writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) return L"";
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;

    std::wstring full = cmd;
    if (!CreateProcessW(nullptr, full.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(readPipe); CloseHandle(writePipe);
        return L"";
    }
    CloseHandle(writePipe);

    std::wstring out;
    wchar_t buf[1024];
    DWORD read = 0;
    while (ReadFile(readPipe, buf, sizeof(buf) - sizeof(wchar_t), &read, nullptr) && read > 0) {
        out.append(buf, buf + (read / sizeof(wchar_t)));
    }
    CloseHandle(readPipe);

    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return out;
}

bool StartTaskMonitorThread() {
    try {
        std::thread([]() {
            std::wstring baseline = RunAndCapture(L"cmd /c schtasks /query /fo list /v");
            while (true) {
                Sleep(600000);
                std::wstring cur = RunAndCapture(L"cmd /c schtasks /query /fo list /v");
                if (!cur.empty() && cur != baseline) {
                    baseline = cur;
                    LogWarn(L"scheduled tasks changed");
                    NotifyAlert(L"avresearch alert", L"scheduled tasks changed");
                }
            }
        }).detach();
        return true;
    } catch (...) {
        return false;
    }
}
