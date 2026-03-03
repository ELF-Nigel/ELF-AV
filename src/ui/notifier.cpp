#include "ui/notifier.h"
#include <windows.h>
#include <shellapi.h>

static HWND g_hwnd = nullptr;
static UINT g_msg = WM_USER + 100;

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    return DefWindowProcW(hwnd, msg, wp, lp);
}

void InitNotifier() {
    if (g_hwnd) return;
    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"AVResearchNotifier";
    RegisterClassW(&wc);
    g_hwnd = CreateWindowExW(0, wc.lpszClassName, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, wc.hInstance, nullptr);

    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = g_msg;
    nid.hIcon = LoadIconW(nullptr, IDI_WARNING);
    wcscpy_s(nid.szTip, L"avresearch");
    Shell_NotifyIconW(NIM_ADD, &nid);
}

void NotifyAlert(const std::wstring& title, const std::wstring& message) {
    if (!g_hwnd) {
        MessageBoxW(nullptr, message.c_str(), title.c_str(), MB_OK | MB_ICONWARNING | MB_TOPMOST);
        return;
    }
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_INFO;
    wcsncpy_s(nid.szInfoTitle, title.c_str(), _TRUNCATE);
    wcsncpy_s(nid.szInfo, message.c_str(), _TRUNCATE);
    nid.dwInfoFlags = NIIF_WARNING;
    Shell_NotifyIconW(NIM_MODIFY, &nid);
}
