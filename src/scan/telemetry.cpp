#include "scan/telemetry.h"
#include "core/logger.h"
#include <windows.h>
#include <wevtapi.h>
#include <thread>
#include <vector>

#pragma comment(lib, "wevtapi.lib")

static std::wstring ExtractNewProcessName(const std::wstring& xml) {
    const std::wstring tag = L"<Data Name='NewProcessName'>";
    auto pos = xml.find(tag);
    if (pos == std::wstring::npos) return L"";
    pos += tag.size();
    auto end = xml.find(L"</Data>", pos);
    if (end == std::wstring::npos) return L"";
    return xml.substr(pos, end - pos);
}

static void TelemetryLoop(TelemetryCallback cb) {
    // Security Event ID 4688: Process creation (requires auditing enabled).
    const wchar_t* channel = L"Security";
    const wchar_t* query = L"*[System[(EventID=4688)]]";

    EVT_HANDLE hSub = EvtSubscribe(
        nullptr,
        nullptr,
        channel,
        query,
        nullptr,
        nullptr,
        nullptr,
        EvtSubscribeToFutureEvents
    );

    if (!hSub) {
        LogWarn(L"process telemetry unavailable (evtsubscribe failed). ensure auditing is enabled.");
        return;
    }

    while (true) {
        EVT_HANDLE hEvent = nullptr;
        DWORD returned = 0;
        if (!EvtNext(hSub, 1, &hEvent, INFINITE, 0, &returned)) {
            continue;
        }

        DWORD bufSize = 0;
        DWORD used = 0;
        DWORD props = 0;
        EvtRender(nullptr, hEvent, EvtRenderEventXml, 0, nullptr, &used, &props);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::vector<wchar_t> buf(used / sizeof(wchar_t) + 2);
            if (EvtRender(nullptr, hEvent, EvtRenderEventXml, (DWORD)(buf.size() * sizeof(wchar_t)), buf.data(), &used, &props)) {
                std::wstring xml(buf.data());
                auto proc = ExtractNewProcessName(xml);
                if (!proc.empty()) cb(proc);
            }
        }

        if (hEvent) EvtClose(hEvent);
    }
}

bool StartProcessTelemetryThread(TelemetryCallback cb) {
    try {
        std::thread t(TelemetryLoop, cb);
        t.detach();
        return true;
    } catch (...) {
        return false;
    }
}
