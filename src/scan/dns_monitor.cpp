#include "scan/dns_monitor.h"
#include "core/logger.h"
#include "ui/notifier.h"
#include <windows.h>
#include <iphlpapi.h>
#include <thread>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")

static std::wstring SnapshotDns() {
    std::wstring snap;
    ULONG size = 0;
    GetNetworkParams(nullptr, &size);
    if (size == 0) return snap;
    std::vector<BYTE> buf(size);
    auto* info = (FIXED_INFO*)buf.data();
    if (GetNetworkParams(info, &size) != NO_ERROR) return snap;
    IP_ADDR_STRING* dns = &info->DnsServerList;
    while (dns) {
        snap += std::wstring(dns->IpAddress.String, dns->IpAddress.String + strlen(dns->IpAddress.String));
        snap += L"|";
        dns = dns->Next;
    }
    return snap;
}

bool StartDnsMonitorThread() {
    try {
        std::thread([]() {
            std::wstring baseline = SnapshotDns();
            while (true) {
                Sleep(300000);
                auto cur = SnapshotDns();
                if (!cur.empty() && cur != baseline) {
                    baseline = cur;
                    LogWarn(L"dns settings changed");
                    NotifyAlert(L"avresearch alert", L"dns settings changed");
                }
            }
        }).detach();
        return true;
    } catch (...) {
        return false;
    }
}
