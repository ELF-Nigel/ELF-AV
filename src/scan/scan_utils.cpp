#include "scan/scan_utils.h"
#include "core/logger.h"
#include "scan/protection.h"
#include "ui/notifier.h"
#include <windows.h>
#include <vector>
#include <shlobj.h>

static void HandleScanResult(const std::wstring& path, const Config& cfg, const ScanResult& res, bool record) {
    if (record) RecordFileEvent(path);
    if (!res.malicious) return;

    LogWarn(L"detected: " + path + L" | " + res.reason + L" | " + res.sha256);
    NotifyAlert(L"avresearch alert", L"threat detected: " + path);
    if (cfg.delete_on_signature && res.reason == L"signature match") {
        if (DeleteFileW(path.c_str())) {
            LogInfo(L"deleted: " + path);
            return;
        }
    }
    if (cfg.quarantine_on_detect) {
        if (QuarantineFile(path, cfg.quarantine_dir, res.sha256)) {
            LogInfo(L"quarantined: " + path);
        } else {
            LogError(L"quarantine failed: " + path);
        }
    }
}

void ProcessFileEvent(const std::wstring& path, const Config& cfg, const SignatureDB& sigs) {
    auto res = ScanFile(path, cfg, sigs);
    HandleScanResult(path, cfg, res, true);
}

static bool ScanPathRecursiveImpl(const std::wstring& path, const Config& cfg, const SignatureDB& sigs, bool record) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return false;
    if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        auto res = ScanFile(path, cfg, sigs);
        HandleScanResult(path, cfg, res, record);
        return true;
    }

    std::wstring pattern = path + L"\\*";
    WIN32_FIND_DATAW f{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &f);
    if (h == INVALID_HANDLE_VALUE) return false;
    do {
        std::wstring name = f.cFileName;
        if (name == L"." || name == L"..") continue;
        std::wstring full = path + L"\\" + name;
        if (f.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            ScanPathRecursiveImpl(full, cfg, sigs, record);
        } else {
            auto res = ScanFile(full, cfg, sigs);
            HandleScanResult(full, cfg, res, record);
        }
    } while (FindNextFileW(h, &f));
    FindClose(h);
    return true;
}

bool ScanPathRecursive(const std::wstring& path, const Config& cfg, const SignatureDB& sigs) {
    return ScanPathRecursiveImpl(path, cfg, sigs, true);
}

bool ScanPathRecursiveNoRecord(const std::wstring& path, const Config& cfg, const SignatureDB& sigs) {
    return ScanPathRecursiveImpl(path, cfg, sigs, false);
}

std::vector<std::wstring> GetFixedDrives() {
    std::vector<std::wstring> drives;
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; i++) {
        if (!(mask & (1 << i))) continue;
        wchar_t root[] = { (wchar_t)(L'A' + i), L':', L'\\', L'\0' };
        if (GetDriveTypeW(root) == DRIVE_FIXED) {
            drives.emplace_back(root);
        }
    }
    return drives;
}

std::vector<std::wstring> GetStartupFolders() {
    std::vector<std::wstring> out;
    PWSTR path = nullptr;
    if (SHGetKnownFolderPath(FOLDERID_Startup, 0, nullptr, &path) == S_OK) {
        out.emplace_back(path);
        CoTaskMemFree(path);
    }
    if (out.empty()) {
        wchar_t buf[MAX_PATH] = {0};
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, SHGFP_TYPE_CURRENT, buf))) {
            out.emplace_back(buf);
        }
    }
    path = nullptr;
    if (SHGetKnownFolderPath(FOLDERID_CommonStartup, 0, nullptr, &path) == S_OK) {
        out.emplace_back(path);
        CoTaskMemFree(path);
    }
    if (out.size() < 2) {
        wchar_t buf[MAX_PATH] = {0};
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_STARTUP, nullptr, SHGFP_TYPE_CURRENT, buf))) {
            out.emplace_back(buf);
        }
    }
    return out;
}

void ScanStartupFolders(const Config& cfg, const SignatureDB& sigs) {
    for (const auto& dir : GetStartupFolders()) {
        ScanPathRecursiveNoRecord(dir, cfg, sigs);
    }
}

static std::vector<std::wstring> GetRemovableDrivesOnce() {
    std::vector<std::wstring> drives;
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; i++) {
        if (!(mask & (1 << i))) continue;
        wchar_t root[] = { (wchar_t)(L'A' + i), L':', L'\\', L'\0' };
        if (GetDriveTypeW(root) == DRIVE_REMOVABLE) {
            drives.emplace_back(root);
        }
    }
    return drives;
}

void ScanRemovableDrivesOnce(const Config& cfg, const SignatureDB& sigs) {
    for (const auto& d : GetRemovableDrivesOnce()) {
        ScanPathRecursiveNoRecord(d, cfg, sigs);
    }
}
