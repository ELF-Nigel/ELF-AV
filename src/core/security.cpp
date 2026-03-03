#include "core/security.h"
#include "core/logger.h"
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <sddl.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>

#pragma comment(lib, "wintrust.lib")

// NOTE: Replace kEncryptedSigs with output from tools\\seal_sigs.exe
static const BYTE kEncryptedSigs[] = {
    0x01, 0x00, 0x00, 0x00
};
static const size_t kEncryptedSigsLen = sizeof(kEncryptedSigs);

bool DecryptEmbeddedSignatures(std::vector<std::wstring>& out) {
    out.clear();

    std::vector<BYTE> regBlob;
    if (LoadSignatureBlobFromRegistry(regBlob)) {
        DATA_BLOB in{};
        in.pbData = regBlob.data();
        in.cbData = (DWORD)regBlob.size();

        DATA_BLOB outBlob{};
        if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &outBlob)) {
            std::wstring blob((wchar_t*)outBlob.pbData, outBlob.cbData / sizeof(wchar_t));
            LocalFree(outBlob.pbData);

            if (!blob.empty()) VirtualLock(blob.data(), blob.size() * sizeof(wchar_t));
            size_t start = 0;
            while (start < blob.size()) {
                size_t end = blob.find(L'\n', start);
                if (end == std::wstring::npos) end = blob.size();
                std::wstring line = blob.substr(start, end - start);
                if (!line.empty()) out.push_back(line);
                start = end + 1;
            }
            if (!blob.empty()) {
                SecureZeroMemory(blob.data(), blob.size() * sizeof(wchar_t));
                VirtualUnlock(blob.data(), blob.size() * sizeof(wchar_t));
            }
            return true;
        }
    }

    DATA_BLOB in{};
    in.pbData = (BYTE*)kEncryptedSigs;
    in.cbData = (DWORD)kEncryptedSigsLen;

    DATA_BLOB outBlob{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &outBlob)) {
        LogWarn(L"signature blob decrypt failed (expected until sealed).");
        return false;
    }

    std::wstring blob((wchar_t*)outBlob.pbData, outBlob.cbData / sizeof(wchar_t));
    LocalFree(outBlob.pbData);

    if (!blob.empty()) VirtualLock(blob.data(), blob.size() * sizeof(wchar_t));

    size_t start = 0;
    while (start < blob.size()) {
        size_t end = blob.find(L'\n', start);
        if (end == std::wstring::npos) end = blob.size();
        std::wstring line = blob.substr(start, end - start);
        if (!line.empty()) out.push_back(line);
        start = end + 1;
    }
    if (!blob.empty()) {
        SecureZeroMemory(blob.data(), blob.size() * sizeof(wchar_t));
        VirtualUnlock(blob.data(), blob.size() * sizeof(wchar_t));
    }
    return true;
}

bool VerifySelfSignature() {
    wchar_t path[MAX_PATH] = {0};
    if (GetModuleFileNameW(nullptr, path, MAX_PATH) == 0) return false;

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = path;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(WINTRUST_DATA);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwStateAction = WTD_STATEACTION_IGNORE;

    LONG status = WinVerifyTrust(nullptr, &policy, &data);
    if (status != ERROR_SUCCESS) {
        LogWarn(L"binary is not authenticode-signed or signature invalid.");
        return false;
    }
    return true;
}

bool IsFileSignedPath(const std::wstring& path) {
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = path.c_str();

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(WINTRUST_DATA);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwStateAction = WTD_STATEACTION_IGNORE;

    LONG status = WinVerifyTrust(nullptr, &policy, &data);
    return status == ERROR_SUCCESS;
}

bool HardenDirectoryAcl(const std::wstring& path) {
    CreateDirectoryW(path.c_str(), nullptr);

    // Allow only SYSTEM and BUILTIN\\Administrators
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1, &sd, nullptr)) {
        return false;
    }

    PACL dacl = nullptr;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    if (!GetSecurityDescriptorDacl(sd, &daclPresent, &dacl, &daclDefaulted) || !daclPresent) {
        LocalFree(sd);
        return false;
    }

    bool ok = (SetNamedSecurityInfoW(
        (LPWSTR)path.c_str(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr,
        dacl,
        nullptr
    ) == ERROR_SUCCESS);

    LocalFree(sd);
    return ok;
}

static bool RunAuditPol(const std::wstring& args) {
    std::wstring cmd = L"auditpol.exe " + args;
    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return false;
    }
    WaitForSingleObject(pi.hProcess, 5000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code == 0;
}

bool EnsureProcessAuditEnabled() {
    // Enables Security Event ID 4688 (Process Creation)
    bool ok1 = RunAuditPol(L"/set /subcategory:\\\"Process Creation\\\" /success:enable /failure:enable");
    bool ok2 = RunAuditPol(L"/set /subcategory:\\\"Process Termination\\\" /success:enable /failure:enable");
    return ok1 && ok2;
}

bool GetSelfSha256(std::wstring& out) {
    out.clear();
    wchar_t path[MAX_PATH] = {0};
    if (GetModuleFileNameW(nullptr, path, MAX_PATH) == 0) return false;

    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD hashObjectSize = 0, dataLen = 0, hashLen = 0;
    std::vector<uint8_t> hashObject;
    std::vector<uint8_t> hash(32);
    std::vector<uint8_t> buf(1 << 16);
    DWORD read = 0;
    bool ok = false;
    std::wstringstream ss;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) goto cleanup;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectSize, sizeof(DWORD), &dataLen, 0) != 0) goto cleanup;
    if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(DWORD), &dataLen, 0) != 0) goto cleanup;
    hashObject.resize(hashObjectSize);
    hash.resize(hashLen);
    if (BCryptCreateHash(hAlg, &hHash, hashObject.data(), (ULONG)hashObject.size(), nullptr, 0, 0) != 0) goto cleanup;

    while (ReadFile(h, buf.data(), (DWORD)buf.size(), &read, nullptr) && read > 0) {
        if (BCryptHashData(hHash, buf.data(), read, 0) != 0) goto cleanup;
    }
    if (BCryptFinishHash(hHash, hash.data(), (ULONG)hash.size(), 0) != 0) goto cleanup;

    for (auto b : hash) ss << std::hex << std::setw(2) << std::setfill(L'0') << (int)b;
    out = ss.str();
    ok = true;

cleanup:
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static bool OpenSigKey(HKEY root, REGSAM access, HKEY& outKey) {
    const wchar_t* path = L"Software\\AVResearch";
    if (RegCreateKeyExW(root, path, 0, nullptr, 0, access, nullptr, &outKey, nullptr) != ERROR_SUCCESS) {
        return false;
    }
    return true;
}

bool SaveSignatureBlobToRegistry(const std::wstring& blobPath) {
    if (!IsFileSignedPath(blobPath)) {
        LogError(L"signature blob is not authenticode-signed. refusing import.");
        return false;
    }
    HANDLE h = CreateFileW(blobPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD size = GetFileSize(h, nullptr);
    if (size == INVALID_FILE_SIZE || size == 0) { CloseHandle(h); return false; }

    std::vector<BYTE> buf(size);
    DWORD read = 0;
    bool ok = ReadFile(h, buf.data(), size, &read, nullptr) && read == size;
    CloseHandle(h);
    if (!ok) return false;

    HKEY key = nullptr;
    if (OpenSigKey(HKEY_LOCAL_MACHINE, KEY_SET_VALUE, key)) {
        RegSetValueExW(key, L"SigBlob", 0, REG_BINARY, buf.data(), size);
        RegCloseKey(key);
        return true;
    }
    if (OpenSigKey(HKEY_CURRENT_USER, KEY_SET_VALUE, key)) {
        RegSetValueExW(key, L"SigBlob", 0, REG_BINARY, buf.data(), size);
        RegCloseKey(key);
        return true;
    }
    return false;
}

bool LoadSignatureBlobFromRegistry(std::vector<BYTE>& out) {
    out.clear();
    HKEY key = nullptr;
    DWORD type = 0, size = 0;

    if (OpenSigKey(HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, key) == false) {
        if (OpenSigKey(HKEY_CURRENT_USER, KEY_QUERY_VALUE, key) == false) return false;
    }

    if (RegQueryValueExW(key, L"SigBlob", nullptr, &type, nullptr, &size) != ERROR_SUCCESS || type != REG_BINARY || size == 0) {
        RegCloseKey(key);
        return false;
    }
    out.resize(size);
    bool ok = (RegQueryValueExW(key, L"SigBlob", nullptr, &type, out.data(), &size) == ERROR_SUCCESS);
    RegCloseKey(key);
    return ok;
}

static bool EncryptStringToRegistry(const std::wstring& name, const std::wstring& value) {
    DATA_BLOB in{};
    in.pbData = (BYTE*)value.data();
    in.cbData = (DWORD)(value.size() * sizeof(wchar_t));
    DATA_BLOB outBlob{};
    if (!CryptProtectData(&in, L"AVResearchMeta", nullptr, nullptr, nullptr, CRYPTPROTECT_LOCAL_MACHINE, &outBlob)) {
        return false;
    }
    HKEY key = nullptr;
    if (!OpenSigKey(HKEY_LOCAL_MACHINE, KEY_SET_VALUE, key)) {
        if (!OpenSigKey(HKEY_CURRENT_USER, KEY_SET_VALUE, key)) {
            LocalFree(outBlob.pbData);
            return false;
        }
    }
    bool ok = (RegSetValueExW(key, name.c_str(), 0, REG_BINARY, outBlob.pbData, outBlob.cbData) == ERROR_SUCCESS);
    RegCloseKey(key);
    SecureZeroMemory(outBlob.pbData, outBlob.cbData);
    LocalFree(outBlob.pbData);
    return ok;
}

static bool DecryptStringFromRegistry(const std::wstring& name, std::wstring& out) {
    out.clear();
    HKEY key = nullptr;
    DWORD type = 0, size = 0;
    if (!OpenSigKey(HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, key)) {
        if (!OpenSigKey(HKEY_CURRENT_USER, KEY_QUERY_VALUE, key)) return false;
    }
    if (RegQueryValueExW(key, name.c_str(), nullptr, &type, nullptr, &size) != ERROR_SUCCESS || type != REG_BINARY || size == 0) {
        RegCloseKey(key);
        return false;
    }
    std::vector<BYTE> buf(size);
    if (RegQueryValueExW(key, name.c_str(), nullptr, &type, buf.data(), &size) != ERROR_SUCCESS) {
        RegCloseKey(key);
        return false;
    }
    RegCloseKey(key);

    DATA_BLOB in{};
    in.pbData = buf.data();
    in.cbData = (DWORD)buf.size();
    DATA_BLOB outBlob{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &outBlob)) return false;
    out.assign((wchar_t*)outBlob.pbData, outBlob.cbData / sizeof(wchar_t));
    SecureZeroMemory(outBlob.pbData, outBlob.cbData);
    LocalFree(outBlob.pbData);
    return true;
}

bool SaveQuarantineMeta(const std::wstring& sha256, const std::wstring& originalPath) {
    return EncryptStringToRegistry(L"Q_" + sha256, originalPath);
}

bool LoadQuarantineMeta(const std::wstring& sha256, std::wstring& originalPath) {
    return DecryptStringFromRegistry(L"Q_" + sha256, originalPath);
}

bool DeleteQuarantineMeta(const std::wstring& sha256) {
    HKEY key = nullptr;
    if (!OpenSigKey(HKEY_LOCAL_MACHINE, KEY_SET_VALUE, key)) {
        if (!OpenSigKey(HKEY_CURRENT_USER, KEY_SET_VALUE, key)) return false;
    }
    bool ok = (RegDeleteValueW(key, (L"Q_" + sha256).c_str()) == ERROR_SUCCESS);
    RegCloseKey(key);
    return ok;
}

bool SetDirectoryLockdown(const std::wstring& path, bool enable) {
    CreateDirectoryW(path.c_str(), nullptr);
    const wchar_t* sddl_lock = L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;RX;;;AU)(A;;RX;;;BU)";
    const wchar_t* sddl_unlock = L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;AU)(A;;0x1301bf;;;BU)";

    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(enable ? sddl_lock : sddl_unlock, SDDL_REVISION_1, &sd, nullptr)) {
        return false;
    }

    PACL dacl = nullptr;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    if (!GetSecurityDescriptorDacl(sd, &daclPresent, &dacl, &daclDefaulted) || !daclPresent) {
        LocalFree(sd);
        return false;
    }

    bool ok = (SetNamedSecurityInfoW(
        (LPWSTR)path.c_str(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr,
        dacl,
        nullptr
    ) == ERROR_SUCCESS);

    LocalFree(sd);
    return ok;
}

bool IsUserWritablePath(const std::wstring& path) {
    auto p = path;
    std::transform(p.begin(), p.end(), p.begin(), ::towlower);
    return (p.find(L"\\users\\") != std::wstring::npos) ||
           (p.find(L"\\appdata\\") != std::wstring::npos) ||
           (p.find(L"\\temp\\") != std::wstring::npos) ||
           (p.find(L"\\downloads\\") != std::wstring::npos);
}

bool HardenFileAcl(const std::wstring& path) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;BU)(A;;GR;;;AU)", SDDL_REVISION_1, &sd, nullptr)) {
        return false;
    }

    PACL dacl = nullptr;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    if (!GetSecurityDescriptorDacl(sd, &daclPresent, &dacl, &daclDefaulted) || !daclPresent) {
        LocalFree(sd);
        return false;
    }

    bool ok = (SetNamedSecurityInfoW(
        (LPWSTR)path.c_str(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr,
        dacl,
        nullptr
    ) == ERROR_SUCCESS);

    LocalFree(sd);
    return ok;
}

bool HardenInstallDir() {
    wchar_t path[MAX_PATH] = {0};
    if (GetModuleFileNameW(nullptr, path, MAX_PATH) == 0) return false;
    std::wstring exe(path);
    auto pos = exe.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return false;
    std::wstring dir = exe.substr(0, pos);

    // lock down exe and containing dir
    bool ok1 = HardenFileAcl(exe);
    bool ok2 = SetDirectoryLockdown(dir, false);
    return ok1 && ok2;
}

static std::wstring ExtractExePath(const std::wstring& cmd) {
    std::wstring s = cmd;
    s.erase(0, s.find_first_not_of(L" \t"));
    if (s.empty()) return L"";
    if (s[0] == L'\"') {
        auto end = s.find(L'\"', 1);
        if (end != std::wstring::npos) return s.substr(1, end - 1);
    }
    auto end = s.find(L' ');
    return (end == std::wstring::npos) ? s : s.substr(0, end);
}

static bool IsSuspiciousAutorunPath(const std::wstring& path) {
    auto p = path;
    std::transform(p.begin(), p.end(), p.begin(), ::towlower);
    return (p.find(L"\\appdata\\") != std::wstring::npos) ||
           (p.find(L"\\temp\\") != std::wstring::npos) ||
           (p.find(L"\\downloads\\") != std::wstring::npos);
}

static void CleanRunKey(HKEY root, const std::wstring& subkey) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ | KEY_WRITE, &key) != ERROR_SUCCESS) return;

    DWORD idx = 0;
    wchar_t name[256];
    BYTE data[2048];
    DWORD nameLen = 256;
    DWORD dataLen = 2048;
    DWORD type = 0;

    while (RegEnumValueW(key, idx, name, &nameLen, nullptr, &type, data, &dataLen) == ERROR_SUCCESS) {
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            std::wstring cmd((wchar_t*)data, dataLen / sizeof(wchar_t));
            std::wstring exe = ExtractExePath(cmd);
            if (!exe.empty()) {
                if (IsSuspiciousAutorunPath(exe) && !IsFileSignedPath(exe)) {
                    RegDeleteValueW(key, name);
                    LogWarn(L"removed suspicious autorun: " + exe);
                }
            }
        }
        nameLen = 256;
        dataLen = 2048;
        idx++;
    }

    RegCloseKey(key);
}

bool CleanSuspiciousAutoruns() {
    CleanRunKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    CleanRunKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    return true;
}

bool EnsureScheduledTask() {
    wchar_t path[MAX_PATH] = {0};
    if (GetModuleFileNameW(nullptr, path, MAX_PATH) == 0) return false;
    std::wstring cmd = L"/create /f /sc onlogon /rl highest /tn avresearch /tr \\\"";
    cmd += path;
    cmd += L" --service\\\"";

    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    std::wstring full = L"schtasks.exe " + cmd;
    if (!CreateProcessW(nullptr, full.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return false;
    }
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}
