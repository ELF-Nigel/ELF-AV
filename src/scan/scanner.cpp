#include "scan/scanner.h"
#include "core/utils.h"
#include "core/logger.h"
#include "core/security.h"
#include "scan/protection.h"
#include "scan/script_heuristics.h"
#include <windows.h>
#include <bcrypt.h>
#include <fstream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <unordered_map>
#include <mutex>
#include <wintrust.h>
#include <softpub.h>
#include <algorithm>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")

static std::wstring BytesToHex(const std::vector<uint8_t>& bytes) {
    std::wstringstream ss;
    for (auto b : bytes) {
        ss << std::hex << std::setw(2) << std::setfill(L'0') << (int)b;
    }
    return ss.str();
}

static bool HashSHA256(const std::wstring& path, std::wstring& out_hex) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD hashObjectSize = 0, dataLen = 0, hashLen = 0;
    std::vector<uint8_t> hashObject;
    std::vector<uint8_t> hash(32);
    std::ifstream in;
    std::vector<char> buffer;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return false;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectSize, sizeof(DWORD), &dataLen, 0) != 0) goto cleanup;
    if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(DWORD), &dataLen, 0) != 0) goto cleanup;
    hashObject.resize(hashObjectSize);
    hash.resize(hashLen);

    if (BCryptCreateHash(hAlg, &hHash, hashObject.data(), (ULONG)hashObject.size(), nullptr, 0, 0) != 0) goto cleanup;

    in.open(path, std::ios::binary);
    if (!in) goto cleanup;

    buffer.assign(1 << 16, 0);
    while (in) {
        in.read(buffer.data(), buffer.size());
        std::streamsize got = in.gcount();
        if (got > 0) {
            if (BCryptHashData(hHash, (PUCHAR)buffer.data(), (ULONG)got, 0) != 0) goto cleanup;
        }
    }

    if (BCryptFinishHash(hHash, hash.data(), (ULONG)hash.size(), 0) != 0) goto cleanup;
    out_hex = BytesToHex(hash);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return true;

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return false;
}

static bool IsFileSigned(const std::wstring& path) {
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

static DWORD RvaToOffset(DWORD rva, IMAGE_NT_HEADERS* nt, IMAGE_SECTION_HEADER* sections) {
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD start = sections[i].VirtualAddress;
        DWORD end = start + (std::max)(sections[i].Misc.VirtualSize, sections[i].SizeOfRawData);
        if (rva >= start && rva < end) {
            return sections[i].PointerToRawData + (rva - start);
        }
    }
    return 0;
}

static bool HasSuspiciousImports(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    HANDLE map = CreateFileMappingW(h, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!map) { CloseHandle(h); return false; }
    BYTE* base = (BYTE*)MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    if (!base) { CloseHandle(map); CloseHandle(h); return false; }

    bool suspicious = false;
    auto* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) goto cleanup;
    auto* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) goto cleanup;
    auto* sections = IMAGE_FIRST_SECTION(nt);

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0) goto cleanup;
    DWORD impOffset = RvaToOffset(dir.VirtualAddress, nt, sections);
    if (!impOffset) goto cleanup;

    auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(base + impOffset);
    static const char* kBad[] = {
        "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "NtWriteVirtualMemory",
        "SetWindowsHookExW", "SetWindowsHookExA", "RegSetValueExW", "RegSetValueExA",
        "WinExec", "ShellExecuteW", "ShellExecuteA", "URLDownloadToFileW", "URLDownloadToFileA"
    };

    for (; desc->Name; ++desc) {
        DWORD nameOffset = RvaToOffset(desc->Name, nt, sections);
        if (!nameOffset) continue;
        auto* thunk = (IMAGE_THUNK_DATA*)(base + RvaToOffset(desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk, nt, sections));
        if (!thunk) continue;

        for (; thunk->u1.AddressOfData; ++thunk) {
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) continue;
            auto* imp = (IMAGE_IMPORT_BY_NAME*)(base + RvaToOffset((DWORD)thunk->u1.AddressOfData, nt, sections));
            if (!imp) continue;
            for (auto bad : kBad) {
                if (_stricmp((char*)imp->Name, bad) == 0) {
                    suspicious = true;
                    goto cleanup;
                }
            }
        }
    }

cleanup:
    UnmapViewOfFile(base);
    CloseHandle(map);
    CloseHandle(h);
    return suspicious;
}

static double ShannonEntropy(const std::vector<uint8_t>& data) {
    if (data.empty()) return 0.0;
    double counts[256] = {0};
    for (auto b : data) counts[b]++;
    double ent = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) continue;
        double p = counts[i] / data.size();
        ent -= p * std::log2(p);
    }
    return ent;
}

static bool IsSuspiciousPath(const std::wstring& path) {
    auto p = ToLower(path);
    return (p.find(L"\\downloads\\") != std::wstring::npos) ||
           (p.find(L"\\temp\\") != std::wstring::npos) ||
           (p.find(L"\\appdata\\local\\temp\\") != std::wstring::npos);
}

static bool IsExecutableExt(const std::wstring& path) {
    auto p = ToLower(path);
    auto dot = p.find_last_of(L'.');
    if (dot == std::wstring::npos) return false;
    auto ext = p.substr(dot + 1);
    static const wchar_t* exts[] = {L"exe", L"dll", L"scr", L"com", L"bat", L"cmd", L"ps1", L"vbs", L"js"};
    for (auto e : exts) if (ext == e) return true;
    return false;
}

void SignatureDB::LoadEmbedded() {
    ready_ = true;
}

bool SignatureDB::Has(const std::wstring& sha256) const {
    if (!ready_) return false;

    std::vector<std::wstring> sigs;
    if (!DecryptEmbeddedSignatures(sigs)) return false;

    auto needle = ToLower(sha256);
    bool hit = false;
    for (auto& s : sigs) {
        if (!s.empty()) VirtualLock(s.data(), s.size() * sizeof(wchar_t));
        auto t = ToLower(Trim(s));
        if (!t.empty() && t == needle) {
            hit = true;
            break;
        }
    }

    for (auto& s : sigs) {
        if (!s.empty()) {
            SecureZeroMemory(s.data(), s.size() * sizeof(wchar_t));
            VirtualUnlock(s.data(), s.size() * sizeof(wchar_t));
        }
    }
    sigs.clear();
    sigs.shrink_to_fit();

    return hit;
}

static std::mutex g_cacheMu;
static std::unordered_map<std::wstring, uint64_t> g_recentScan;
static const uint64_t kRescanMs = 10000;

static bool ShouldScan(const std::wstring& path) {
    uint64_t now = GetTickCount64();
    std::lock_guard<std::mutex> lock(g_cacheMu);
    auto it = g_recentScan.find(path);
    if (it != g_recentScan.end() && (now - it->second) < kRescanMs) return false;
    g_recentScan[path] = now;
    if (g_recentScan.size() > 4096) g_recentScan.clear();
    return true;
}

static bool HasAlternateDataStreams(const std::wstring& path) {
    WIN32_FIND_STREAM_DATA data{};
    HANDLE h = FindFirstStreamW(path.c_str(), FindStreamInfoStandard, &data, 0);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool has_ads = false;
    do {
        std::wstring name = data.cStreamName;
        if (name != L"::$DATA") {
            has_ads = true;
            break;
        }
    } while (FindNextStreamW(h, &data));
    FindClose(h);
    return has_ads;
}

static bool IsDoubleExtension(const std::wstring& path) {
    auto p = ToLower(path);
    static const wchar_t* bait[] = {L"pdf", L"doc", L"docx", L"xls", L"xlsx", L"txt", L"jpg", L"png", L"mp4"};
    auto last = p.find_last_of(L'.');
    if (last == std::wstring::npos) return false;
    auto prev = p.find_last_of(L'.', last - 1);
    if (prev == std::wstring::npos) return false;
    auto ext1 = p.substr(prev + 1, last - prev - 1);
    auto ext2 = p.substr(last + 1);
    bool exec = false;
    for (auto e : {L"exe", L"scr", L"com", L"bat", L"cmd", L"ps1", L"vbs", L"js"}) {
        if (ext2 == e) { exec = true; break; }
    }
    if (!exec) return false;
    for (auto b : bait) if (ext1 == b) return true;
    return false;
}

static bool IsHiddenOrSystem(const std::wstring& path) {
    DWORD a = GetFileAttributesW(path.c_str());
    if (a == INVALID_FILE_ATTRIBUTES) return false;
    return (a & FILE_ATTRIBUTE_HIDDEN) || (a & FILE_ATTRIBUTE_SYSTEM);
}

static int FileAgeMinutes(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return -1;
    FILETIME ct{}, at{}, wt{};
    if (!GetFileTime(h, &ct, &at, &wt)) { CloseHandle(h); return -1; }
    CloseHandle(h);
    FILETIME nowFt{};
    GetSystemTimeAsFileTime(&nowFt);
    ULARGE_INTEGER n{}, c{};
    n.HighPart = nowFt.dwHighDateTime; n.LowPart = nowFt.dwLowDateTime;
    c.HighPart = ct.dwHighDateTime; c.LowPart = ct.dwLowDateTime;
    if (n.QuadPart < c.QuadPart) return -1;
    uint64_t diff = n.QuadPart - c.QuadPart;
    return (int)(diff / 600000000ULL); // 100ns to minutes
}

static bool EndsWith(const std::wstring& s, const std::wstring& suffix) {
    if (s.size() < suffix.size()) return false;
    return s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool LooksLikeDllSideLoading(const std::wstring& path) {
    auto p = ToLower(path);
    if (!EndsWith(p, L".dll")) return false;
    if (p.find(L"\\windows\\system32\\") != std::wstring::npos) return false;
    if (p.find(L"\\program files\\") == std::wstring::npos) return false;
    if (IsFileSigned(path)) return false;
    return true;
}

ScanResult ScanFile(const std::wstring& path, const Config& cfg, const SignatureDB& sigs) {
    ScanResult result;
    if (!FileExists(path)) return result;
    if (!ShouldScan(path)) return result;

    uint64_t size = GetFileSize(path);
    if (size > cfg.max_file_mb * 1024ull * 1024ull) return result;

    std::wstring sha256;
    if (!HashSHA256(path, sha256)) return result;
    result.sha256 = sha256;

    if (sigs.Has(sha256)) {
        result.malicious = true;
        result.reason = L"signature match";
        return result;
    }

    // heuristic: executable from suspicious path + high entropy
    bool exec = IsExecutableExt(path);
    bool suspicious = IsSuspiciousPath(path);

    size_t sample_bytes = cfg.entropy_sample_mb * 1024ull * 1024ull;
    std::vector<uint8_t> sample;
    sample.reserve(sample_bytes);

    std::ifstream in(path, std::ios::binary);
    if (in) {
        std::vector<char> buf(1 << 16);
        while (in && sample.size() < sample_bytes) {
            in.read(buf.data(), buf.size());
            std::streamsize got = in.gcount();
            if (got <= 0) break;
            size_t to_copy = (size_t)got;
            if (sample.size() + to_copy > sample_bytes) to_copy = sample_bytes - sample.size();
            sample.insert(sample.end(), buf.begin(), buf.begin() + to_copy);
        }
    }

    double ent = ShannonEntropy(sample);
    if (exec && suspicious && ent > 7.2) {
        result.malicious = true;
        result.reason = L"heuristic: exec in suspicious path + high entropy";
    }

    if (!result.malicious && exec) {
        bool signedOk = IsFileSigned(path);
        if (!signedOk && IsSuspiciousPath(path) && HasSuspiciousImports(path)) {
            result.malicious = true;
            result.reason = L"heuristic: unsigned + suspicious imports + user path";
        }
    }

    if (!result.malicious && exec) {
        bool signedOk = IsFileSigned(path);
        if (!signedOk && (IsDoubleExtension(path) || HasAlternateDataStreams(path) || IsHiddenOrSystem(path)) && IsSuspiciousPath(path)) {
            result.malicious = true;
            result.reason = L"heuristic: unsigned + ads/doubleext/hidden in user path";
        }
    }

    if (!result.malicious && exec) {
        bool signedOk = IsFileSigned(path);
        int ageMin = FileAgeMinutes(path);
        if (!signedOk && IsSuspiciousPath(path) && ageMin >= 0 && ageMin <= 10) {
            result.malicious = true;
            result.reason = L"heuristic: new unsigned executable in user path";
        }
    }

    if (!result.malicious && ScriptLooksMalicious(path) && IsSuspiciousPath(path)) {
        result.malicious = true;
        result.reason = L"heuristic: suspicious script content";
    }

    if (!result.malicious && LooksLikeDllSideLoading(path)) {
        result.malicious = true;
        result.reason = L"heuristic: unsigned dll in program files";
    }

    // Heuristic: during mass-change, high-entropy non-executable files likely ransomware
    if (!result.malicious && IsMassChangeActive() && !exec && ent > 7.6) {
        result.malicious = true;
        result.reason = L"heuristic: mass-change + high entropy";
    }

    return result;
}

bool QuarantineFile(const std::wstring& path, const std::wstring& quarantine_dir, const std::wstring& sha256) {
    CreateDirectoryW(quarantine_dir.c_str(), nullptr);

    std::wstring base = path;
    auto pos = base.find_last_of(L"\\/");
    if (pos != std::wstring::npos) base = base.substr(pos + 1);

    std::wstring target = quarantine_dir + L"\\" + base + L"." + sha256 + L".q";
    if (MoveFileExW(path.c_str(), target.c_str(), MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING)) {
        SaveQuarantineMeta(sha256, path);
        return true;
    }
    return false;
}
