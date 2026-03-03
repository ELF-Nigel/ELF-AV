#include "core/utils.h"
#include <algorithm>
#include <cwctype>
#include <windows.h>

std::wstring ToLower(const std::wstring& s) {
    std::wstring out = s;
    std::transform(out.begin(), out.end(), out.begin(), towlower);
    return out;
}

std::wstring Trim(const std::wstring& s) {
    size_t start = 0;
    while (start < s.size() && iswspace(s[start])) start++;
    size_t end = s.size();
    while (end > start && iswspace(s[end - 1])) end--;
    return s.substr(start, end - start);
}

std::vector<std::wstring> Split(const std::wstring& s, wchar_t delim) {
    std::vector<std::wstring> out;
    std::wstring cur;
    for (auto ch : s) {
        if (ch == delim) {
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(ch);
        }
    }
    out.push_back(cur);
    return out;
}

bool FileExists(const std::wstring& path) {
    DWORD attrib = GetFileAttributesW(path.c_str());
    return (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}

uint64_t GetFileSize(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) return 0;
    ULARGE_INTEGER size;
    size.HighPart = data.nFileSizeHigh;
    size.LowPart = data.nFileSizeLow;
    return size.QuadPart;
}

std::wstring ExpandEnvVars(const std::wstring& s) {
    if (s.find(L'%') == std::wstring::npos) return s;
    DWORD needed = ExpandEnvironmentStringsW(s.c_str(), nullptr, 0);
    if (needed == 0) return s;
    std::wstring out;
    out.resize(needed - 1);
    ExpandEnvironmentStringsW(s.c_str(), out.data(), needed);
    return out;
}
