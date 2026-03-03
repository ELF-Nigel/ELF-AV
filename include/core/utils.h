#pragma once
#include <string>
#include <vector>

std::wstring ToLower(const std::wstring& s);
std::wstring Trim(const std::wstring& s);
std::vector<std::wstring> Split(const std::wstring& s, wchar_t delim);
bool FileExists(const std::wstring& path);
uint64_t GetFileSize(const std::wstring& path);
std::wstring ExpandEnvVars(const std::wstring& s);
