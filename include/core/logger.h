#pragma once
#include <string>

void InitLogger(const std::wstring& log_path);
void LogInfo(const std::wstring& msg);
void LogWarn(const std::wstring& msg);
void LogError(const std::wstring& msg);
