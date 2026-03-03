#pragma once
#include <string>

bool RunAsService();
bool InstallService(const std::wstring& binPath);
bool UninstallService();
bool EnsureServiceRunning();
