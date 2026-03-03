#pragma once
#include <string>
#include "core/config.h"
#include "scan/scanner.h"

bool ScanPathRecursive(const std::wstring& path, const Config& cfg, const SignatureDB& sigs);
void ProcessFileEvent(const std::wstring& path, const Config& cfg, const SignatureDB& sigs);
std::vector<std::wstring> GetFixedDrives();
bool ScanPathRecursiveNoRecord(const std::wstring& path, const Config& cfg, const SignatureDB& sigs);
std::vector<std::wstring> GetStartupFolders();
void ScanStartupFolders(const Config& cfg, const SignatureDB& sigs);
void ScanRemovableDrivesOnce(const Config& cfg, const SignatureDB& sigs);
