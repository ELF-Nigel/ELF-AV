#pragma once
#include <string>
#include <vector>
#include <windows.h>

bool VerifySelfSignature();
bool DecryptEmbeddedSignatures(std::vector<std::wstring>& out);
bool HardenDirectoryAcl(const std::wstring& path);
bool EnsureProcessAuditEnabled();
bool GetSelfSha256(std::wstring& out);
bool SaveSignatureBlobToRegistry(const std::wstring& blobPath);
bool LoadSignatureBlobFromRegistry(std::vector<BYTE>& out);
bool SaveQuarantineMeta(const std::wstring& sha256, const std::wstring& originalPath);
bool LoadQuarantineMeta(const std::wstring& sha256, std::wstring& originalPath);
bool DeleteQuarantineMeta(const std::wstring& sha256);
bool SetDirectoryLockdown(const std::wstring& path, bool enable);
bool IsFileSignedPath(const std::wstring& path);
bool CleanSuspiciousAutoruns();
bool EnsureScheduledTask();
bool HardenFileAcl(const std::wstring& path);
bool HardenInstallDir();
bool IsUserWritablePath(const std::wstring& path);
bool HardenRegistryAcl();
