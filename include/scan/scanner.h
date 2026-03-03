#pragma once
#include <string>
#include "core/config.h"

struct ScanResult {
    bool malicious = false;
    std::wstring reason;
    std::wstring sha256;
};

class SignatureDB {
public:
    void LoadEmbedded();
    bool Has(const std::wstring& sha256) const;
private:
    bool ready_ = false;
};

ScanResult ScanFile(const std::wstring& path, const Config& cfg, const SignatureDB& sigs);
bool QuarantineFile(const std::wstring& path, const std::wstring& quarantine_dir, const std::wstring& sha256);
bool LooksLikeDllSideLoading(const std::wstring& path);
