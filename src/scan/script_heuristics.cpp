#include "scan/scanner.h"
#include "core/utils.h"
#include "core/logger.h"
#include <fstream>
#include <vector>

bool ScriptLooksMalicious(const std::wstring& path) {
    std::wstring lower = ToLower(path);
    if (!(lower.ends_with(L".ps1") || lower.ends_with(L".vbs") || lower.ends_with(L".js"))) return false;

    std::wifstream in(path);
    if (!in) return false;

    std::wstring content, line;
    while (std::getline(in, line)) {
        content += ToLower(line);
        content += L"\n";
        if (content.size() > 1'000'000) break; // limit 1mb
    }

    const wchar_t* patterns[] = {
        L"invoke-expression", L"iex ", L"frombase64string", L"downloadstring",
        L"new-object net.webclient", L"bitsadmin", L"wscript.shell",
        L"powershell -enc", L"regsvr32", L"rundll32", L"schtasks"
    };

    int hits = 0;
    for (auto p : patterns) if (content.find(p) != std::wstring::npos) hits++;

    return hits >= 2;
}
