#include "scan/scanner.h"
#include "core/utils.h"
#include "core/logger.h"
#include <fstream>
#include <vector>

static bool EndsWith(const std::wstring& s, const std::wstring& suffix) {
    if (s.size() < suffix.size()) return false;
    return s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool ScriptLooksMalicious(const std::wstring& path) {
    std::wstring lower = ToLower(path);
    if (!(EndsWith(lower, L".ps1") || EndsWith(lower, L".vbs") || EndsWith(lower, L".js"))) return false;

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
