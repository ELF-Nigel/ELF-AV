#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        std::wcerr << L"usage: seal_sigs.exe <signatures.txt> [-o blob.bin]\n";
        return 1;
    }

    std::wifstream in(argv[1]);
    if (!in) {
        std::wcerr << L"failed to open signatures file.\n";
        return 1;
    }

    std::wstringstream ss;
    std::wstring line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == L'#') continue;
        ss << line << L"\n";
    }
    std::wstring content = ss.str();

    DATA_BLOB inBlob{};
    inBlob.pbData = (BYTE*)content.data();
    inBlob.cbData = (DWORD)(content.size() * sizeof(wchar_t));

    DATA_BLOB outBlob{};
    if (!CryptProtectData(&inBlob, L"AVResearchSigs", nullptr, nullptr, nullptr, CRYPTPROTECT_LOCAL_MACHINE, &outBlob)) {
        std::wcerr << L"cryptprotectdata failed.\n";
        return 1;
    }

    if (argc > 3 && std::wstring(argv[2]) == L"-o") {
        std::ofstream out(argv[3], std::ios::binary);
        out.write((const char*)outBlob.pbData, outBlob.cbData);
        out.close();
        std::wcout << L"wrote blob to: " << argv[3] << L"\n";
    } else {
        std::wcout << L"// paste into src/security.cpp as kencryptedsigs\n";
        std::wcout << L"static const BYTE kEncryptedSigs[] = {\n    ";
        for (DWORD i = 0; i < outBlob.cbData; i++) {
            std::wcout << L"0x" << std::hex << std::uppercase << (int)outBlob.pbData[i];
            if (i + 1 < outBlob.cbData) std::wcout << L", ";
            if ((i + 1) % 12 == 0) std::wcout << L"\n    ";
        }
        std::wcout << L"\n};\n";
    }

    LocalFree(outBlob.pbData);
    return 0;
}
