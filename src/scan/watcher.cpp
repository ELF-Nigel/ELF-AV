#include "scan/watcher.h"
#include "core/logger.h"
#include <windows.h>
#include <thread>
#include <vector>

static void WatchLoop(std::wstring dir, FileEventCallback cb) {
    HANDLE hDir = CreateFileW(
        dir.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        LogError(L"Failed to open watch dir: " + dir);
        return;
    }

    const DWORD bufSize = 64 * 1024;
    std::vector<BYTE> buffer(bufSize);
    DWORD bytesReturned = 0;

    while (true) {
        BOOL ok = ReadDirectoryChangesW(
            hDir,
            buffer.data(),
            bufSize,
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
            &bytesReturned,
            nullptr,
            nullptr
        );
        if (!ok) {
            LogError(L"ReadDirectoryChangesW failed for: " + dir);
            break;
        }

        DWORD offset = 0;
        while (offset < bytesReturned) {
            auto* info = (FILE_NOTIFY_INFORMATION*)(buffer.data() + offset);
            std::wstring name(info->FileName, info->FileNameLength / sizeof(WCHAR));
            std::wstring full = dir + L"\\" + name;

            if (info->Action == FILE_ACTION_ADDED || info->Action == FILE_ACTION_MODIFIED || info->Action == FILE_ACTION_RENAMED_NEW_NAME) {
                cb(full);
            }

            if (info->NextEntryOffset == 0) break;
            offset += info->NextEntryOffset;
        }
    }

    CloseHandle(hDir);
}

bool StartWatchThread(const std::wstring& dir, FileEventCallback cb) {
    try {
        std::thread t(WatchLoop, dir, cb);
        t.detach();
        return true;
    } catch (...) {
        return false;
    }
}
