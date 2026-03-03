#pragma once
#include <string>
#include <functional>

using FileEventCallback = std::function<void(const std::wstring& path)>;

bool StartWatchThread(const std::wstring& dir, FileEventCallback cb);
