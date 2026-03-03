#pragma once
#include <string>
#include <functional>

using TelemetryCallback = std::function<void(const std::wstring& path)>;

bool StartProcessTelemetryThread(TelemetryCallback cb);
