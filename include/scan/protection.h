#pragma once
#include <string>
#include "core/config.h"

void InitProtection(const Config& cfg);
void StartProtectionThread();
void RecordFileEvent(const std::wstring& path);
bool IsMassChangeActive();
