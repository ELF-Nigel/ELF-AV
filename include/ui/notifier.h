#pragma once
#include <string>

void InitNotifier();
void NotifyAlert(const std::wstring& title, const std::wstring& message);
