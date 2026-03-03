#include "core/config.h"
#include "core/utils.h"
#include <windows.h>

Config DefaultConfig() {
    Config cfg;
    std::wstring user = L"%USERNAME%";
    cfg.watch_paths.push_back(ExpandEnvVars(L"C:\\\\Users\\\\%USERNAME%\\\\Downloads"));
    cfg.watch_paths.push_back(ExpandEnvVars(L"C:\\\\Users\\\\%USERNAME%\\\\Desktop"));
    cfg.quarantine_dir = L"C:\\\\av_quarantine";
    cfg.quarantine_on_detect = true;
    cfg.max_file_mb = 50;
    cfg.entropy_sample_mb = 1;
    cfg.periodic_scan_minutes = 360;
    cfg.mass_change_threshold = 200;
    cfg.mass_change_window_seconds = 60;
    cfg.lockdown_cooldown_minutes = 30;
    cfg.delete_on_signature = true;
    return cfg;
}
