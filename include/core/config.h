#pragma once
#include <string>
#include <vector>

struct Config {
    std::vector<std::wstring> watch_paths;
    std::wstring quarantine_dir;
    bool quarantine_on_detect = true;
    size_t max_file_mb = 50;
    size_t entropy_sample_mb = 1;
    uint32_t periodic_scan_minutes = 360;
    uint32_t mass_change_threshold = 200;
    uint32_t mass_change_window_seconds = 60;
    uint32_t lockdown_cooldown_minutes = 30;
    bool delete_on_signature = true;
};

Config DefaultConfig();
