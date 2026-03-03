cmake_minimum_required(VERSION 3.20)
project(av_research LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(av_research
    src/app/main.cpp
    src/core/config.cpp
    src/core/utils.cpp
    src/core/logger.cpp
    src/core/security.cpp
    src/core/service.cpp
    src/scan/scanner.cpp
    src/scan/scan_utils.cpp
    src/scan/watcher.cpp
    src/scan/telemetry.cpp
    src/scan/protection.cpp
    src/scan/script_heuristics.cpp
    src/scan/canary.cpp
    src/scan/net_monitor.cpp
    src/scan/registry_monitor.cpp
    src/scan/removable_monitor.cpp
    src/scan/process_monitor.cpp
    src/scan/persistence_monitor.cpp
    src/scan/system_tamper.cpp
    src/scan/credential_monitor.cpp
    src/scan/lsass_monitor.cpp
    src/scan/driver_monitor.cpp
    src/scan/dns_monitor.cpp
    src/scan/hosts_monitor.cpp
    src/scan/task_monitor.cpp
    src/ui/notifier.cpp
)

target_include_directories(av_research PRIVATE include)

target_compile_definitions(av_research PRIVATE UNICODE _UNICODE)

target_link_libraries(av_research PRIVATE bcrypt crypt32 advapi32 wintrust wevtapi shell32 iphlpapi psapi)

# organize visual studio filters without moving files
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR}/src PREFIX "source" FILES
    src/app/main.cpp
    src/core/config.cpp
    src/core/utils.cpp
    src/core/logger.cpp
    src/core/security.cpp
    src/core/service.cpp
    src/scan/scanner.cpp
    src/scan/scan_utils.cpp
    src/scan/watcher.cpp
    src/scan/telemetry.cpp
    src/scan/protection.cpp
    src/ui/notifier.cpp
)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR}/include PREFIX "include" FILES
    include/core/config.h
    include/core/utils.h
    include/core/logger.h
    include/core/security.h
    include/core/service.h
    include/scan/scanner.h
    include/scan/scan_utils.h
    include/scan/watcher.h
    include/scan/telemetry.h
    include/scan/protection.h
    include/scan/script_heuristics.h
    include/scan/canary.h
    include/scan/net_monitor.h
    include/scan/registry_monitor.h
    include/scan/removable_monitor.h
    include/scan/process_monitor.h
    include/scan/persistence_monitor.h
    include/scan/system_tamper.h
    include/scan/credential_monitor.h
    include/scan/lsass_monitor.h
    include/scan/driver_monitor.h
    include/scan/dns_monitor.h
    include/scan/hosts_monitor.h
    include/scan/task_monitor.h
    include/ui/notifier.h
)
