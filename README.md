# av research prototype (windows, c++)

this is a **research-grade, open-source av prototype** for windows that performs real-time file monitoring and on-access scanning in **user mode**. it is **not** a production antivirus and does not provide the breadth, telemetry, or protections of commercial suites.

## features (mvp)
- real-time directory monitoring (readdirectorychangesw)
- on-access scanning pipeline
- signature detection (sha-256, embedded in code)
- simple heuristic rules (extension + location + entropy)
- suspicious import detection (pe import table heuristics)
- unsigned + suspicious import checks
- ads/double-extension/hidden file heuristics in user paths
- suspicious script content checks (ps1/vbs/js)
- quarantine (move to isolated folder)
- no plaintext config or signature files
- encrypted in-memory signature checks (decrypt per scan, wipe)
- process telemetry via windows event log subscription (etw-backed)
- full system scans (fixed drives) on startup and periodic schedule
- mass-change detector with emergency lockdown (read-only) on watched paths
 - signature matches can be auto-deleted (high confidence)
 - desktop alerts (tray balloon) for detections and lockdowns

## build (windows)

```powershell
mkdir build
cd build
cmake .. -dcmake_build_type=release
cmake --build . --config release
```

## secure signatures (dpapi sealed)
1. create a temporary signature list on a trusted machine (one sha-256 per line).
2. build and run the sealer:
```powershell
cl /ehsc tools\seal_sigs.cpp /link crypt32.lib
tools\seal_sigs.exe c:\temp\signatures.txt
```
3. paste the emitted `kencryptedsigs` array into `src/core/security.cpp`.
4. delete the plaintext file immediately.
5. note: dpapi `local_machine` scope ties the blob to the machine. reseal per target host.

to store the sealed blob in the registry (recommended for updates):
```powershell
tools\seal_sigs.exe c:\temp\signatures.txt -o c:\temp\sigblob.bin
.\build\release\av_research.exe --import-sigs c:\temp\sigblob.bin
del c:\temp\sigblob.bin
```

## run (console)
```powershell
.\build\release\av_research.exe
```

## visual studio 2022 solution
```powershell
powershell -ExecutionPolicy Bypass -File tools\gen_vs2022.ps1
```

## todo (temporary)
- verify ci builds and release artifacts are downloadable
- test scan, quarantine list-details, and restore on vm
- review event log alerts and tray notifications on win11
- validate service hardening and registry acl on clean vm

## on-demand scan
```powershell
.\build\release\av_research.exe --scan c:\path\to\scan
```

## quarantine manager
```powershell
.\build\release\av_research.exe --quarantine list
.\build\release\av_research.exe --quarantine list-details
.\build\release\av_research.exe --quarantine restore <sha256>
.\build\release\av_research.exe --quarantine restore-all
.\build\release\av_research.exe --quarantine delete <sha256>
```
## run as service
```powershell
.\build\release\av_research.exe --install
sc start avresearch
```
to uninstall:
```powershell
.\build\release\av_research.exe --uninstall
```

## installer script (admin)
```powershell
powershell -executionpolicy bypass -file tools\install.ps1 -exepath "c:\program files\avresearch\av_research.exe"
```

## notes
- this project intentionally avoids kernel drivers. for a kernel minifilter, you must create a signed driver and follow microsoft’s wdk guidance.
- use this **only** for legal research and personal experimentation.
 - embedded signatures are dpapi-sealed in `src/core/security.cpp`. replace them with your research data.
 - default watch paths and quarantine dir are set in `src/core/config.cpp`.
 - quarantine acls are hardened to system + administrators only.
 - the binary verifies its authenticode signature at startup (exits if invalid/unsigned).
 - process telemetry uses security event id 4688 (requires auditing enabled).
 - the app attempts to enable process auditing via `auditpol.exe` (admin required).
- the app performs periodic self-integrity checks (sha-256 + signature).
 - signature updates can be imported as dpapi blobs into the registry.
- suspicious autorun entries are removed automatically (unsigned in user/temp paths).
- startup folders are scanned on startup and on schedule.
- canary files are deployed on fixed drives to detect ransomware.
- scheduled task fallback is created for auto-start.
- network anomaly checks for unsigned binaries in user paths.
- registry tamper alerts for critical keys.
- removable drive auto-scan and autorun.inf alerts.
- process hollowing heuristic checks.
- dll side-loading heuristic (unsigned dll in program files).
- persistence audits for services and scheduled tasks.
- script host parent/child anomaly checks (office -> script host).
- system file signature spot-checks (system32).
- browser credential db access alerts.
- lsass-risk process alerts.
- driver load audits.
- dns change monitoring.
- hosts file tamper alerts.
- scheduled task change alerts.
