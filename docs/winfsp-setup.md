# WinFsp Setup

## Runtime prerequisites (end users)

1. Open PowerShell as Administrator.
2. Run:

```powershell
pwsh -NoProfile -File .\scripts\install_prereqs.ps1
```

3. If `WinFsp runtime` is missing, install from:
   - https://winfsp.dev/

4. Re-run the script until all required checks pass.

## Developer prerequisites (native host builds)

1. Install:
   - CMake
   - Visual Studio Build Tools (C++ workload)
   - WinFsp SDK/runtime

2. Validate with:

```powershell
pwsh -NoProfile -File .\scripts\install_prereqs.ps1 -ForDeveloperBuild
```

3. Build host:

```powershell
pwsh -NoProfile -File .\scripts\build_native_host.ps1 -Configuration Release
```

## Native write pilot validation

1. Use `docs/native-write-pilot.md` for hardware + macOS validation sequencing.
2. Record pilot evidence with:

```powershell
pwsh -NoProfile -File .\scripts\update_write_evidence.ps1 -ProfileId "raw::\\.\physicaldrive3::main" -Scenario CrashFault,CrashStageMatrix,HardwarePilot
```

3. Evidence is stored by default at `%ProgramData%\ApfsAccess\write-evidence.json`.
