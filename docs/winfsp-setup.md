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

APFS Access applies its write-safety and recovery checks automatically. Do not edit its validation or recovery state by hand.
