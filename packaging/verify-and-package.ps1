$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Set-Location (Split-Path $PSScriptRoot -Parent)
$project = 'src/Hadramout.Desktop/Hadramout.Desktop.csproj'
$root = Join-Path (Get-Location) 'artifacts'
if (Test-Path $root) { throw 'Artifact directory must be clean.' }
New-Item -ItemType Directory -Path $root | Out-Null
function Invoke-Checked([string] $Executable, [string[]] $Arguments) {
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Executable failed ($LASTEXITCODE)" }
}
# Separate the lightweight shell check from independent native/crypto/storage probes.
# Every stage still has the original hard 30-second bound, with no retries or skips.
$evidenceRoot = Join-Path $root 'smoke-evidence'
New-Item -ItemType Directory -Path $evidenceRoot | Out-Null
$smokeStages = @('shell','database','credential','backup','encrypted-backup','restore-credential','managed-startup')
function Invoke-Smoke([string] $Exe, [string] $Arch) {
    $label = Split-Path (Split-Path $Exe -Parent) -Leaf
    foreach ($stage in $smokeStages) {
        $trace = Join-Path $evidenceRoot "$label-$stage.log"
        if (Test-Path $trace) { throw "Duplicate smoke evidence path: $trace" }
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Host "Smoke START $label/$Arch/$stage (30s limit)"
        $p = $null
        try {
            $p = Start-Process -FilePath $Exe -ArgumentList @('--smoke-stage', $Arch, $stage, ('"' + $trace + '"')) -PassThru
            if (-not $p.WaitForExit(30000)) {
                if (-not $p.HasExited) {
                    try { $p.Kill($true) } catch [System.InvalidOperationException] {
                        if (-not $p.HasExited) { throw }
                    }
                    if (-not $p.WaitForExit(5000)) { throw "Smoke process could not be stopped: $label/$stage" }
                }
                throw "Smoke timeout: $label/$Arch/$stage after $($timer.ElapsedMilliseconds)ms"
            }
            if ($p.ExitCode -ne 0) { throw "Smoke failed: $label/$Arch/$stage ($($p.ExitCode))" }
            if (-not (Test-Path $trace -PathType Leaf)) { throw "Missing smoke evidence: $label/$stage" }
            $lines = @(Get-Content -LiteralPath $trace)
            if ($lines.Count -ne 2 -or $lines[0] -ne "START $stage $Arch" -or
                $lines[1] -notmatch ('^PASS ' + [regex]::Escape($stage) + ' [0-9]+ms
# Complete all pre-package tests before creating final packages.
Invoke-Checked 'dotnet' @('test','Hadramout.slnx','-c','Release','--logger','trx')
foreach ($arch in @('x86','x64')) {
    $probe = Join-Path $root "probe-$arch"
    Invoke-Checked 'dotnet' @('build',$project,'-c','Release','-r',"win-$arch",'--self-contained','true','-o',$probe)
    Invoke-Smoke (Join-Path $probe 'HadramoutMikroTik.exe') $arch
}
$release = Join-Path $root 'release'
New-Item -ItemType Directory -Path $release | Out-Null
$iscc = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Inno Setup 6\ISCC.exe'
if (-not (Test-Path $iscc)) { throw 'Inno Setup 6 compiler not found.' }
foreach ($arch in @('x86','x64')) {
    $payload = Join-Path $root "publish-$arch"
    Invoke-Checked 'dotnet' @('publish',$project,'-c','Release','-r',"win-$arch",'--self-contained','true','-p:PublishTrimmed=false','-p:PublishReadyToRun=false','-o',$payload)
    Invoke-Smoke (Join-Path $payload 'HadramoutMikroTik.exe') $arch
    $zip = Join-Path $release "HadramoutMikroTik-$arch-Portable.zip"
    Compress-Archive -Path (Join-Path $payload '*') -DestinationPath $zip
    $expanded = Join-Path $root "expanded-$arch"
    Expand-Archive -Path $zip -DestinationPath $expanded
    Invoke-Smoke (Join-Path $expanded 'HadramoutMikroTik.exe') $arch
    Invoke-Checked $iscc @("/DArch=$arch","/DPayload=$payload","/DOutputPath=$release",'packaging/Hadramout.iss')
    $setup = Join-Path $release "HadramoutMikroTik-$arch-Setup.exe"
    $installDir = Join-Path $root "installed-$arch"
    $proc = Start-Process -FilePath $setup -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /DIR=""$installDir""" -Wait -PassThru
    if ($proc.ExitCode -ne 0) { throw "Installer failed: $arch" }
    Invoke-Smoke (Join-Path $installDir 'HadramoutMikroTik.exe') $arch
    $proc = Start-Process -FilePath (Join-Path $installDir 'unins000.exe') -ArgumentList '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART' -Wait -PassThru
    if ($proc.ExitCode -ne 0 -or (Test-Path (Join-Path $installDir 'HadramoutMikroTik.exe'))) { throw "Uninstall failed: $arch" }
}
# Require all seven successful receipts for all eight architecture/package checks.
$expectedSmokeLabels = @('probe-x86','probe-x64','publish-x86','publish-x64','expanded-x86','expanded-x64','installed-x86','installed-x64')
foreach ($label in $expectedSmokeLabels) {
    foreach ($stage in $smokeStages) {
        $trace = Join-Path $evidenceRoot "$label-$stage.log"
        if (-not (Test-Path $trace -PathType Leaf)) { throw "Missing required smoke receipt: $label/$stage" }
    }
}
if (@(Get-ChildItem -File $evidenceRoot).Count -ne ($expectedSmokeLabels.Count * $smokeStages.Count)) {
    throw 'Unexpected smoke evidence count.'
}
$expected = @('HadramoutMikroTik-x86-Portable.zip','HadramoutMikroTik-x86-Setup.exe','HadramoutMikroTik-x64-Portable.zip','HadramoutMikroTik-x64-Setup.exe')
if (@(Get-ChildItem -File $release).Count -ne 4) { throw 'Expected exactly four packages.' }
$hashes = foreach ($name in $expected) {
    $file = Join-Path $release $name
    if (-not (Test-Path $file -PathType Leaf)) { throw "Missing $name" }
    (Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $name
}
$hashes | Set-Content -Encoding ascii (Join-Path $release 'SHA256SUMS.txt')
)) {
                throw "Invalid smoke completion evidence: $label/$stage"
            }
            Write-Host "Smoke PASS $label/$Arch/$stage in $($timer.ElapsedMilliseconds)ms"
        }
        finally {
            if (Test-Path $trace -PathType Leaf) { Get-Content -LiteralPath $trace | Write-Host }
            else { Write-Host "No application progress recorded for $label/$Arch/$stage" }
            if ($null -ne $p) { $p.Dispose() }
        }
    }
}
# Complete all pre-package tests before creating final packages.
Invoke-Checked 'dotnet' @('test','Hadramout.slnx','-c','Release','--logger','trx')
foreach ($arch in @('x86','x64')) {
    $probe = Join-Path $root "probe-$arch"
    Invoke-Checked 'dotnet' @('build',$project,'-c','Release','-r',"win-$arch",'--self-contained','true','-o',$probe)
    Invoke-Smoke (Join-Path $probe 'HadramoutMikroTik.exe') $arch
}
$release = Join-Path $root 'release'
New-Item -ItemType Directory -Path $release | Out-Null
$iscc = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Inno Setup 6\ISCC.exe'
if (-not (Test-Path $iscc)) { throw 'Inno Setup 6 compiler not found.' }
foreach ($arch in @('x86','x64')) {
    $payload = Join-Path $root "publish-$arch"
    Invoke-Checked 'dotnet' @('publish',$project,'-c','Release','-r',"win-$arch",'--self-contained','true','-p:PublishTrimmed=false','-p:PublishReadyToRun=false','-o',$payload)
    Invoke-Smoke (Join-Path $payload 'HadramoutMikroTik.exe') $arch
    $zip = Join-Path $release "HadramoutMikroTik-$arch-Portable.zip"
    Compress-Archive -Path (Join-Path $payload '*') -DestinationPath $zip
    $expanded = Join-Path $root "expanded-$arch"
    Expand-Archive -Path $zip -DestinationPath $expanded
    Invoke-Smoke (Join-Path $expanded 'HadramoutMikroTik.exe') $arch
    Invoke-Checked $iscc @("/DArch=$arch","/DPayload=$payload","/DOutputPath=$release",'packaging/Hadramout.iss')
    $setup = Join-Path $release "HadramoutMikroTik-$arch-Setup.exe"
    $installDir = Join-Path $root "installed-$arch"
    $proc = Start-Process -FilePath $setup -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /DIR=""$installDir""" -Wait -PassThru
    if ($proc.ExitCode -ne 0) { throw "Installer failed: $arch" }
    Invoke-Smoke (Join-Path $installDir 'HadramoutMikroTik.exe') $arch
    $proc = Start-Process -FilePath (Join-Path $installDir 'unins000.exe') -ArgumentList '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART' -Wait -PassThru
    if ($proc.ExitCode -ne 0 -or (Test-Path (Join-Path $installDir 'HadramoutMikroTik.exe'))) { throw "Uninstall failed: $arch" }
}
$expected = @('HadramoutMikroTik-x86-Portable.zip','HadramoutMikroTik-x86-Setup.exe','HadramoutMikroTik-x64-Portable.zip','HadramoutMikroTik-x64-Setup.exe')
if (@(Get-ChildItem -File $release).Count -ne 4) { throw 'Expected exactly four packages.' }
$hashes = foreach ($name in $expected) {
    $file = Join-Path $release $name
    if (-not (Test-Path $file -PathType Leaf)) { throw "Missing $name" }
    (Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $name
}
$hashes | Set-Content -Encoding ascii (Join-Path $release 'SHA256SUMS.txt')
