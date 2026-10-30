# Builds the stock console decompiler (consolemain.cc main; the Windows equivalent of `decomp_opt`
# / `decomp_dbg` without CPUI_DEBUG) from a given src/decompile tree with the same MSVC flags and the
# same source list (cpp-sources.txt) as the host crate's build.rs. Used as the single-threaded
# reference the host output is compared against.
#
#   pwsh build_stock_console.ps1 -Decompile <...>/src/decompile -OutDir <dir> [-Jobs 6]
param(
    [Parameter(Mandatory)] [string] $Decompile,
    [Parameter(Mandatory)] [string] $OutDir,
    [int] $Jobs = 6
)
$ErrorActionPreference = 'Stop'
$crate = Split-Path -Parent $PSScriptRoot
$names = Get-Content (Join-Path $crate 'cpp-sources.txt') | Where-Object { $_ -notmatch '^\s*#' } |
    ForEach-Object { $_ -split '\s+' } | Where-Object { $_ }
$cpp = Join-Path $Decompile 'cpp'
$zlib = Join-Path $Decompile 'zlib'
New-Item -ItemType Directory -Force $OutDir, (Join-Path $OutDir 'obj'), (Join-Path $OutDir 'zobj') | Out-Null
$srcs = @($names | ForEach-Object { '"' + (Join-Path $cpp "$_.cc") + '"' }) + ('"' + (Join-Path $cpp 'consolemain.cc') + '"')
$zsrcs = Get-ChildItem $zlib -Filter *.c | ForEach-Object { '"' + $_.FullName + '"' }
$rsp = Join-Path $OutDir 'cpp.rsp'
$zrsp = Join-Path $OutDir 'z.rsp'
$cxx = @('/nologo', '/c', '/MD', '/EHsc', '/O2', '/Oy', '/W0', "/MP$Jobs", '/D_SECURE_SCL=0', '/D_HAS_ITERATOR_DEBUGGING=0',
    '/DWINDOWS', '/D_WINDOWS', '/DWIN32', '/D_WIN32', '/DWIN64', '/D_WIN64', '/DLOCAL_ZLIB', "/I`"$cpp`"",
    "/Fo`"$(Join-Path $OutDir 'obj')\\`"") + $srcs
$cc = @('/nologo', '/c', '/MD', '/O2', '/Oy', '/W0', "/MP$Jobs", '/DNO_GZIP', '/D_CRT_SECURE_NO_DEPRECATE',
    '/D_CRT_NONSTDC_NO_DEPRECATE', '/DZLIB_WINAPI', "/I`"$zlib`"", "/Fo`"$(Join-Path $OutDir 'zobj')\\`"") + $zsrcs
Set-Content -Encoding ascii $rsp ($cxx -join "`n")
Set-Content -Encoding ascii $zrsp ($cc -join "`n")
$vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -property installationPath
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
$exe = Join-Path $OutDir 'decomp_stock.exe'
$link = "link /nologo /OUT:`"$exe`" `"$(Join-Path $OutDir 'obj')\*.obj`" `"$(Join-Path $OutDir 'zobj')\*.obj`""
cmd /c "call `"$vcvars`" >nul && cl @`"$rsp`" && cl @`"$zrsp`" && $link"
if ($LASTEXITCODE -ne 0) { throw "stock build failed ($LASTEXITCODE)" }
Write-Output $exe
