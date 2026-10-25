:: ###
:: IP: GHIDRA
::
:: Licensed under the Apache License, Version 2.0 (the "License");
:: you may not use this file except in compliance with the License.
:: You may obtain a copy of the License at
::
::      http://www.apache.org/licenses/LICENSE-2.0
::
:: Unless required by applicable law or agreed to in writing, software
:: distributed under the License is distributed on an "AS IS" BASIS,
:: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
:: See the License for the specific language governing permissions and
:: limitations under the License.
:: ##
:: Ghidra headless session: a long-lived process that opens a project, lists it, opens and
:: switches programs and runs commands and scripts, driven by JSON lines on stdio and/or an
:: authenticated loopback socket. See Ghidra/Features/HeadlessSession/README.md.
::
:: stdout is the protocol channel: this script must never echo anything to it.

@echo off
setlocal

set MAXMEM_DEFAULT=2G

if not defined GHIDRA_MAXMEM set "GHIDRA_MAXMEM=%MAXMEM_DEFAULT%"
if not defined GHIDRA_HEADLESS_MAXMEM set "GHIDRA_HEADLESS_MAXMEM=%GHIDRA_MAXMEM%"

set VMARG_LIST=-XX:ParallelGCThreads=2 -XX:CICompilerCount=2 -Djava.awt.headless=true
set VMARG_LIST=%VMARG_LIST% %GHIDRA_JAVA_OPTIONS% %GHIDRA_HEADLESS_JAVA_OPTIONS%

set LAUNCH_MODE=fg

set "SCRIPT_DIR=%~dp0"

:: A session is normally started by another program through "cmd /c", which launch.bat takes
:: for a double-click: on a non-zero exit it would then "pause", print to stdout (the protocol
:: channel) and wait on stdin (the caller's request pipe). A set variable overrides cmd's dynamic
:: %cmdcmdline%, so launch.bat sees an interactive shell and exits with the real code.
set "cmdcmdline=cmd.exe"

:: Quote every argument again so that ';' (as in -scriptPath "a;b") and spaces survive the call.
setlocal EnableDelayedExpansion
set params=

:Loop
if "%~1" == "" goto cont
set params=!params! "%~1"
shift
goto Loop

:cont

setlocal DisableDelayedExpansion

call "%SCRIPT_DIR%launch.bat" %LAUNCH_MODE% jdk Ghidra-HeadlessSession "%GHIDRA_HEADLESS_MAXMEM%" "%VMARG_LIST%" ghidra.app.util.headless.session.HeadlessSession %params%
exit /B %ERRORLEVEL%
