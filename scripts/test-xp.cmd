@echo off
setlocal
cd /d "%~dp0"
if not exist logs mkdir logs
ver > logs\system.txt
for %%D in (kernel32 advapi32 ws2_32 ntdll) do go2xp-xp.exe exports "%SystemRoot%\system32\%%D.dll" > "logs\exports-%%D.txt" 2>&1
echo The next unpatched probe is expected to fail on XP. Capture its dialog.
hello.exe > logs\hello-unpatched.log 2>&1
for %%P in (hello files exec console signals net) do call :probe %%P
echo Send logs, build-info.txt, SHA256SUMS and screenshots back.
exit /b
:probe
echo Running %1-xp.exe
%1-xp.exe > logs\%1.log 2>&1
set probe_exit=%ERRORLEVEL%
echo %probe_exit% > logs\%1.exit.txt
type logs\%1.log
exit /b
