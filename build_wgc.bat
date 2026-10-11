@echo off
set "MSVC_ROOT=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207"
set "WINSDK_ROOT=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.26100.0"
set "MSBUILD_DIR=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\arm64"
set "PATH=%MSVC_ROOT%\bin\Hostarm64\arm64;%WINSDK_ROOT%\bin\%WINSDK_VER%\arm64;%MSBUILD_DIR%;%PATH%"
set "INCLUDE=%MSVC_ROOT%\include;%WINSDK_ROOT%\Include\%WINSDK_VER%\ucrt;%WINSDK_ROOT%\Include\%WINSDK_VER%\um;%WINSDK_ROOT%\Include\%WINSDK_VER%\shared"
set "LIB=%MSVC_ROOT%\lib\arm64;%WINSDK_ROOT%\Lib\%WINSDK_VER%\ucrt\arm64;%WINSDK_ROOT%\Lib\%WINSDK_VER%\um\arm64"

if not defined SODIUM_SRC set "SODIUM_SRC=%USERPROFILE%\dev\libsodium-src"
if not defined SODIUM_OUT set "SODIUM_OUT=%USERPROFILE%\dev\libsodium-arm64"

if exist "%SODIUM_OUT%\lib\sodium.lib" goto :configure

echo === Building libsodium ===
msbuild "%SODIUM_SRC%\builds\msvc\vs2022\libsodium\libsodium.vcxproj" /p:Configuration=ReleaseLIB /p:Platform=arm64 /p:PlatformToolset=v143 /p:WindowsTargetPlatformVersion=%WINSDK_VER% /t:Build /m
if %ERRORLEVEL% NEQ 0 exit /b 1

mkdir "%SODIUM_OUT%\include" 2>nul
mkdir "%SODIUM_OUT%\include\sodium" 2>nul
mkdir "%SODIUM_OUT%\lib" 2>nul
xcopy "%SODIUM_SRC%\src\libsodium\include\*.h" "%SODIUM_OUT%\include\" /Q /Y >nul
xcopy "%SODIUM_SRC%\src\libsodium\include\sodium\*.h" "%SODIUM_OUT%\include\sodium\" /Q /Y >nul
REM Find the built libsodium.lib (output path varies)
for /R "%SODIUM_SRC%" %%f in (libsodium.lib) do copy "%%f" "%SODIUM_OUT%\lib\sodium.lib" /Y >nul

:configure
echo === Configuring noisetun ===
rmdir /S /Q "%~dp0build" 2>nul
cmake -B %~dp0.\build -S %~dp0. -G Ninja -DCMAKE_C_COMPILER=cl.exe -DCMAKE_BUILD_TYPE=Release -DSODIUM_INCLUDE_DIR="%SODIUM_OUT%\include" -DSODIUM_LIBRARY="%SODIUM_OUT%\lib\sodium.lib" -DWG_BUILD_TESTS=OFF -DWG_BUILD_BENCH=OFF -DWG_BUILD_TOOLS=OFF -DWG_USE_OPENSSL=OFF -DWG_ASAN=OFF
if %ERRORLEVEL% NEQ 0 exit /b 1

echo === Building noisetun ===
cmake --build %~dp0.\build
