@echo off
cd ..
cd build-android
if not exist plugins mkdir plugins
cd plugins
del ".\*" /s /f /q
if not exist android mkdir android
xcopy /I ..\build-android-armeabi-v7a\bin\*.apk .\android\
xcopy /I ..\build-android-arm64-v8a\bin\*.apk .\android\
cd ..\..
if exist x64\Development (
	if not exist x64\Development\plugins mkdir x64\Development\plugins
	if not exist x64\Development\plugins\android mkdir x64\Development\plugins\android
	xcopy /I /y build-android\plugins\android\*.apk x64\Development\plugins\android
)
cd android_utility
if "%~1"=="" (pause)