@echo off
cd build-android
if not exist plugins mkdir plugins
cd plugins
del ".\*" /s /f /q
if not exist android mkdir android
xcopy /I ..\build-android-armeabi-v7a\bin\org.renderdoc.renderdoccmd.arm32.apk .\android\
xcopy /I ..\build-android-arm64-v8a\bin\org.renderdoc.renderdoccmd.arm64.apk .\android\
cd ..\..
if "%~1"=="" (pause)