@echo off
chcp 936

if not exist ".\build-android" mkdir build-android
cd build-android
if not exist ".\build-android-armeabi-v7a" mkdir build-android-armeabi-v7a
if not exist ".\build-android-arm64-v8a" mkdir build-android-arm64-v8a
if not exist ".\plugins" mkdir plugins

cd build-android-armeabi-v7a
rem del ".\*" /f /q /s
cmake -DBUILD_ANDROID=On -DANDROID_ABI=armeabi-v7a ..\..\
make

cd ..

cd build-android-arm64-v8a
rem del ".\*" /f /q /s
cmake -DBUILD_ANDROID=On -DANDROID_ABI=arm64-v8a ..\..\
make

cd ..

cd plugins
del ".\*" /s /f /q
mkdir android
xcopy ..\build-android-armeabi-v7a\bin\org.renderdoc.renderdoccmd.arm32.apk .\plugins\org.renderdoc.renderdoccmd.arm32.apk
xcopy ..\build-android-arm64-v8a\bin\org.renderdoc.renderdoccmd.arm64.apk .\plugins\org.renderdoc.renderdoccmd.arm64.apk

pause