@echo off
if not exist build-android mkdir build-android
cd build-android
if not exist build-android-armeabi-v7a mkdir build-android-armeabi-v7a
if not exist build-android-arm64-v8a mkdir build-android-arm64-v8a
cd build-android-armeabi-v7a
rem del ".\*" /f /q /s
cmake -DBUILD_ANDROID=On -DANDROID_ABI=armeabi-v7a -G "MinGW Makefiles" -S ..\..\
cd ..
cd build-android-arm64-v8a
rem del ".\*" /f /q /s
cmake -DBUILD_ANDROID=On -DANDROID_ABI=arm64-v8a -G "MinGW Makefiles" -S ..\..\
cd ..
cd ..
if "%~1"=="" (pause)