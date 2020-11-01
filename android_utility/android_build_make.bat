@echo off
cd ..
cd build-android
cd build-android-armeabi-v7a
make
cd ..
cd build-android-arm64-v8a
make
cd ..
cd ..
cd android_utility
if "%~1"=="" (pause)
