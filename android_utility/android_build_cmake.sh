#!/bin/bash
cd ..
mkdir -p build-android
cd build-android
mkdir -p build-android-armeabi-v7a
mkdir -p build-android-arm64-v8a
cd build-android-armeabi-v7a
cmake -DBUILD_ANDROID=On -DANDROID_ABI=armeabi-v7a -S ../../
cd ..
cd build-android-arm64-v8a
cmake -DBUILD_ANDROID=On -DANDROID_ABI=arm64-v8a -S ../../
cd ..
cd ..
cd android_utility
if [ -z "$1" ]
then
        read -n1 -r -p "Press any key to continue..." key
fi
