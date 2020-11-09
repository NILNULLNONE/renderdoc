#!/bin/bash
cd ../build-android/build-android-armeabi-v7a
make
cd ../build-android-arm64-v8a
make
cd ../../android_utility
if [ -z "$1" ]
then
        read -n1 -r -p "Press any key to continue..." key
fi
