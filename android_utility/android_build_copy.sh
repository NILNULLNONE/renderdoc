#!/bin/bash
cd ../build-android
mkdir -p plugins
cd plugins
rm -rf ./*
mkdir -p android
cp ../build-android-armeabi-v7a/bin/*.apk ./android/
cp ../build-android-arm64-v8a/bin/*.apk ./android/
cd ../../android_utility
if [ -z "$1" ]
then
        read -n1 -r -p "Press any key to continue..." key
fi

