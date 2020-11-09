#!/bin/bash
cd ..
rm -rf build-android
if [ -z "$1" ]
then
	read -n1 -r -p "Press any key to continue..." key
fi
cd android_utility
