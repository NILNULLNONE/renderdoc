#!/bin/bash
sh ./android_build_make.sh no_pause
sh ./android_build_copy.sh no_pause
read -n1 -r -p "Press any key to continue..." key
