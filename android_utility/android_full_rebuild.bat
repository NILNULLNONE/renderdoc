@echo off
call .\android_build_clean.bat no_pause
call .\android_build_cmake.bat no_pause
call .\android_build_make.bat no_pause
call .\android_build_copy.bat no_pause
pause