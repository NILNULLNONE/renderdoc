@echo off
call .\android_clean.bat no_pause
call .\android_cmake.bat no_pause
call .\android_make.bat no_pause
call .\android_copy.bat no_pause
pause