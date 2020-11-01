@echo off
cd ..
if exist build-android rd /s /q ".\build-android"
if "%~1"=="" (pause)
cd android_utility