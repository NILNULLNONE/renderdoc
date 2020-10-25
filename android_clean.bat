@echo off
if exist build-android rd /s /q ".\build-android"
if "%~1"=="" (pause)