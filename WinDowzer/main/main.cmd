@echo off
del main.exe
g++ main.cpp -o main.exe -std=c++11 -m64
main.exe 0x00080286 005
pause
exit
