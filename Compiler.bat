@ECHO OFF

nasm -f win64 .\Assembly.asm -o .\Assembly.obj
g++ -o cordyceps.exe main.cpp Assembly.obj
del *.obj