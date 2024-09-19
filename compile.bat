@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp loader.cpp /link /OUT:loader.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
del *.obj