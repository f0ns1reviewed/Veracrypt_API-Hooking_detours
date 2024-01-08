# Veracrypt_API-Hooking_detours


## Compile:

```
@ECHO OFF

cl.exe /nologo /W0 vcsniff.cpp /MT /link /DLL detours\lib.X64\detours.lib /OUT:vcsniff_detours.dll

del *.obj *.lib *.exp
```
Required:
detours.lib
[Github](https://github.com/Zer0Mem0ry/Detour/blob/master/dll/detours.lib)
