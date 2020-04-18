#include <stdio.h>
#include <Windows.h>
#include <WinInet.h>
#include <winternl.h>
#include "apihook.h"

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWCHAR,ULONG,PUNICODE_STRING,PHANDLE);
typedef BOOL (WINAPI *pCreateProcessInternalW)(HANDLE,LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION,PHANDLE);
typedef void (WINAPI *pExitProcess)(UINT);
typedef HANDLE (WINAPI *pCreateThread)(LPSECURITY_ATTRIBUTES,SIZE_T,LPTHREAD_START_ROUTINE,PVOID,DWORD,LPDWORD);
typedef HINTERNET (WINAPI *pInternetConnectA)(HINTERNET,LPCSTR,INTERNET_PORT,LPCSTR,LPCSTR,DWORD,DWORD,DWORD_PTR);

API_HOOK LdrHook,CpiHook,EPHook,CTHook,ICHook;
char szDllName[260];

BOOL WINAPI HookCreateProcessInternalW(HANDLE hToken,LPCWSTR AppName,LPWSTR CmdLine,LPSECURITY_ATTRIBUTES ProcessAttr,LPSECURITY_ATTRIBUTES ThreadAttr,BOOL bIH,DWORD flags,LPVOID env,LPCWSTR CurrDir,LPSTARTUPINFOW si,LPPROCESS_INFORMATION pi,PHANDLE NewToken)
{
	// CreateProcessInternalW hook - Hook child processes
	
	BOOL ret;
	PVOID mem;
	char szModuleFileName[260],str[4096];

	pCreateProcessInternalW fnCreateProcessInternalW=(pCreateProcessInternalW)CpiHook.OrigFunction;

	// Call the original function

	if(!(flags & CREATE_SUSPENDED))
	{
		ret=fnCreateProcessInternalW(hToken,AppName,CmdLine,ProcessAttr,ThreadAttr,bIH,flags|CREATE_SUSPENDED,env,CurrDir,si,pi,NewToken);
	}

	else
	{
		ret=fnCreateProcessInternalW(hToken,AppName,CmdLine,ProcessAttr,ThreadAttr,bIH,flags,env,CurrDir,si,pi,NewToken);
	}

	if(ret)
	{
		GetModuleFileName(NULL,szModuleFileName,260);
		sprintf(str,"CreateProcessInternalW called by process %s (%d), thread %d | Child process ID: %d | Primary thread ID: %d",szModuleFileName,GetCurrentProcessId(),GetCurrentThreadId(),pi->dwProcessId,pi->dwThreadId);

		OutputDebugString(str); // Display information on DebugView
		
		mem=VirtualAllocEx(pi->hProcess,NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE); // Allocate memory

		WriteProcessMemory(pi->hProcess,mem,szDllName,strlen(szDllName),NULL); // Write the DLL name to the child process
		QueueUserAPC((PAPCFUNC)LoadLibraryA,pi->hThread,(ULONG_PTR)mem); // Queue an APC to call LoadLibrary

		if(!(flags & CREATE_SUSPENDED))
		{
			ResumeThread(pi->hThread);
		}

		return ret;
	}

	return FALSE;
}

void WINAPI HookExitProcess(UINT ExitStatus)
{
	// Monitor process exit
	
	char szModuleFileName[260],str[4096];
	pExitProcess fnExitProcess=(pExitProcess)EPHook.OrigFunction;

	GetModuleFileName(NULL,szModuleFileName,260);
	sprintf(str,"ExitProcess called by process %s (%d), thread %d | Exit status: %d",szModuleFileName,GetCurrentProcessId(),GetCurrentThreadId(),ExitStatus);
	OutputDebugString(str);

	return fnExitProcess(ExitStatus); // Call the original function
}

HANDLE WINAPI HookCreateThread(LPSECURITY_ATTRIBUTES ThreadAttr,SIZE_T StackSize,LPTHREAD_START_ROUTINE StartAddress,PVOID Parameter,DWORD flags,LPDWORD ThreadId)
{
	// Monitor thread creation
	
	char szModuleFileName[260],str[4096];
	HANDLE ret;
	DWORD TID;
	pCreateThread fnCreateThread=(pCreateThread)CTHook.OrigFunction;

	ret=fnCreateThread(ThreadAttr,StackSize,StartAddress,Parameter,flags,&TID);

	GetModuleFileName(NULL,szModuleFileName,260);
	sprintf(str,"CreateThread called by process %s (%d), thread %d | Start address: %#x Parameter: %#x Thread ID of the new thread: %d",szModuleFileName,GetCurrentProcessId(),GetCurrentThreadId(),StartAddress,Parameter,TID);
	OutputDebugString(str);

	if(ThreadId!=NULL)
	{
		*ThreadId=TID; // Return the thread ID to caller
	}

	return ret;
}

HINTERNET WINAPI HookInternetConnectA(HINTERNET hInternet,LPCSTR ServerName,INTERNET_PORT Port,LPCSTR UserName,LPCSTR Password,DWORD Service,DWORD Flags,DWORD_PTR Context)
{
	// Monitor network traffic
	
	char szModuleFileName[260],str[4096];
	pInternetConnectA fnInternetConnectA=(pInternetConnectA)ICHook.OrigFunction;

	GetModuleFileName(NULL,szModuleFileName,260);
	sprintf(str,"InternetConnectA called by process %s (%d), thread %d | Server name: %s Port: %d",szModuleFileName,GetCurrentProcessId(),GetCurrentThreadId(),ServerName,Port);
	OutputDebugString(str);

	return fnInternetConnectA(hInternet,ServerName,Port,UserName,Password,Service,Flags,Context); // Call the original function
}

NTSTATUS NTAPI HookLdrLoadDll(PWCHAR PathToFile,ULONG Flags,PUNICODE_STRING ModuleFileName,PHANDLE ModuleHandle)
{
	// Monitor DLL loading
	
	pLdrLoadDll fnLdrLoadDll=(pLdrLoadDll)LdrHook.OrigFunction;
	char szModuleFileName[260],str[4096];
	NTSTATUS ret;

	GetModuleFileName(NULL,szModuleFileName,260);

	sprintf(str,"LdrLoadDll called by process %s (%d), thread %d | DLL name: %ws",szModuleFileName,GetCurrentProcessId(),GetCurrentThreadId(),ModuleFileName->Buffer);
	OutputDebugString(str);
	ret=fnLdrLoadDll(PathToFile,Flags,ModuleFileName,ModuleHandle);

	// Hook the InternetConnectA function if wininet.dll is loaded

	if(!wcsicmp(L"wininet.dll",ModuleFileName->Buffer))
	{
		InitAPIHook(&ICHook,"wininet.dll","InternetConnectA",HookInternetConnectA);
		StartAPIHook(&ICHook);
	}

	return ret;
}

BOOL WINAPI DllMain(HMODULE hModule,DWORD dwReason,LPVOID lpReserved)
{
	char szModuleFileName[260],str[4096];
	
	switch(dwReason)
	{
	    case DLL_PROCESS_ATTACH:

			GetModuleFileName(NULL,szModuleFileName,260);
			sprintf(str,"API hooking DLL injected into process %s (%d).",szModuleFileName,GetCurrentProcessId());
			OutputDebugString(str);

			GetModuleFileName(hModule,szDllName,260);

			// Hook the functions

			InitAPIHook(&LdrHook,"ntdll.dll","LdrLoadDll",HookLdrLoadDll);
			StartAPIHook(&LdrHook);

			InitAPIHook(&CpiHook,"kernel32.dll","CreateProcessInternalW",HookCreateProcessInternalW);
			StartAPIHook(&CpiHook);

			InitAPIHook(&EPHook,"kernel32.dll","ExitProcess",HookExitProcess);
			StartAPIHook(&EPHook);

			InitAPIHook(&CTHook,"kernel32.dll","CreateThread",HookCreateThread);
			StartAPIHook(&CTHook);

			InitAPIHook(&ICHook,"wininet.dll","InternetConnectA",HookInternetConnectA);
			StartAPIHook(&ICHook);

			break;

		case DLL_PROCESS_DETACH:

			GetModuleFileName(NULL,szModuleFileName,260);
			sprintf(str,"API hooking DLL unloaded from process %s (%d).",szModuleFileName,GetCurrentProcessId());
			OutputDebugString(str);

			// Unhook the functions

			UnhookAPIHook(&LdrHook);
			RemoveAPIHook(&LdrHook);

			UnhookAPIHook(&CpiHook);
			RemoveAPIHook(&CpiHook);

			UnhookAPIHook(&EPHook);
			RemoveAPIHook(&EPHook);

			UnhookAPIHook(&CTHook);
			RemoveAPIHook(&CTHook);

			UnhookAPIHook(&ICHook);
			RemoveAPIHook(&ICHook);

			break;
	}

	return TRUE;
}