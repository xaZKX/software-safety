#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

BOOL LoadDll(DWORD dwProcessId, LPTSTR lpszDllName)
{
	HANDLE	hProcess = NULL;
	HANDLE	hThread = NULL;
	PSTR		pszDllFile = NULL;
	// 打开进程
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == NULL)
		return FALSE;
	printf("打开进程 %d 成功!\n\n", dwProcessId);
	// 分配远程空间
	int cch = 1 + strlen(lpszDllName);
	pszDllFile = (PSTR)VirtualAllocEx(hProcess,
		NULL,
		cch,
		MEM_COMMIT,
		PAGE_READWRITE);
	if (pszDllFile == NULL)
		return FALSE;
	printf("分配远程空间成功!\n\n");
	// 把DLL的名字变量地址写入到远程空间中
	if ((WriteProcessMemory(hProcess,
		(PVOID)pszDllFile,
		(PVOID)lpszDllName,
		cch,
		NULL)) == FALSE)
	{
		return FALSE;
	}
	printf("写远程内存成功!\n\n");
	// 获取远程进程地址空间中LoadLibrary函数的地址
	PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA");
	if (pfnThreadRtn == NULL)
		return FALSE;
	printf("获取LoadLibrary函数地址成功!\n\n");
	// 创建远程线程
	hThread = CreateRemoteThread(hProcess,
		NULL,
		0,
		pfnThreadRtn,
		(PVOID)pszDllFile,
		0,
		NULL);
	if (hThread == NULL)
		return FALSE;
	printf("创建远程线程成功!\n\n");
	// 等待远程线程执行结束，并非必要
	system("pause");
	WaitForSingleObject(hThread, INFINITE);

	VirtualFreeEx(hProcess, (PVOID)pszDllFile, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;
}
void main()
{
	char lpDllName[] = "C:\\IATHook.dll";

	// 枚举进程，得到指定进程ID
	PROCESSENTRY32 ProcessEntry = { 0 };
	HANDLE hProcessSnap;
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32);

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	BOOL bRet = Process32First(hProcessSnap, &ProcessEntry);
	while (bRet)
	{	// 判断进程是否为 calc.exe,注入计算器进程
		if (strcmp("notepad.exe", ProcessEntry.szExeFile) == 0)
		{
			LoadDll(ProcessEntry.th32ProcessID, lpDllName);
			break;
		}
		bRet = Process32Next(hProcessSnap, &ProcessEntry);
	}
}


	