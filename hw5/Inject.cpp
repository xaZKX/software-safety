#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

BOOL LoadDll(DWORD dwProcessId, LPTSTR lpszDllName)
{
	HANDLE	hProcess = NULL;
	HANDLE	hThread = NULL;
	PSTR		pszDllFile = NULL;
	// �򿪽���
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == NULL)
		return FALSE;
	printf("�򿪽��� %d �ɹ�!\n\n", dwProcessId);
	// ����Զ�̿ռ�
	int cch = 1 + strlen(lpszDllName);
	pszDllFile = (PSTR)VirtualAllocEx(hProcess,
		NULL,
		cch,
		MEM_COMMIT,
		PAGE_READWRITE);
	if (pszDllFile == NULL)
		return FALSE;
	printf("����Զ�̿ռ�ɹ�!\n\n");
	// ��DLL�����ֱ�����ַд�뵽Զ�̿ռ���
	if ((WriteProcessMemory(hProcess,
		(PVOID)pszDllFile,
		(PVOID)lpszDllName,
		cch,
		NULL)) == FALSE)
	{
		return FALSE;
	}
	printf("дԶ���ڴ�ɹ�!\n\n");
	// ��ȡԶ�̽��̵�ַ�ռ���LoadLibrary�����ĵ�ַ
	PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA");
	if (pfnThreadRtn == NULL)
		return FALSE;
	printf("��ȡLoadLibrary������ַ�ɹ�!\n\n");
	// ����Զ���߳�
	hThread = CreateRemoteThread(hProcess,
		NULL,
		0,
		pfnThreadRtn,
		(PVOID)pszDllFile,
		0,
		NULL);
	if (hThread == NULL)
		return FALSE;
	printf("����Զ���̳߳ɹ�!\n\n");
	// �ȴ�Զ���߳�ִ�н��������Ǳ�Ҫ
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

	// ö�ٽ��̣��õ�ָ������ID
	PROCESSENTRY32 ProcessEntry = { 0 };
	HANDLE hProcessSnap;
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32);

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	BOOL bRet = Process32First(hProcessSnap, &ProcessEntry);
	while (bRet)
	{	// �жϽ����Ƿ�Ϊ calc.exe,ע�����������
		if (strcmp("notepad.exe", ProcessEntry.szExeFile) == 0)
		{
			LoadDll(ProcessEntry.th32ProcessID, lpDllName);
			break;
		}
		bRet = Process32Next(hProcessSnap, &ProcessEntry);
	}
}


	