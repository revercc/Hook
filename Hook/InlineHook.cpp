//Inlinehook
#include <Windows.h>	
#include <TlHelp32.h>

BYTE		bOldCode[0x5];	//Hookǰ���ֽ���
int WINAPI My_MessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
int	SetInlineHook(HMODULE hModule, PVOID FuncAddress, DWORD * pChangeAddress);
int DeleteHook(DWORD ChangeAddress);

int main()
{
	
	DWORD	ChangeAddress;
	HMODULE hModule	= GetModuleHandle("USER32.dll");

	MessageBox(NULL, TEXT("InlineHook��װǰ"), NULL, MB_OK);

	//����InlineHook
	SetInlineHook(hModule, My_MessageBox, &ChangeAddress);
	MessageBox(NULL, TEXT("InlineHook��װʧ��"), NULL, MB_OK);


	//ж��InlineHook
	DeleteHook(ChangeAddress);
	MessageBox(NULL, TEXT("InlineHookж�سɹ�"), NULL, MB_OK);

	return 0;
}



int	SetInlineHook(HMODULE hModule, PVOID FuncAddress, DWORD * pChangeAddress)
{
	//��ȡ��ǰ���̾��
	HANDLE hProcess=GetCurrentProcess();						
	//��װHook���ĵ�ַ
	*pChangeAddress = (DWORD)GetProcAddress(hModule,"MessageBoxA");	
	

	//��ȡHOOKǰ������
	SIZE_T ByteNume = 0;
	ReadProcessMemory(hProcess, LPVOID(*pChangeAddress), bOldCode, 0x5, &ByteNume);
	if (!ByteNume)
	{
		return FALSE;
	}

	//��Hookλ��д��jmpָ��
	BYTE		WriteData[5] = { 0 };		//��Ҫд���jmpָ��
	DWORD	dwOldProtect = 0;			//�ڴ�ԭ��������
	WriteData[0] = 0xE9;
	((DWORD *)(WriteData + 1))[0] = (DWORD)FuncAddress - (*pChangeAddress) - 5;	
	VirtualProtect(LPVOID(*pChangeAddress), 0x5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	//HOOK�������̰߳�ȫ����ͣ�����޹��߳�
	HANDLE hThread = NULL;
	THREADENTRY32 stThreadEntry32 = { 0 };
	stThreadEntry32.dwSize = sizeof(THREADENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	Thread32First(hSnapshot, &stThreadEntry32);
	do {
		if (stThreadEntry32.th32ThreadID != GetCurrentThreadId())
		{
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, stThreadEntry32.th32ThreadID);
			SuspendThread(hThread);
			CloseHandle(hThread);
		}
	} while (TRUE == Thread32Next(hSnapshot, &stThreadEntry32));

	CloseHandle(hSnapshot);

	WriteProcessMemory(hProcess,LPVOID(*pChangeAddress), WriteData, 5, NULL);	

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	Thread32First(hSnapshot, &stThreadEntry32);
	do {
		if (stThreadEntry32.th32ThreadID != GetCurrentThreadId())
		{
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, stThreadEntry32.th32ThreadID);
			ResumeThread(hThread);
			CloseHandle(hThread);
		}
	} while (TRUE == Thread32Next(hSnapshot, &stThreadEntry32));
	CloseHandle(hSnapshot);

	VirtualProtect(LPVOID(*pChangeAddress), 0x5, dwOldProtect, &dwOldProtect);

	return TRUE;
}

	//��Hookλ��д��jmpָ��
	BYTE		WriteData[5] = { 0 };		//��Ҫд���jmpָ��
	DWORD	dwOldProtect = 0;			//�ڴ�ԭ��������
	WriteData[0] = 0xE9;
	((DWORD *)(WriteData + 1))[0] = (DWORD)FuncAddress - (*pChangeAddress) - 5;	
	VirtualProtect(LPVOID(*pChangeAddress), 0x5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

int DeleteHook(DWORD ChangeAddress)
{

	//��ȡ��ǰ���̾��
	HANDLE hProcess = GetCurrentProcess();
	
	//��ԭhook��ָ��
	DWORD	dwOldProtect = 0;			//�ڴ�ԭ��������
	VirtualProtect(LPVOID(ChangeAddress), 0x5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	WriteProcessMemory(hProcess, LPVOID(ChangeAddress), bOldCode, 0x5, NULL);
	VirtualProtect(LPVOID(ChangeAddress), 0x5, dwOldProtect, &dwOldProtect);

	return 0;
}

	return TRUE;
}


int DeleteHook(DWORD ChangeAddress)
{

	int		iRet = 0;
	HMODULE	hModule = GetModuleHandle("USER32.dll");
	DWORD	ChangeAddress = (DWORD)GetProcAddress(hModule, "MessageBoxA");

	//���滷��
	_asm
	{
		pushad
		pushfd
	}
	//�Ȼ�ԭhook�ĺ������ٵ���
	DeleteHook(ChangeAddress);
	//�ָ�����
	_asm
	{
		popfd
		popad
	}
	iRet = MessageBox(hWnd, "InlineHook��װ�ɹ�", lpCaption, uType);	
	//����Hook
	SetInlineHook(hModule, My_MessageBox, &ChangeAddress);

	return iRet;
}
