//Inlinehook
#include <Windows.h>	
#include <TlHelp32.h>

BYTE		bOldCode[0x5];	//Hook前的字节码
int WINAPI My_MessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
int	SetInlineHook(HMODULE hModule, PVOID FuncAddress, DWORD * pChangeAddress);
int DeleteHook(DWORD ChangeAddress);

int main()
{
	
	DWORD	ChangeAddress;
	HMODULE hModule	= GetModuleHandle("USER32.dll");

	MessageBox(NULL, TEXT("InlineHook安装前"), NULL, MB_OK);

	//设置InlineHook
	SetInlineHook(hModule, My_MessageBox, &ChangeAddress);
	MessageBox(NULL, TEXT("InlineHook安装失败"), NULL, MB_OK);


	//卸载InlineHook
	DeleteHook(ChangeAddress);
	MessageBox(NULL, TEXT("InlineHook卸载成功"), NULL, MB_OK);

	return 0;
}



int	SetInlineHook(HMODULE hModule, PVOID FuncAddress, DWORD * pChangeAddress)
{
	//获取当前进程句柄
	HANDLE hProcess=GetCurrentProcess();						
	//安装Hook处的地址
	*pChangeAddress = (DWORD)GetProcAddress(hModule,"MessageBoxA");	
	

	//读取HOOK前机器码
	SIZE_T ByteNume = 0;
	ReadProcessMemory(hProcess, LPVOID(*pChangeAddress), bOldCode, 0x5, &ByteNume);
	if (!ByteNume)
	{
		return FALSE;
	}

	//向Hook位置写入jmp指令
	BYTE		WriteData[5] = { 0 };		//需要写入的jmp指令
	DWORD	dwOldProtect = 0;			//内存原来的属性
	WriteData[0] = 0xE9;
	((DWORD *)(WriteData + 1))[0] = (DWORD)FuncAddress - (*pChangeAddress) - 5;	
	VirtualProtect(LPVOID(*pChangeAddress), 0x5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	//HOOK操作的线程安全，暂停其他无关线程
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

	//向Hook位置写入jmp指令
	BYTE		WriteData[5] = { 0 };		//需要写入的jmp指令
	DWORD	dwOldProtect = 0;			//内存原来的属性
	WriteData[0] = 0xE9;
	((DWORD *)(WriteData + 1))[0] = (DWORD)FuncAddress - (*pChangeAddress) - 5;	
	VirtualProtect(LPVOID(*pChangeAddress), 0x5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

int DeleteHook(DWORD ChangeAddress)
{

	//获取当前进程句柄
	HANDLE hProcess = GetCurrentProcess();
	
	//还原hook的指令
	DWORD	dwOldProtect = 0;			//内存原来的属性
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

	//保存环境
	_asm
	{
		pushad
		pushfd
	}
	//先还原hook的函数，再调用
	DeleteHook(ChangeAddress);
	//恢复环境
	_asm
	{
		popfd
		popad
	}
	iRet = MessageBox(hWnd, "InlineHook安装成功", lpCaption, uType);	
	//设置Hook
	SetInlineHook(hModule, My_MessageBox, &ChangeAddress);

	return iRet;
}
