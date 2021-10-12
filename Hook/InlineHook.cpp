//Inlinehook
#include <Windows.h>
DWORD JmpBackAddr;
int WINAPI My_MessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
int	SetInlineHook(HMODULE hModule, PVOID FuncAddress, DWORD * pChangeAddress);
int WINAPI Trampoline(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

int main()
{
	
	DWORD	ChangeAddress;
	HMODULE hModule	= GetModuleHandle("USER32.dll");

	MessageBox(NULL, TEXT("InlineHook安装前"), NULL, MB_OK);

	//设置InlineHook
	SetInlineHook(hModule, My_MessageBox, &ChangeAddress);
	MessageBox(NULL, TEXT("InlineHook安装失败"), NULL, MB_OK);


	//卸载InlineHook
	//DeleteHook();
	MessageBox(NULL, TEXT("InlineHook卸载成功"), NULL, MB_OK);

	return 0;
}



int	SetInlineHook(HMODULE hModule, PVOID FuncAddress, DWORD * pChangeAddress)
{
	HANDLE hProcess=GetCurrentProcess();			//获取当前进程句柄
	int n = GetLastError();
	*pChangeAddress = (DWORD)GetProcAddress(hModule,"MessageBoxA");					//安装Hook处的地址
	JmpBackAddr = (*pChangeAddress) + 5;
	BYTE WriteData[5];

	WriteData[0] = 0xE9;
	((DWORD *)(WriteData + 1))[0] = (DWORD)FuncAddress - (*pChangeAddress) - 5;		//计算写入的jmp指令的偏移

	WriteProcessMemory(hProcess,LPVOID(*pChangeAddress), WriteData, 5, NULL);		//向Hook位置写入jmp指令

	return 0;
}








//Detour函数
int WINAPI My_MessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{

	

	int ret = Trampoline(hWnd, "InlineHook安装成功", lpCaption, uType);	//通过调用中间函数来达到直接调用原始MessageBox的目的
	return ret;
}


//当调用原始MessageBox时直接调用此函数
//此函数为裸函数（编译器不加优化）
__declspec( naked )
int WINAPI Trampoline(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	_asm
	{
		//由于我们写入的Jmp指令破坏了原来的前3条指令,因此在这里执行原函数的前3条指令
		mov edi,edi  //这一句其实可以不要
		push ebp
		mov ebp,esp
		jmp JmpBackAddr //跳到Hook代码之后的地方，绕过自己安装的HOOK

	}

}
