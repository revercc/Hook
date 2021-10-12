#include <Windows.h>
#include <imagehlp.h>
#pragma comment(lib,"imagehlp.lib")
typedef int
(WINAPI *PMessageBox)(
HWND	hWnd,
LPCSTR	lpText,
LPCSTR	lpCaption,
UINT	uType);

int WINAPI My_MessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
BOOL InstallEATHook(HMODULE hModule, char * szFuncName, DWORD FuncAddress, DWORD * ChangeAddress, DWORD * OldAddress);
int main()
{
	HMODULE	hModule = GetModuleHandle("user32.dll");
	DWORD	ChangeAddress;
	DWORD	OldAddress;
	char		szModule[] = "USER32.dll";
	


	PMessageBox OldMessageBox = (PMessageBox)GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");
	OldMessageBox(NULL, TEXT("EAT_HOOK安装前"), NULL, MB_OK);
	OldAddress = (DWORD)OldMessageBox;
	//安装EAT_Hook
	InstallEATHook(hModule, szModule, (DWORD)My_MessageBox, &ChangeAddress, &OldAddress);
	PMessageBox NewMessageBox = (PMessageBox)GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");
	NewMessageBox(NULL, TEXT("EAT_HOOK安装失败"), NULL, MB_OK);

	//卸载EAT_Hook
	//DeleteEATHook();

	OldMessageBox = (PMessageBox)GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");
	OldMessageBox(NULL, TEXT("EAT_HOOK卸载失败"), NULL, MB_OK);

	return 0;
}

BOOL InstallEATHook(HMODULE hModule, char * szFuncName, DWORD FuncAddress, DWORD * ChangeAddress, DWORD * OldAddress)
{
	ULONG ulSize;
	IMAGE_EXPORT_DIRECTORY * pExportDir;
	pExportDir = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData(hModule, TRUE,IMAGE_DIRECTORY_ENTRY_EXPORT, &ulSize);
	int x = 0;
	while(((DWORD *)((BYTE *)hModule + pExportDir->AddressOfNames))[x] != 0)
	{
		//注意在比较时不能用函数名，因为有的函数没有函数名（其用序号调用）
		if((DWORD)((BYTE *)hModule + ((DWORD *)((BYTE *)hModule + pExportDir->AddressOfFunctions))[x]) == *OldAddress)
		{
			//改变属性
			DWORD dwOldProtect;
			MEMORY_BASIC_INFORMATION  mbi;
			VirtualQuery((LPCVOID)(&(((DWORD *)((BYTE *)hModule + pExportDir->AddressOfFunctions))[x])),&mbi,sizeof(mbi));
			VirtualProtect(mbi.BaseAddress,mbi.RegionSize,PAGE_EXECUTE_READWRITE,&dwOldProtect);


			
	
			*ChangeAddress = (DWORD)&(((DWORD *)((BYTE *)hModule + pExportDir->AddressOfFunctions))[x]);
			((DWORD *)((BYTE *)hModule + pExportDir->AddressOfFunctions))[x] = (FuncAddress - (DWORD)hModule);


			//恢复属性
			VirtualProtect(mbi.BaseAddress,mbi.RegionSize,dwOldProtect,0);
			return TRUE;
		}
		x++;
	}




}

int WINAPI My_MessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	int ret = MessageBox(hWnd, TEXT("EAT_HOOK安装成功"), lpCaption, uType);
	return ret;
}