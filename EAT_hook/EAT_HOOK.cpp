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
	OldMessageBox(NULL, TEXT("EAT_HOOK��װǰ"), NULL, MB_OK);
	OldAddress = (DWORD)OldMessageBox;
	//��װEAT_Hook
	InstallEATHook(hModule, szModule, (DWORD)My_MessageBox, &ChangeAddress, &OldAddress);
	PMessageBox NewMessageBox = (PMessageBox)GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");
	NewMessageBox(NULL, TEXT("EAT_HOOK��װʧ��"), NULL, MB_OK);

	//ж��EAT_Hook
	//DeleteEATHook();

	OldMessageBox = (PMessageBox)GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");
	OldMessageBox(NULL, TEXT("EAT_HOOKж��ʧ��"), NULL, MB_OK);

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
		//ע���ڱȽ�ʱ�����ú���������Ϊ�еĺ���û�к�������������ŵ��ã�
		if((DWORD)((BYTE *)hModule + ((DWORD *)((BYTE *)hModule + pExportDir->AddressOfFunctions))[x]) == *OldAddress)
		{
			//�ı�����
			DWORD dwOldProtect;
			MEMORY_BASIC_INFORMATION  mbi;
			VirtualQuery((LPCVOID)(&(((DWORD *)((BYTE *)hModule + pExportDir->AddressOfFunctions))[x])),&mbi,sizeof(mbi));
			VirtualProtect(mbi.BaseAddress,mbi.RegionSize,PAGE_EXECUTE_READWRITE,&dwOldProtect);


			
	
			*ChangeAddress = (DWORD)&(((DWORD *)((BYTE *)hModule + pExportDir->AddressOfFunctions))[x]);
			((DWORD *)((BYTE *)hModule + pExportDir->AddressOfFunctions))[x] = (FuncAddress - (DWORD)hModule);


			//�ָ�����
			VirtualProtect(mbi.BaseAddress,mbi.RegionSize,dwOldProtect,0);
			return TRUE;
		}
		x++;
	}




}

int WINAPI My_MessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	int ret = MessageBox(hWnd, TEXT("EAT_HOOK��װ�ɹ�"), lpCaption, uType);
	return ret;
}