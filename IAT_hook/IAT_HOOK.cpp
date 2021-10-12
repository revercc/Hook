//IAT   HOOK
//（顾名思义其只能对输入地址表存在的函数进行hook），动态获取地址调用的函数不能hook

#include <Windows.h>
#include <TlHelp32.h>
#include <imagehlp.h>
#pragma  comment (lib, "imagehlp")
#include <iostream>

using namespace std;

typedef int					//定义一种和HOOK函数类型相同的函数指针
(WINAPI *PFN_MessageBoxA)(
	HWND hWnd,         
	LPCSTR lpText,     
	LPCSTR lpCaption,  
	UINT uType          
	);


PFN_MessageBoxA Old = NULL;
int WINAPI My_MessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
BOOL	InstallMoudleIATHook(HMODULE hModToHook,char * szModuleName, char * szFuncName, PVOID DetourFunc, DWORD * pThunkPointer, DWORD * OldAddress);
BOOL DeleteMoudleIATHook(DWORD ChangeAddress,DWORD OldMessageBoxAddress);

int main()
{
	DWORD	ChangeAddress = NULL;				//指向被修改的位置
	DWORD	OldMessageBoxAddress;		 		//指向原始MessageBox函数的地址
	HMODULE hModule	= GetModuleHandle(NULL);
	char		szModule[] = "USER32.dll";
	char		szProcName[] = "MessageBoxA";
	
	MessageBox(NULL, TEXT("IAT_Hook安装之前"), NULL, MB_OK);
	//进行IAThook
	InstallMoudleIATHook(hModule, szModule, szProcName, My_MessageBox, &ChangeAddress, &OldMessageBoxAddress);
	Old = (PFN_MessageBoxA)OldMessageBoxAddress;				//设置HOOK的函数的原始地址
	MessageBox(NULL, TEXT("IAT_HOOK失败"), NULL, MB_OK);

	//卸载IAThook
	DeleteMoudleIATHook(ChangeAddress, OldMessageBoxAddress);
	MessageBox(NULL, TEXT("IAT_HOOK卸载成功"), NULL, MB_OK);
	return 0;
}



//安装IAT_hook
BOOL InstallMoudleIATHook(HMODULE hModToHook,char * szModuleName, char * szFuncName, PVOID DetourFunc, DWORD * pThunkPointer, DWORD * OldAddress)
{
	PIMAGE_IMPORT_DESCRIPTOR	pImportDescriptor;			//指向输入表
	ULONG ulSize;											//数据目录项的大小

	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hModToHook, TRUE,IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);

	while(pImportDescriptor->FirstThunk)
	{
		char * str1 = (char *)((BYTE *)hModToHook + pImportDescriptor->Name);
		if(strcmp(str1, szModuleName) == 0)			//如果找到匹配的模块
		{
			IMAGE_THUNK_DATA * lpThunk = ((IMAGE_THUNK_DATA *)((BYTE *)hModToHook + pImportDescriptor->OriginalFirstThunk));
			IMAGE_IMPORT_BY_NAME * lpImport;
			int num = 0;			//函数所在的序号
			while(lpThunk->u1.AddressOfData != 0)
			{
				lpImport	= (IMAGE_IMPORT_BY_NAME *)((BYTE *)hModToHook + lpThunk->u1.AddressOfData);
				if(strcmp((char *)lpImport->Name, szFuncName) == 0)
				{
					IMAGE_THUNK_DATA * lpThunk2 = ((IMAGE_THUNK_DATA *)((BYTE *)hModToHook + pImportDescriptor->FirstThunk));
					for(int i = 0; i < num; i++)
						lpThunk2++;

					//改变属性
					DWORD dwOldProtect;
					MEMORY_BASIC_INFORMATION  mbi;
					VirtualQuery(lpThunk2,&mbi,sizeof(mbi));
					VirtualProtect(mbi.BaseAddress,mbi.RegionSize,PAGE_EXECUTE_READWRITE,&dwOldProtect);


					*pThunkPointer	= (DWORD)lpThunk2;
					*OldAddress		= (DWORD)lpThunk2->u1.AddressOfData;
					lpThunk2->u1.AddressOfData = (DWORD)DetourFunc;

					//恢复属性
					VirtualProtect(mbi.BaseAddress,mbi.RegionSize,dwOldProtect,0);
					return TRUE;
				}
				num++;
				lpThunk++;

			}

		}
		else
			pImportDescriptor++;
	}


	return FALSE;
}


//卸载IAT_Hook
BOOL DeleteMoudleIATHook(DWORD ChangeAddress,DWORD OldMessageBoxAddress)
{
	//改变属性
	DWORD dwOldProtect;
	MEMORY_BASIC_INFORMATION  mbi;
	VirtualQuery((LPCVOID)ChangeAddress,&mbi,sizeof(mbi));
	VirtualProtect(mbi.BaseAddress,mbi.RegionSize,PAGE_EXECUTE_READWRITE,&dwOldProtect);
	
	((IMAGE_THUNK_DATA *)ChangeAddress)->u1.AddressOfData	= (DWORD)OldMessageBoxAddress;
	
	//恢复属性
	VirtualProtect(mbi.BaseAddress,mbi.RegionSize,dwOldProtect,0);
	return 0;
}

//Detour函数
int WINAPI My_MessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	int ret = Old(hWnd, TEXT("IAT_HOOK成功"), lpCaption, uType | MB_ICONERROR);
	return ret;
}





