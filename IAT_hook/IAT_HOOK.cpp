//IAT   HOOK
//������˼����ֻ�ܶ������ַ����ڵĺ�������hook������̬��ȡ��ַ���õĺ�������hook

#include <Windows.h>
#include <TlHelp32.h>
#include <imagehlp.h>
#pragma  comment (lib, "imagehlp")
#include <iostream>

using namespace std;

typedef int					//����һ�ֺ�HOOK����������ͬ�ĺ���ָ��
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
	DWORD	ChangeAddress = NULL;				//ָ���޸ĵ�λ��
	DWORD	OldMessageBoxAddress;		 		//ָ��ԭʼMessageBox�����ĵ�ַ
	HMODULE hModule	= GetModuleHandle(NULL);
	char		szModule[] = "USER32.dll";
	char		szProcName[] = "MessageBoxA";
	
	MessageBox(NULL, TEXT("IAT_Hook��װ֮ǰ"), NULL, MB_OK);
	//����IAThook
	InstallMoudleIATHook(hModule, szModule, szProcName, My_MessageBox, &ChangeAddress, &OldMessageBoxAddress);
	Old = (PFN_MessageBoxA)OldMessageBoxAddress;				//����HOOK�ĺ�����ԭʼ��ַ
	MessageBox(NULL, TEXT("IAT_HOOKʧ��"), NULL, MB_OK);

	//ж��IAThook
	DeleteMoudleIATHook(ChangeAddress, OldMessageBoxAddress);
	MessageBox(NULL, TEXT("IAT_HOOKж�سɹ�"), NULL, MB_OK);
	return 0;
}



//��װIAT_hook
BOOL InstallMoudleIATHook(HMODULE hModToHook,char * szModuleName, char * szFuncName, PVOID DetourFunc, DWORD * pThunkPointer, DWORD * OldAddress)
{
	PIMAGE_IMPORT_DESCRIPTOR	pImportDescriptor;			//ָ�������
	ULONG ulSize;											//����Ŀ¼��Ĵ�С

	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hModToHook, TRUE,IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);

	while(pImportDescriptor->FirstThunk)
	{
		char * str1 = (char *)((BYTE *)hModToHook + pImportDescriptor->Name);
		if(strcmp(str1, szModuleName) == 0)			//����ҵ�ƥ���ģ��
		{
			IMAGE_THUNK_DATA * lpThunk = ((IMAGE_THUNK_DATA *)((BYTE *)hModToHook + pImportDescriptor->OriginalFirstThunk));
			IMAGE_IMPORT_BY_NAME * lpImport;
			int num = 0;			//�������ڵ����
			while(lpThunk->u1.AddressOfData != 0)
			{
				lpImport	= (IMAGE_IMPORT_BY_NAME *)((BYTE *)hModToHook + lpThunk->u1.AddressOfData);
				if(strcmp((char *)lpImport->Name, szFuncName) == 0)
				{
					IMAGE_THUNK_DATA * lpThunk2 = ((IMAGE_THUNK_DATA *)((BYTE *)hModToHook + pImportDescriptor->FirstThunk));
					for(int i = 0; i < num; i++)
						lpThunk2++;

					//�ı�����
					DWORD dwOldProtect;
					MEMORY_BASIC_INFORMATION  mbi;
					VirtualQuery(lpThunk2,&mbi,sizeof(mbi));
					VirtualProtect(mbi.BaseAddress,mbi.RegionSize,PAGE_EXECUTE_READWRITE,&dwOldProtect);


					*pThunkPointer	= (DWORD)lpThunk2;
					*OldAddress		= (DWORD)lpThunk2->u1.AddressOfData;
					lpThunk2->u1.AddressOfData = (DWORD)DetourFunc;

					//�ָ�����
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


//ж��IAT_Hook
BOOL DeleteMoudleIATHook(DWORD ChangeAddress,DWORD OldMessageBoxAddress)
{
	//�ı�����
	DWORD dwOldProtect;
	MEMORY_BASIC_INFORMATION  mbi;
	VirtualQuery((LPCVOID)ChangeAddress,&mbi,sizeof(mbi));
	VirtualProtect(mbi.BaseAddress,mbi.RegionSize,PAGE_EXECUTE_READWRITE,&dwOldProtect);
	
	((IMAGE_THUNK_DATA *)ChangeAddress)->u1.AddressOfData	= (DWORD)OldMessageBoxAddress;
	
	//�ָ�����
	VirtualProtect(mbi.BaseAddress,mbi.RegionSize,dwOldProtect,0);
	return 0;
}

//Detour����
int WINAPI My_MessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	int ret = Old(hWnd, TEXT("IAT_HOOK�ɹ�"), lpCaption, uType | MB_ICONERROR);
	return ret;
}





