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

	MessageBox(NULL, TEXT("InlineHook��װǰ"), NULL, MB_OK);

	//����InlineHook
	SetInlineHook(hModule, My_MessageBox, &ChangeAddress);
	MessageBox(NULL, TEXT("InlineHook��װʧ��"), NULL, MB_OK);


	//ж��InlineHook
	//DeleteHook();
	MessageBox(NULL, TEXT("InlineHookж�سɹ�"), NULL, MB_OK);

	return 0;
}



int	SetInlineHook(HMODULE hModule, PVOID FuncAddress, DWORD * pChangeAddress)
{
	HANDLE hProcess=GetCurrentProcess();			//��ȡ��ǰ���̾��
	int n = GetLastError();
	*pChangeAddress = (DWORD)GetProcAddress(hModule,"MessageBoxA");					//��װHook���ĵ�ַ
	JmpBackAddr = (*pChangeAddress) + 5;
	BYTE WriteData[5];

	WriteData[0] = 0xE9;
	((DWORD *)(WriteData + 1))[0] = (DWORD)FuncAddress - (*pChangeAddress) - 5;		//����д���jmpָ���ƫ��

	WriteProcessMemory(hProcess,LPVOID(*pChangeAddress), WriteData, 5, NULL);		//��Hookλ��д��jmpָ��

	return 0;
}








//Detour����
int WINAPI My_MessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{

	

	int ret = Trampoline(hWnd, "InlineHook��װ�ɹ�", lpCaption, uType);	//ͨ�������м亯�����ﵽֱ�ӵ���ԭʼMessageBox��Ŀ��
	return ret;
}


//������ԭʼMessageBoxʱֱ�ӵ��ô˺���
//�˺���Ϊ�㺯���������������Ż���
__declspec( naked )
int WINAPI Trampoline(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	_asm
	{
		//��������д���Jmpָ���ƻ���ԭ����ǰ3��ָ��,���������ִ��ԭ������ǰ3��ָ��
		mov edi,edi  //��һ����ʵ���Բ�Ҫ
		push ebp
		mov ebp,esp
		jmp JmpBackAddr //����Hook����֮��ĵط����ƹ��Լ���װ��HOOK

	}

}
