#include <iostream>
#include <Windows.h>
using namespace std;
class Test
{
public:
	virtual void PrintData();
};

void Test::PrintData()
{
	cout << "����ԭ����"<<endl;
}

class Test2
{
public:
	virtual void PrintData();
};

void Test2::PrintData()
{
	cout << "����Detour����"<<endl;
}

int main(int argc, char* argv[], char* envp[])
{
	Test	*	pTest = new Test;
	Test2*	pTest2 = new Test2;
	LPVOID	lpVirtualTable;
	DWORD	dwOldProtect = 0;

	//HOOK��װǰ
	pTest->PrintData();

	//�滻�麯����ַ
	lpVirtualTable = (LPVOID) * ((DWORD*)&(*pTest));
	VirtualProtect(lpVirtualTable, 0x4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	*(DWORD*)lpVirtualTable = *(DWORD*)(*((DWORD*)&(*pTest2)));
	VirtualProtect(lpVirtualTable, 0x4, dwOldProtect, &dwOldProtect);

	//HOOK��װ��
	pTest->PrintData();

	return 0;
}