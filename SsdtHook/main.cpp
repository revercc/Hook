#include <ntifs.h>
#include <ntimage.h>
#include <intrin.h>
//ȥ��д����
extern "C"
VOID DisableWriteProtect(PULONG pOldAttr);

//��ԭд����
extern "C"
VOID EnableWriteProtect(ULONG uOldAttr);


//����ṹʵ��δ����,�������Լ����塣
typedef struct ServiceDescriptorEntry{
	PVOID ServiceTableBase;						//PVOIDָ�����ͣ���32λ�����Ͼ���32λ/64λ�����Ͼ���64λ
	PVOID ServiceCounterTableBase;
	ULONGLONG NumberOfServices;
	PVOID ParamTableBase;
}ServiceDescriptorTableEntry_t, * PServiceDescriptorTableEntry_t;


PServiceDescriptorTableEntry_t KeServiceDescriptorTable = NULL;



//ͨ������������Ѱ��SSDT��Ļ���ַ
ULONGLONG MyGetKeServiceDescriptorTable64()
{
	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	ULONG templong = 0;
	ULONGLONG addr = 0;
	for (i = StartSearchAddress;i < EndSearchAddress;i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			b1 = *i;
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15) //4c8d15
			{
				memcpy(&templong, i + 3, 4);
				addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
				return addr;
			}
		}
	}
	return 0;
}


//��ȡSSDI�ж�Ӧ����ŵķ����ַ
ULONGLONG GetSSDTFuncCurrentAddr(ULONG id)
{
	LONG dwtemp = 0;
	PULONG ServiceTableBase = NULL;											//ֻҪ��ָ����ʹ�С�͸���ϵͳ��λ���仯�����������ָ��ʲô���ͣ�
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwtemp = ServiceTableBase[id];
	dwtemp = dwtemp >> 4;
	return (LONGLONG)dwtemp + (ULONGLONG)ServiceTableBase;
}


#define SETBIT(x,y) x|=(1<<y) //��X�ĵ�Yλ��1  
#define CLRBIT(x,y) x&=~(1<<y) //��X�ĵ�Yλ��0  
#define GETBIT(x,y) (x & (1 << y)) //ȡX�ĵ�Yλ������0���0  
ULONG GetOffsetAddress(ULONGLONG FuncAddr, CHAR paramCount)
{
	LONG dwtmp = 0, i;
	CHAR b = 0, bits[4] = { 0 };
	PULONG stb = NULL;
	stb = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwtmp = (LONG)(FuncAddr - (ULONGLONG)stb);
	dwtmp = dwtmp << 4;
	if (paramCount > 4)
	{
		paramCount = paramCount - 4;
	}
	else
	{
		paramCount = 0;
	}
	memcpy(&b, &dwtmp, 1);
	for (i = 0;i < 4;i++)
	{
		bits[i] = GETBIT(paramCount, i);
		if (bits[i])
		{
			SETBIT(b, i);
		}
		else
		{
			CLRBIT(b, i);
		}
	}
	memcpy(&dwtmp, &b, 1);
	return dwtmp;
}



void SetSSDTFuncCurrentAddr(void* new_proc, ULONG id)
{

	LONG	dwtemp = 0;
	ULONG	uOldAttr;						//ԭCR3��ֵ
	PULONG	ServiceTableBase = NULL;
	UCHAR	szShellCode[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";					//shellcode��jmpָ��

	DisableWriteProtect(&uOldAttr);			//ȥ��д����

	//hook ssdt����Ŀ�����̣����ΪKeBugCheckEx
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwtemp = (ULONGLONG)KeBugCheckEx - (ULONGLONG)ServiceTableBase;
	dwtemp = dwtemp << 4;
	dwtemp = dwtemp + 7;					//���õ���λ��ֵ�������hook�����Ĳ���С��4��Ϊ0�������hook �ĺ�����������4���������������ȥ4��
	
	
	
	
	ServiceTableBase[id] = GetOffsetAddress((ULONG)KeBugCheckEx, 11);


	//inline hook KebugCheckEx
	memcpy(szShellCode + 6, &new_proc, 8);	//��shellcode��д�������Լ����˺����ĵ�ַ
	memcpy(KeBugCheckEx, szShellCode, 14);	//��KeBugCheckEx������ͷд�����ǵ�shellcode
	

	EnableWriteProtect(uOldAttr);			//�ָ�д����

}


//��Unicode��ģ�����Ƹ�ΪANSI�����
void UnicodeToChar(PUNICODE_STRING stUnicodeString, UCHAR* szString)
{
	ANSI_STRING stAnsiString;
	RtlUnicodeStringToAnsiString(&stAnsiString, stUnicodeString, TRUE);
	strncpy((char*)szString, stAnsiString.Buffer, stAnsiString.Length);
	//RtlUnicodeStringToAnsiString�����ڲ���ʵ��
	//RtlUnicodeToMultiByteN((PCHAR)szString, 256, NULL, stUnicodeString->Buffer, 2 * RtlxUnicodeStringToOemSize(stUnicodeString));

	if (strrchr((char*)szString, '\\') != NULL)
		strcpy((char*)szString, strrchr((char*)szString, '\\') + 1);
	RtlFreeAnsiString(&stAnsiString);
}



//��HOOK�ĺ��������µĺ���
__kernel_entry  NTSTATUS NtNewCreateFile(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
)
{
	NTSTATUS ntstatus;
	UCHAR	szProtectFileName[256] = "11.txt";									//��Ҫ�������ļ�����
	UCHAR	szFileName[256] = { 0 };												//���ڲ������ļ�����

	//ULONG	uReturnLength;
	//PPUBLIC_OBJECT_TYPE_INFORMATION pFileInfo;	
	//UCHAR	szFileInfo[256 * 3] = {0};
	//ע��FileHandle����Ǵ����ļ��Ķ����type����һ�㶼�ǽ��̴������ļ����ԣ�һ���ȡ�����͵����ƶ���Process��
	//ntstatus = ZwQueryObject(*FileHandle, ObjectTypeInformation, szFileInfo, 256 * 3, &uReturnLength);
	//pFileInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)szFileInfo;

	UnicodeToChar(ObjectAttributes->ObjectName, szFileName);
	if (strcmp((char*)szFileName, (char*)szProtectFileName) == 0)				//����޸ı��������ļ�
	{
		return STATUS_OBJECT_NAME_NOT_FOUND;									//����״̬ʧ��(�ļ�����δ�ҵ�)
	}

	ntstatus = NtCreateFile(													//����ԭ���ķ�������
		FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength);

	return ntstatus;
}

//SSDT_HOOK��װ����
void* InstallSsdtHook( void* new_proc, void** old_proc)
{
	KeServiceDescriptorTable = (PServiceDescriptorTableEntry_t)MyGetKeServiceDescriptorTable64();				//���KeServiceDescriptorEntry�Ļ�ַ
	*old_proc = (void *)GetSSDTFuncCurrentAddr(0x52);															//���������ŵõ�������ַ
	SetSSDTFuncCurrentAddr(new_proc, 0x52);																		//�����µ�SSDT����
	
	return *old_proc;						//���ؾɵĺ�����ַ
}



//����ж�غ���
extern "C"
void DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	KdPrint(("the dirver is unload!"));
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	VOID* OldProc;				//�ɵĺ�����ַ				
	
	DbgBreakPoint();
	//��װssdt_HOOK
	InstallSsdtHook( NtNewCreateFile, &OldProc);

	pDriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}