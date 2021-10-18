#include <ntddk.h>
//#include <ntifs.h>
// ����ṹʵ��δ�������������Լ����塣
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase;
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;

// ����SSDT�ķ��ţ�32λ�Ĵ˷���KeServiceDescriptorTable�ǵ����ģ�
extern "C" __declspec(dllimport)  ServiceDescriptorTableEntry_t  KeServiceDescriptorTable;

VOID* OldProc = NULL;				//�ɵĺ�����ַ

extern "C"
NTSTATUS NtCreateFile(
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
);


//ȥ��д����
VOID DisableWriteProtect(PULONG pOldAttr)
{
	_asm
	{
		 cli					;���ж�
	     push  eax
         push  ebx

         mov   eax, cr0
         mov   ebx, eax
         and   eax, 0xFFFEFFFF      
         mov   cr0, eax
     

         mov   eax,pOldAttr              
         mov   [eax],ebx
         
         pop   ebx
         pop   eax
        
	}
}

//��ԭд����
VOID EnableWriteProtect(ULONG uOldAttr)
{
	_asm
	{
	     push  eax
         mov   eax, uOldAttr
         mov   cr0, eax
         pop   eax
		 sti					;���ж�
        
	}

}




//��Unicode��ģ�����Ƹ�ΪANSI�����
void UnicodeToChar(PUNICODE_STRING stUnicodeString, UCHAR* szString)
{
	ANSI_STRING stAnsiString;
	RtlUnicodeStringToAnsiString(&stAnsiString, stUnicodeString, TRUE);
	strncpy((char*)szString, stAnsiString.Buffer, stAnsiString.Length);
	//RtlUnicodeStringToAnsiString�����ڲ���ʵ��
	//RtlUnicodeToMultiByteN((PCHAR)szString, 256, NULL, stUnicodeString->Buffer, 2 * RtlxUnicodeStringToOemSize(stUnicodeString));

	if(strrchr((char*)szString,'\\') != NULL)
		strcpy((char*)szString,strrchr((char*)szString,'\\') + 1);
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
	UCHAR	szFileName[256] = {0};												//���ڲ������ļ�����
	

	UnicodeToChar(ObjectAttributes->ObjectName, szFileName);
	if(strcmp((char*)szFileName, (char*)szProtectFileName) == 0)				//����޸ı��������ļ�
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
void* InstallSsdtHook(void* Proc_to_hook, void* new_proc)
{	
	ULONG	uOldAttr;						//ԭCR3��ֵ
	DWORD32	dwServiceIndex;					//��HOOK���������

	dwServiceIndex = *((DWORD32*)((UCHAR*)Proc_to_hook + 1));							//��ȡ�������̶�Ӧ�ķ����
	OldProc = (void*)KeServiceDescriptorTable.ServiceTableBase[dwServiceIndex];		//����ԭʼSSDT�������̵ĵ�ַ
	
	DisableWriteProtect(&uOldAttr);			//ȥ��д����
	KeServiceDescriptorTable.ServiceTableBase[dwServiceIndex] = (unsigned int)new_proc;	//����ssdt��������Ϊ�����Լ��ĺ���
	EnableWriteProtect(uOldAttr);			//�ָ�д����

	return OldProc;							//���ؾɵĺ�����ַ
}


//SSDT_HOOKж�غ���
void UnInstallSsdtHook(void* Proc_to_hook)
{
	ULONG	uOldAttr;						//ԭCR3��ֵ
	DWORD32	dwServiceIndex;					//��HOOK���������

	dwServiceIndex = *((DWORD32*)((UCHAR*)Proc_to_hook + 1));							//��ȡ�������̶�Ӧ�ķ����
	DisableWriteProtect(&uOldAttr);			//ȥ��д����
	KeServiceDescriptorTable.ServiceTableBase[dwServiceIndex] = (unsigned int)OldProc;	//�ָ�ssdt��������
	EnableWriteProtect(uOldAttr);			//�ָ�д����

}


//����ж�غ���
void DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	PVOID ProcAddress;					//��Ҫhook�ĺ�����ַ
	UNICODE_STRING szToHookName;		//��Ҫhook�ĺ�������
	RtlInitUnicodeString(&szToHookName, L"ZwCreateFile");
	ProcAddress = MmGetSystemRoutineAddress(&szToHookName);

	//ж��ssdt_hook
	UnInstallSsdtHook(ProcAddress);
	KdPrint(("the dirver is unload!"));
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
					
	PVOID ProcAddress;					//��Ҫhook�ĺ�����ַ
	UNICODE_STRING szToHookName;		//��Ҫhook�ĺ�������
	RtlInitUnicodeString(&szToHookName, L"ZwCreateFile");
	DbgBreakPoint();
	ProcAddress = MmGetSystemRoutineAddress(&szToHookName);

	//��װssdt_HOOK
	InstallSsdtHook(ProcAddress, NtNewCreateFile);

	DriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}







