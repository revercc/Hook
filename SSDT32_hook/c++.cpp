#include <ntddk.h>
//#include <ntifs.h>
// 这个结构实际未公开。在这里自己定义。
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase;
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;

// 导入SSDT的符号（32位的此符号KeServiceDescriptorTable是导出的）
extern "C" __declspec(dllimport)  ServiceDescriptorTableEntry_t  KeServiceDescriptorTable;

VOID* OldProc = NULL;				//旧的函数地址

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


//去除写保护
VOID DisableWriteProtect(PULONG pOldAttr)
{
	_asm
	{
		 cli					;关中断
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

//还原写保护
VOID EnableWriteProtect(ULONG uOldAttr)
{
	_asm
	{
	     push  eax
         mov   eax, uOldAttr
         mov   cr0, eax
         pop   eax
		 sti					;开中断
        
	}

}




//将Unicode的模块名称改为ANSI编码的
void UnicodeToChar(PUNICODE_STRING stUnicodeString, UCHAR* szString)
{
	ANSI_STRING stAnsiString;
	RtlUnicodeStringToAnsiString(&stAnsiString, stUnicodeString, TRUE);
	strncpy((char*)szString, stAnsiString.Buffer, stAnsiString.Length);
	//RtlUnicodeStringToAnsiString函数内部的实现
	//RtlUnicodeToMultiByteN((PCHAR)szString, 256, NULL, stUnicodeString->Buffer, 2 * RtlxUnicodeStringToOemSize(stUnicodeString));

	if(strrchr((char*)szString,'\\') != NULL)
		strcpy((char*)szString,strrchr((char*)szString,'\\') + 1);
	RtlFreeAnsiString(&stAnsiString);
}




//被HOOK的函数填充的新的函数
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
	UCHAR	szProtectFileName[256] = "11.txt";									//需要保护的文件名称
	UCHAR	szFileName[256] = {0};												//正在操作的文件名称
	

	UnicodeToChar(ObjectAttributes->ObjectName, szFileName);
	if(strcmp((char*)szFileName, (char*)szProtectFileName) == 0)				//如果修改被保护的文件
	{
		return STATUS_OBJECT_NAME_NOT_FOUND;									//返回状态失败(文件名称未找到)
	}																		
	
	ntstatus = NtCreateFile(													//调用原来的服务例程
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

//SSDT_HOOK安装函数
void* InstallSsdtHook(void* Proc_to_hook, void* new_proc)
{	
	ULONG	uOldAttr;						//原CR3的值
	DWORD32	dwServiceIndex;					//待HOOK服务的索引

	dwServiceIndex = *((DWORD32*)((UCHAR*)Proc_to_hook + 1));							//获取服务例程对应的服务号
	OldProc = (void*)KeServiceDescriptorTable.ServiceTableBase[dwServiceIndex];		//保存原始SSDT服务例程的地址
	
	DisableWriteProtect(&uOldAttr);			//去除写保护
	KeServiceDescriptorTable.ServiceTableBase[dwServiceIndex] = (unsigned int)new_proc;	//设置ssdt服务例程为我们自己的函数
	EnableWriteProtect(uOldAttr);			//恢复写保护

	return OldProc;							//返回旧的函数地址
}


//SSDT_HOOK卸载函数
void UnInstallSsdtHook(void* Proc_to_hook)
{
	ULONG	uOldAttr;						//原CR3的值
	DWORD32	dwServiceIndex;					//待HOOK服务的索引

	dwServiceIndex = *((DWORD32*)((UCHAR*)Proc_to_hook + 1));							//获取服务例程对应的服务号
	DisableWriteProtect(&uOldAttr);			//去除写保护
	KeServiceDescriptorTable.ServiceTableBase[dwServiceIndex] = (unsigned int)OldProc;	//恢复ssdt服务例程
	EnableWriteProtect(uOldAttr);			//恢复写保护

}


//驱动卸载函数
void DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	PVOID ProcAddress;					//需要hook的函数地址
	UNICODE_STRING szToHookName;		//需要hook的函数名称
	RtlInitUnicodeString(&szToHookName, L"ZwCreateFile");
	ProcAddress = MmGetSystemRoutineAddress(&szToHookName);

	//卸载ssdt_hook
	UnInstallSsdtHook(ProcAddress);
	KdPrint(("the dirver is unload!"));
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
					
	PVOID ProcAddress;					//需要hook的函数地址
	UNICODE_STRING szToHookName;		//需要hook的函数名称
	RtlInitUnicodeString(&szToHookName, L"ZwCreateFile");
	DbgBreakPoint();
	ProcAddress = MmGetSystemRoutineAddress(&szToHookName);

	//安装ssdt_HOOK
	InstallSsdtHook(ProcAddress, NtNewCreateFile);

	DriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}







