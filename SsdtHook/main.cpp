#include <ntifs.h>
#include <ntimage.h>
#include <intrin.h>
//去除写保护
extern "C"
VOID DisableWriteProtect(PULONG pOldAttr);

//还原写保护
extern "C"
VOID EnableWriteProtect(ULONG uOldAttr);


//这个结构实际未公开,在这里自己定义。
typedef struct ServiceDescriptorEntry{
	PVOID ServiceTableBase;						//PVOID指针类型，在32位机器上就是32位/64位机器上就是64位
	PVOID ServiceCounterTableBase;
	ULONGLONG NumberOfServices;
	PVOID ParamTableBase;
}ServiceDescriptorTableEntry_t, * PServiceDescriptorTableEntry_t;


PServiceDescriptorTableEntry_t KeServiceDescriptorTable = NULL;



//通过搜索特征码寻找SSDT表的基地址
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


//获取SSDI中对应服务号的服务地址
ULONGLONG GetSSDTFuncCurrentAddr(ULONG id)
{
	LONG dwtemp = 0;
	PULONG ServiceTableBase = NULL;											//只要是指针其就大小就跟随系统的位数变化（无论其具体指向什么类型）
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwtemp = ServiceTableBase[id];
	dwtemp = dwtemp >> 4;
	return (LONGLONG)dwtemp + (ULONGLONG)ServiceTableBase;
}


#define SETBIT(x,y) x|=(1<<y) //将X的第Y位置1  
#define CLRBIT(x,y) x&=~(1<<y) //将X的第Y位清0  
#define GETBIT(x,y) (x & (1 << y)) //取X的第Y位，返回0或非0  
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
	ULONG	uOldAttr;						//原CR3的值
	PULONG	ServiceTableBase = NULL;
	UCHAR	szShellCode[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";					//shellcode：jmp指令

	DisableWriteProtect(&uOldAttr);			//去除写保护

	//hook ssdt表中目标例程，填充为KeBugCheckEx
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwtemp = (ULONGLONG)KeBugCheckEx - (ULONGLONG)ServiceTableBase;
	dwtemp = dwtemp << 4;
	dwtemp = dwtemp + 7;					//设置低四位的值（如果被hook函数的参数小于4就为0，如果被hook 的函数参数大于4就是其参数个数减去4）
	
	
	
	
	ServiceTableBase[id] = GetOffsetAddress((ULONG)KeBugCheckEx, 11);


	//inline hook KebugCheckEx
	memcpy(szShellCode + 6, &new_proc, 8);	//向shellcode中写入我们自己过滤函数的地址
	memcpy(KeBugCheckEx, szShellCode, 14);	//向KeBugCheckEx函数开头写入我们的shellcode
	

	EnableWriteProtect(uOldAttr);			//恢复写保护

}


//将Unicode的模块名称改为ANSI编码的
void UnicodeToChar(PUNICODE_STRING stUnicodeString, UCHAR* szString)
{
	ANSI_STRING stAnsiString;
	RtlUnicodeStringToAnsiString(&stAnsiString, stUnicodeString, TRUE);
	strncpy((char*)szString, stAnsiString.Buffer, stAnsiString.Length);
	//RtlUnicodeStringToAnsiString函数内部的实现
	//RtlUnicodeToMultiByteN((PCHAR)szString, 256, NULL, stUnicodeString->Buffer, 2 * RtlxUnicodeStringToOemSize(stUnicodeString));

	if (strrchr((char*)szString, '\\') != NULL)
		strcpy((char*)szString, strrchr((char*)szString, '\\') + 1);
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
	UCHAR	szFileName[256] = { 0 };												//正在操作的文件名称

	//ULONG	uReturnLength;
	//PPUBLIC_OBJECT_TYPE_INFORMATION pFileInfo;	
	//UCHAR	szFileInfo[256 * 3] = {0};
	//注意FileHandle句柄是创建文件的对象的type。（一般都是进程创建的文件所以，一般获取的类型的名称都是Process）
	//ntstatus = ZwQueryObject(*FileHandle, ObjectTypeInformation, szFileInfo, 256 * 3, &uReturnLength);
	//pFileInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)szFileInfo;

	UnicodeToChar(ObjectAttributes->ObjectName, szFileName);
	if (strcmp((char*)szFileName, (char*)szProtectFileName) == 0)				//如果修改被保护的文件
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
void* InstallSsdtHook( void* new_proc, void** old_proc)
{
	KeServiceDescriptorTable = (PServiceDescriptorTableEntry_t)MyGetKeServiceDescriptorTable64();				//获得KeServiceDescriptorEntry的基址
	*old_proc = (void *)GetSSDTFuncCurrentAddr(0x52);															//根据索引号得到函数地址
	SetSSDTFuncCurrentAddr(new_proc, 0x52);																		//设置新的SSDT例程
	
	return *old_proc;						//返回旧的函数地址
}



//驱动卸载函数
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

	VOID* OldProc;				//旧的函数地址				
	
	DbgBreakPoint();
	//安装ssdt_HOOK
	InstallSsdtHook( NtNewCreateFile, &OldProc);

	pDriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}