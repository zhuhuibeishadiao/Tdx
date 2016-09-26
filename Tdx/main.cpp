#include "precomp.h"


#define IOCODE_ASK   		71
#define IOCODE_STOPPING		72
#define IOCODE_PAUSE		73
#define IOCODE_START		74
#define IOCODE_UPDATE		75
#define IOCODE_UPDATE_ALONE		76      //要杀的独立进程广告
#define IOCODE_GET_TIMES		77       
#define IOCODE_SET_EVENT		78    

#define XDRVIOCTRL_ASK      		CTL_CODE(FILE_DEVICE_UNKNOWN, IOCODE_ASK, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define XDRVIOCTRL_STOP     		CTL_CODE(FILE_DEVICE_UNKNOWN, IOCODE_STOPPING, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define XDRVIOCTRL_PAUSE    		CTL_CODE(FILE_DEVICE_UNKNOWN, IOCODE_PAUSE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define XDRVIOCTRL_START    		CTL_CODE(FILE_DEVICE_UNKNOWN, IOCODE_START, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define XDRVIOCTRL_UPDATE   	    CTL_CODE(FILE_DEVICE_UNKNOWN, IOCODE_UPDATE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define XDRVIOCTRL_UPDATE_ALONE   	CTL_CODE(FILE_DEVICE_UNKNOWN, IOCODE_UPDATE_ALONE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define XDRVIOCTRL_GET_TIMES   	    CTL_CODE(FILE_DEVICE_UNKNOWN, IOCODE_GET_TIMES, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define XDRVIOCTRL_SET_EVENT   	    CTL_CODE(FILE_DEVICE_UNKNOWN, IOCODE_SET_EVENT, METHOD_BUFFERED, FILE_ANY_ACCESS)

WCHAR g_DeviceName[] = L"\\Device\\zyantiAd";
WCHAR g_DeviceLinkName[] = L"\\DosDevices\\zyantiAd";

extern WIN_VER_DETAIL g_osver;
extern WIN_VER_DETAIL GetWindowsVersion();

#define DELAY_ONE_MICROSECOND  (-10) 
#define DELAY_ONE_MILLISECOND (DELAY_ONE_MICROSECOND*1000) 


PDEVICE_OBJECT g_udp_DevObj = NULL;

PKEVENT pEvent = NULL;
 
int g_runing = 1;

PDEVICE_OBJECT g_hDevice;

PWCHAR  pAlone   = NULL; //独立的进程广告程序
PUCHAR  pProcess = NULL;
PUCHAR  pPageAd  = NULL;
PUCHAR  pVideo   = NULL;
PUCHAR  pURL     = NULL;

//#define FileObjectNum   72
//PFILEOBJECT_INFO pFileObject = NULL;

#define MAX_PROCESS   64
HANDLE  myHandle[MAX_PROCESS] = {0};


ULONG crc32_table[256]; // Lookup table arrays
BOOLEAN  OkInite=FALSE;
 
void KeSleep(int milliSeconds){
  KTIMER timer = {0};
  LARGE_INTEGER duetime;
  duetime.QuadPart = (__int64) milliSeconds * -10000;
  KeInitializeTimerEx(&timer, NotificationTimer);   
  KeSetTimerEx(&timer, duetime, 0, NULL);
  KeWaitForSingleObject (&timer, Executive, KernelMode, FALSE, NULL);
}


VOID MyThread()//线程调用的函数  
{  
	//do{
	//	if(tswitch){
	//		KeEnterCriticalRegion();
	//		tswitch--;
	//		//DbgPrint("tswitch = %d\n", tswitch);
	//		if(hadChanged){
	//			hadChanged = 0;
	//			if(tswitch ==1)
	//				tTimes++;
	//		}
	//		KeLeaveCriticalRegion();
	//	}
	//	KeSleep(1000);
	//}while(1);

	PsTerminateSystemThread(STATUS_SUCCESS);  
}  

ULONG Reflect(ULONG ref, UCHAR ch)
{
	ULONG value=0;
	int i;
	for(i = 1; i < (ch + 1); i++)
	{
		if(ref & 1)
			value |= 1 << (ch - i);
		ref >>= 1;
	}
	return value;
}

VOID Init_CRC32_Table()
{
   int i,j;
   ULONG ulPolynomial = 0x04c11db7;
   for(i = 0; i <= 0xFF; i++)
	{
	crc32_table[i]=Reflect(i, 8) << 24;
	for (j = 0; j < 8; j++)
		crc32_table[i] = (crc32_table[i] << 1) ^ (crc32_table[i] & (1 << 31) ? ulPolynomial : 0);
	crc32_table[i] = Reflect(crc32_table[i], 32);
	}

}

ULONG Get_CRC(PUCHAR csData, ULONG dwSize)
{
	ULONG  crc=0xffffffff;
	int len;
	PUCHAR buffer;

	if(!OkInite){
		Init_CRC32_Table();
		OkInite=TRUE;
	}

	len = dwSize;
	buffer = (PUCHAR)csData;
	while(len--)
		crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ *buffer++];
	return crc^0xffffffff;
}
 
NTSTATUS  KillProcessByKernelMemClear( HANDLE m_process_id)
{
	PEPROCESS m_process;
	NTSTATUS status = STATUS_SUCCESS;
	KAPC_STATE m_kapc_state;
	ULONG      m_index=0;
	BOOLEAN    m_is_valid;	

	status=PsLookupProcessByProcessId(m_process_id,&m_process);
	if(!NT_SUCCESS(status))	
	{
		//DbgPrint("PsLookupProcessByProcessId 函数调用失败！\n");
		return status;
	}
	KeStackAttachProcess ((PKPROCESS)m_process,&m_kapc_state); 
	for(m_index=0;m_index<0x80000000;m_index+=0x1000)
	{
		if(MmIsAddressValid((PVOID)(m_index)))
		{
			__try
			{		
				memset((PVOID)m_index,0xcc,0x1000);	
			}
			__except(1)
			{
			//	DbgPrint("异常地址:0x%x\n",m_index);
				continue;
			}
		}
		else
		{
		//	DbgPrint("地址无效:0x%x\n",m_index);	
			if(m_index>0x1000000)
			{
				break;
			}
		}
	}
	KeUnstackDetachProcess(&m_kapc_state);
	return status;
}

typedef NTSTATUS (*QUERY_INFO_PROCESS2) (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
    );
QUERY_INFO_PROCESS2 ZwQueryInformationProcess2=NULL; 
BOOLEAN GetProcessImagePath( IN  ULONG   dwProcessId,OUT PUNICODE_STRING ProcessImagePath)
{
    NTSTATUS Status;
    HANDLE hProcess;
    PEPROCESS pEprocess;
    ULONG returnedLength;
    ULONG bufferLength;
    PVOID buffer;
    PUNICODE_STRING imageName;
    BOOLEAN re=FALSE;

    PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process


    if (NULL == ZwQueryInformationProcess2)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
        ZwQueryInformationProcess2 =(QUERY_INFO_PROCESS2) MmGetSystemRoutineAddress(&routineName);
        if (NULL == ZwQueryInformationProcess2)
        {
            //DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
			return FALSE;
        }
    }


    Status = PsLookupProcessByProcessId((HANDLE)dwProcessId, &pEprocess);
	if (!NT_SUCCESS(Status)){   return FALSE;}
    //Wdm中定义的全局变量 PsProcessType
    Status = ObOpenObjectByPointer(pEprocess,          // Object
                                   OBJ_KERNEL_HANDLE,  // HandleAttributes
                                   NULL,               // PassedAccessState OPTIONAL
                                   GENERIC_READ,       // DesiredAccess
                                   *PsProcessType,     // ObjectType
                                   KernelMode,         // AccessMode
                                   &hProcess);
    if (!NT_SUCCESS(Status)) {   return FALSE;}

    //
    // Step one - get the size we need
    //
    Status = ZwQueryInformationProcess2( hProcess,
                                        ProcessImageFileName,
                                        NULL, // buffer
                                        0, // buffer size
                                        &returnedLength);




    if (STATUS_INFO_LENGTH_MISMATCH != Status) {    return FALSE;}
    //
    // Is the passed-in buffer going to be big enough for us?
    // This function returns a single contguous buffer model...
    //
    bufferLength = returnedLength - sizeof(UNICODE_STRING);
    if (ProcessImagePath->MaximumLength < bufferLength)
    {
        ProcessImagePath->Length = (USHORT) bufferLength;
        {   return FALSE;}
    }
    //
    // If we get here, the buffer IS going to be big enough for us, so
    // let's allocate some storage.
    //
    buffer = ExAllocatePoolWithTag(PagedPool, returnedLength, 'ipgD');
    if (NULL == buffer){   return FALSE;}
    //
    // Now lets go get the data
    //
    Status = ZwQueryInformationProcess2( hProcess,
                                        ProcessImageFileName,
                                        buffer,
                                        returnedLength,
                                        &returnedLength);
    if (NT_SUCCESS(Status))
    {
        imageName = (PUNICODE_STRING) buffer;
        RtlCopyUnicodeString(ProcessImagePath, imageName);
		re=TRUE;
    }

    ZwClose(hProcess);
    ExFreePool(buffer);
    return re;
}

BOOLEAN GetProcessName(HANDLE ProcessId)
{
	UNICODE_STRING  virDir;
	int i, j;
	WCHAR pname[512]={0};  //必须这么长
	memset(pname,0,1024);
	RtlInitEmptyUnicodeString(&virDir,pname,600);
	if(GetProcessImagePath((ULONG)ProcessId,&virDir)){    }
	else return FALSE; 

	_wcslwr(pname); 

	if(pProcess){
		int num = *((ULONG*)(pProcess+8));
		_dat1_ * pd = (_dat1_ *)(pProcess+12);
		for(i=0; i<num; i++){
			if(wcsstr(pname, pd[i].pname)){
				for(j=0; j<MAX_PROCESS; j++)if(myHandle[j] == 0){
					myHandle[j] = (HANDLE)ProcessId;
					//DbgPrint("insert=%d,%S\n", ProcessId, pname);
					break;
				}
				break;
			}
		}
	}
 
	return TRUE;
}

 
VOID EnumAllProcess()
{
	ULONG ProcessId = 0;
	int i;
	for(i=0; i<MAX_PROCESS; i++)
		myHandle[i] = (HANDLE)0;

	for(ProcessId = 100; ProcessId < 9999; ProcessId += 4)
	{
		GetProcessName((HANDLE)ProcessId);
	}
}


VOID ProcessCreateMon ( HANDLE hParentId, HANDLE PId, BOOLEAN bCreate )
{
	int i;

	if(!g_runing)
		return;

    if ( bCreate )
    {
		GetProcessName(PId);   
      
	}
	else {
		for(i=0; i<MAX_PROCESS; i++)
			if(PId == myHandle[i]){
				myHandle[i] = (HANDLE)0;
				break;
			}

	}
}
 

//读要禁止的URL信息。
//int readUrlInfo(PWCHAR fname)
//{
//	HANDLE hFile=NULL;
//	IO_STATUS_BLOCK Io_Status_Block={0};
//    OBJECT_ATTRIBUTES obj_attrib;
//	NTSTATUS status;
//    int bRet=0, len, i;
//	ULONG crc;
//	PULONG ps; 
//    UNICODE_STRING  file ; 
//	LARGE_INTEGER offset={0};
//	FILE_STANDARD_INFORMATION  basic;
//	WCHAR fname2[300] = {0};
//
//	memcpy(fname2, L"\\??\\", 8);
//	memcpy(fname2+4, fname, wcslen(fname)*2);
//
//	RtlInitUnicodeString(&file,fname2);
//    InitializeObjectAttributes( &obj_attrib,&file,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//    status = ZwCreateFile(&hFile,
//							GENERIC_READ,
//							&obj_attrib,
//							&Io_Status_Block,
//							NULL,
//							FILE_ATTRIBUTE_NORMAL,
//							FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
//							FILE_OPEN,
//							FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
//							NULL, 0);
//	if(!NT_SUCCESS(status)){ bRet = -1;	goto __end; }  
// 
//    status = ZwQueryInformationFile(hFile,&Io_Status_Block,&basic,sizeof(FILE_STANDARD_INFORMATION),FileStandardInformation);
//	if(!NT_SUCCESS(status)){ bRet = -2 ; goto __end;	 }    
//    len=basic.EndOfFile.u.LowPart;
//	if(len < 20 || len > (1024*200))
//		{ bRet = -3 ; goto __end;	 }
//
//	pURL = (PUCHAR) ExAllocatePoolWithTag(NonPagedPool, len, 1234);
//	if(!pURL)
//		{ bRet = -4 ; goto __end;	 }
//	memset(pURL, 0, len);
//	ZwReadFile(hFile,NULL,NULL,NULL,&Io_Status_Block, pURL, len, &offset, NULL);
//
//	crc = Get_CRC(pURL+4, len-4);
//	if(crc != *((ULONG*)pURL)){
//		bRet = -5 ; goto __end;
//	}
//
//    ps = (PULONG)(pURL+12);
//    for(i=0; i < ((len-12)/4); i++)ps[i] ^= *((PULONG)(pURL+4));
//
//	DbgPrint("url=%s_%s\n", (char*)(pURL+12), (char*)(pURL+12+strlen((char*)(pURL+12)))+1);
//
//__end:
//	if(hFile)
//		ZwClose(hFile);
//	DbgPrint("URL=%d\n", bRet);
//	return bRet;
//}

NTSTATUS DisptachShutDown(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	DbgPrint("ShutDownDispatch!\n");
	return STATUS_SUCCESS;
}
 

VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING DeviceLinkName;
 
	PsSetCreateProcessNotifyRoutine(ProcessCreateMon, TRUE);

	IoUnregisterShutdownNotification(g_hDevice);
	g_runing = 0;
 
	xtdi_unhook_tcp();

	xtdi_unhook_udp();

	RtlInitUnicodeString(&DeviceLinkName, g_DeviceLinkName);
	IoDeleteSymbolicLink (&DeviceLinkName);

	IoDeleteDevice (DriverObject->DeviceObject);
}
 
 
NTSTATUS IoCtrlDispatch( PDEVICE_OBJECT dev, PIRP Irp )
{
	NTSTATUS status = 1;
	ULONG len = 0;
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation( Irp ); 
		
	switch( irpStack->MajorFunction )
	{
	case IRP_MJ_CREATE:
		break;
	case IRP_MJ_CLEANUP:
 
		break;
	case IRP_MJ_CLOSE:
		break;
	case IRP_MJ_DEVICE_CONTROL:
		{
			ULONG ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
			ULONG* inputBuffer	= (ULONG *)Irp->AssociatedIrp.SystemBuffer;
			ULONG uOutSize = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
			ULONG* pout	= (ULONG*)Irp->UserBuffer;

			switch(ioControlCode)
			{
			case XDRVIOCTRL_ASK:
				{
					if(inputBuffer && (*inputBuffer) == 0x1234 && pout){
						Irp->IoStatus.Status = STATUS_SUCCESS;
	 
						*pout = (ULONG)g_runing;
						DbgPrint("ask 0k\n");
					}
				}
				break;

			case XDRVIOCTRL_PAUSE:
				{
					if(inputBuffer && (*inputBuffer) == 0x1234 && pout){
						*pout = 0x5678;
 
						Irp->IoStatus.Status = STATUS_SUCCESS;
						DbgPrint("pause 0k\n");
					}
				}
				break;
			case XDRVIOCTRL_STOP:
				{
					if(inputBuffer && (*inputBuffer) == 0x1234 && pout){
						Irp->IoStatus.Status = STATUS_SUCCESS;
 
						*pout = 0x5678;
						DbgPrint("stop 0k\n");
					}
				}
				break;
			case XDRVIOCTRL_START:
				{
					if(inputBuffer && (*inputBuffer) == 0x1234 && pout){
						Irp->IoStatus.Status = STATUS_SUCCESS;
						//memset(pFileObject, 0, FileObjectNum*sizeof(FILEOBJECT_INFO));
	 
						*pout = 0x5678;
						DbgPrint("start 0k\n");
					}
				}
				break;
 
			}
		}
		break;
	}

	Irp->IoStatus.Information = len; 
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return status; 
}
 

NTSTATUS GDDriverDisptach(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
 
	if( DeviceObject == g_xttdi.drvobj_tcp || DeviceObject == g_xttdi.drvobj_udp )
	{ 
		 
		return xtdi_dispatch( DeviceObject, Irp ); 
	}
	else if( DeviceObject == g_xttdi.drvobj_ioctrl ){  
		return IoCtrlDispatch( DeviceObject, Irp ); 
	}
 
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0; 
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
 
	return status;
}
 



extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS ntStatus;
	PDEVICE_OBJECT  deviceObject = NULL;
	UNICODE_STRING DeviceName, DeviceLinkName;
	HANDLE threadHandle;

	int i;
	g_osver = GetWindowsVersion();
 
	_try {
		xtdi_init(DriverObject);
		DriverObject->DriverUnload = OnUnload;

		RtlInitUnicodeString(&DeviceName, g_DeviceName);
		RtlInitUnicodeString(&DeviceLinkName, g_DeviceLinkName);
		ntStatus = IoCreateDevice (DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
		if (!NT_SUCCESS(ntStatus)) {
 
			return ntStatus;
		}
		g_xttdi.drvobj_ioctrl = deviceObject;

		ntStatus = IoCreateSymbolicLink (&DeviceLinkName, &DeviceName);

		if (!NT_SUCCESS(ntStatus)) {
			IoDeleteDevice (deviceObject);
			return ntStatus;
		}

		g_osver = GetWindowsVersion();

		for( i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++ ) {
			DriverObject->MajorFunction[i] = GDDriverDisptach;
		}

		DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = DisptachShutDown;
 
			//HANDLE threadHandle = NULL;

		xtdi_hook_tcp();

		xtdi_hook_udp();
 
		ntStatus = IoRegisterShutdownNotification(deviceObject);

		if (!NT_SUCCESS(ntStatus))
		{
			DbgPrint("IoRegisterShutdownNotification Error code:0x%x\n",ntStatus);
			return ntStatus;
		}

		g_hDevice = deviceObject;

		PsCreateSystemThread(  //创建线程  
				&threadHandle,  
				THREAD_ALL_ACCESS,  
				NULL,  
				NULL,  
				NULL,  
				(PKSTART_ROUTINE)MyThread,//调用的函数  
				NULL  //PVOID StartContext 传递给函数的参数  
		);
		for(i=0; i<MAX_PROCESS; i++) myHandle[i] = (HANDLE)0;
 
		PsSetCreateProcessNotifyRoutine(ProcessCreateMon, FALSE);//设置进程监控

 	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		IoDeleteSymbolicLink(&DeviceLinkName);
		IoDeleteDevice (deviceObject);

		return STATUS_SUCCESS;
	}

	return STATUS_SUCCESS;
}







