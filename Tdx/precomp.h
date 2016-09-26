
#pragma warning(disable:4214)   // bit field types other than int

#pragma warning(disable:4201)   // nameless struct/union
#pragma warning(disable:4115)   // named type definition in parentheses
#pragma warning(disable:4127)   // conditional expression is constant
#pragma warning(disable:4054)   // cast of function pointer to PVOID
#pragma warning(disable:4244)   // conversion from 'int' to 'BOOLEAN', possible loss of data
#pragma warning(disable:4206)   // nonstandard extension used : translation unit is empty

#pragma warning(disable:4995)
#pragma warning(disable:4996)	// 

#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>
#include <wdm.h>
#include <wdmsec.h>
#include <ntstrsafe.h>
 
#include "XKWinUndef.h"
#include "XTdi.h"

#define FileObjectNum   128

typedef struct _FILEOBJECT_INFO
{
	PVOID pObject;
	ULONG ip;
	ULONG port;
	int i;         
}FILEOBJECT_INFO,*PFILEOBJECT_INFO;

typedef struct  _dat1{
    ULONG        pid;     
    WCHAR        pname[72];
} _dat1_;

typedef struct  _process_dat
{
	ULONG   crc;
	ULONG   key;
	ULONG   pnum;   //进程个数
    _dat1_  pdat[1];
} process_dat;

typedef struct  _dat_info
{
	char      adname[32];     //原来的名字
	char      newname[32];    //新的名
}dat_info;

typedef struct  _dat2{
	char      url[48];
	int       adNum;    //广告数
	dat_info  info[1];
} _dat2_;


typedef struct  _pagead_dat
{
	ULONG    crc;
	ULONG    key;
	ULONG    flen;     //本文件长度
	ULONG    urlNum;   //网站数
	_dat2_   addat[1];
} pagead_dat;

typedef struct  _antiurl_dat
{
	ULONG   crc;
	ULONG   key;
	ULONG   urlnum;   //url个数
    char    urlname[1];
} antiurl_dat;

typedef struct _UPDATE_INFO{ 
	ULONG  op;
    WCHAR pname[260];
	WCHAR aname[260];
	WCHAR vname[260];
	WCHAR uname[260]; 
}UPDATE_INFO;

typedef struct _ALONE_INFO{ 
	ULONG  crc;
	ULONG  key;
	ULONG  num;
	ULONG  len;
	WCHAR  reserved;  //对齐
	WCHAR  fname[1];
}ALONE_INFO;


typedef struct _TDI_EVENT_CONTEXT{
	PFILE_OBJECT	fileobj;		/* address object */
	PVOID			old_handler;	/* old event handler */
	PVOID			old_context;	/* old event handler context */
	PVOID           context;
} TDI_EVENT_CONTEXT, *PTDI_EVENT_CONTEXT;




