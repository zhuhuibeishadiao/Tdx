
#ifndef XTDI_HEAD_DEIFNE_
#define XTDI_HEAD_DEIFNE_

#ifdef __cplusplus
extern "C" {
#endif

#include <tdikrnl.h>

#define XTDI_PROTO_TCP         6
#define XTDI_PROTO_UDP         17

#define x_alloc(isize)              ExAllocatePool(NonPagedPool, isize)
#define x_free(pdata)               ExFreePool(pdata)
#define x_alloc_tag(isize, utag)    ExAllocatePoolWithTag(NonPagedPool, isize, utag)
#define x_free_tag(pdata, utag)     ExFreePoolWithTag(pdata, utag)


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
                                    OUT PIRP *IoRequestPacket);
NTSTATUS tdi_event_receive(
                           __in_opt PVOID TdiEventContext,
                           __in_opt CONNECTION_CONTEXT ConnectionContext,
                           __in ULONG ReceiveFlags,
                           __in ULONG BytesIndicated,
                           __in ULONG BytesAvailable,
                           __out ULONG *BytesTaken,
                           __in PVOID Tsdu,                   // pointer describing this TSDU, typically a lump of bytes
                           __out_opt PIRP *IoRequestPacket    // TdiReceive IRP if MORE_PROCESSING_REQUIRED.
                           );

typedef struct _xt_tdi
{
	PDRIVER_OBJECT drvobj;
	PDEVICE_OBJECT drvobj_tcp;		// TCP Filter
	PDEVICE_OBJECT drvobj_udp;		// UDP Filter
	PDEVICE_OBJECT drvobj_ioctrl;	// User Program Used
} xt_tdi, *pxt_tdi;

typedef struct _xt_devext
{
	PDEVICE_OBJECT      lower_device;
    CHAR                protocol;     // TCP=6 or UDP=17
}xt_devext, *pxt_devext;

extern xt_tdi g_xttdi;

extern NTSTATUS xtdi_init(PDRIVER_OBJECT drvobj);
extern NTSTATUS xtdi_deinit();

extern NTSTATUS xtdi_hook_tcp();
extern NTSTATUS xtdi_unhook_tcp();
extern NTSTATUS xtdi_hook_udp();
extern NTSTATUS xtdi_unhook_udp();

extern BOOLEAN xtdi_hookcheck_tcp();
extern BOOLEAN xtdi_hookcheck_udp();


extern NTSTATUS xtdi_dispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);


typedef enum WIN_VER_DETAIL {
		WINDOWS_VERSION_NONE,
		WINDOWS_VERSION_2K,
		WINDOWS_VERSION_XP,
		WINDOWS_VERSION_XP_64,
		WINDOWS_VERSION_2K3,
		WINDOWS_VERSION_2K3_SP1_SP2,
		WINDOWS_VERSION_VISTA,
		WINDOWS_VERSION_WIN7,
		WINDOWS_VERSION_WIN7_64
} WIN_VER_DETAIL;
extern WIN_VER_DETAIL g_osver;
extern WIN_VER_DETAIL GetWindowsVersion();

#ifdef __cplusplus
}
#endif

#endif
