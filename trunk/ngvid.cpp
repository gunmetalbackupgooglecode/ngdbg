/*++

	This is the part of NGdbg kernel debugger
	
	ngvid.cpp

	This file contains routine to prepare all enviromnent
	to use video.
	It searches DrvCopyBits, pointer to primary surface, etc..

	Also, it hooks keyboard.

	This file also contains DriverEntry and DriverUnload of the driver
	
--*/

#include <ntifs.h>
#include <stdarg.h>
#include "winddi.h"
#include "winnt.h"
#include "splice.h"
#include "win32k.h"
#include "i8042.h"
#include <ntddkbd.h>
#include <ntddmou.h>
#include <ntdd8042.h>
#include "dbgeng.h"

#define  KBD_HOOK_ISR		0


VOID
Worker(
	);

PVOID 
IoHookInterrupt (
	ULONG Vector, 
	PVOID NewRoutine
	);

extern BOOLEAN (*OldISR)(PKINTERRUPT,PVOID);

BOOLEAN
  InterruptService(
    IN PKINTERRUPT  Interrupt,
    IN PVOID  ServiceContext
    );

PVOID
GetVector(
  IN UCHAR Interrupt
  );

ULONG 
GetIOAPICIntVector (
	ULONG Vector
	);

VOID
Cleanup(
	);

VOID 
ProcessScanCode(
	UCHAR Byte
	);


VOID _cdecl EngPrint (char *fmt, ...)
{
	va_list va;
	va_start (va, fmt);

	EngDebugPrint ("", fmt, va);
}

//
// Hook routine for IOCTL_INTERNAL_I8042_HOOK_KEYBOARD
//

BOOLEAN
  IsrHookRoutine(
    IN PVOID  IsrContext,							// esp+4
    IN PKEYBOARD_INPUT_DATA  CurrentInput,			// esp+8
    IN POUTPUT_PACKET  CurrentOutput,				// esp+c
    IN OUT UCHAR  StatusByte,						// esp+10
    IN PUCHAR  Byte,								// esp+14
    OUT PBOOLEAN  ContinueProcessing,				// esp+18
    IN PKEYBOARD_SCAN_STATE  ScanState				// esp+1c
    )
{
	KdPrint(("IsrHookRoutine: Byte %X\n", *Byte));
	*ContinueProcessing = TRUE;

	ProcessScanCode (*Byte);

	return TRUE;
}

KDPC HotkeyResetStateDpc;
VOID
  HotkeyResetStateDeferredRoutine(
    IN struct _KDPC  *Dpc,
    IN PVOID  DeferredContext,
    IN PVOID  SystemArgument1,
    IN PVOID  SystemArgument2
    );


NTSTATUS
I8042HookKeyboard(
	PI8042_KEYBOARD_ISR IsrRoutine
	)

/*++

Routine Description

	Hook keyboard by calling i8042prt with ioctl code IOCTL_INTERNAL_I8042_HOOK_KEYBOARD

Arguments

	IsrRoutine

		New hook routine

Return value

	NTSTATUS of the operation

--*/

{
	UNICODE_STRING DeviceName;
	PDEVICE_OBJECT DeviceObject;
	PFILE_OBJECT FileObject;
	NTSTATUS Status;

	RtlInitUnicodeString (&DeviceName, L"\\Device\\KeyboardClass0");

	Status = IoGetDeviceObjectPointer (&DeviceName,
		FILE_READ_ATTRIBUTES,
		&FileObject,
		&DeviceObject);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("IoGetDeviceObjectPointer failed st %X\n", Status));
		return Status;
	}

	PIRP Irp;
	IO_STATUS_BLOCK IoStatus;
	KEVENT Event;

	KeInitializeEvent (&Event, SynchronizationEvent, FALSE);

	INTERNAL_I8042_HOOK_KEYBOARD hookkbd = {0};
	hookkbd.IsrRoutine = IsrRoutine;
	
	Irp = IoBuildDeviceIoControlRequest (
		IOCTL_INTERNAL_I8042_HOOK_KEYBOARD,
		DeviceObject,
		&hookkbd,
		sizeof(hookkbd),
		NULL,
		0,
		TRUE,
		&Event,
		&IoStatus );

	Status = IoCallDriver (DeviceObject, Irp);

	if (Status == STATUS_PENDING)
	{
		KeWaitForSingleObject (&Event, Executive, KernelMode, FALSE, NULL);
	}

	if (NT_SUCCESS(Status))
		Status = IoStatus.Status;

	ObDereferenceObject (FileObject);

	if (!NT_SUCCESS(Status))
	{
		KdPrint(("IOCTL_INTERNAL_HOOK_KEYBOARD failed with status %X\n", Status));
		return Status;
	}

	KdPrint(("IOCTL_INTERNAL_HOOK_KEYBOARD ok\n"));
	return STATUS_SUCCESS;
}

#pragma pack(push,1)
typedef union TRAMPOLINE
{
	struct
	{
		UCHAR PushOpcode;			// PUSH IsrRoutine
		PVOID Address;
		UCHAR RetOpcode;			// RETN
	} e1;
	struct
	{
		USHORT XorEaxEaxOpcode;		// 33C0			XOR EAX, EAX
		UCHAR IncEaxOpcode;			// 40			INC EAX
		UCHAR MovOpcode[4];			// 8B4C2418		MOV ECX, DWORD PTR SS:[ESP+18]
		UCHAR Mov2Opcode[3];		// C60101		MOV BYTE PTR [ECX], 1
		UCHAR RetOpcode[3];			// C21C00		RETN 1C
	} e2;
} *PTRAMPOLINE;
#pragma pack(pop)

PTRAMPOLINE TrampolineIsr;

//
// Create ISR trampoline
//

VOID CreateTrampoline()
{
	PSHARED_DISP_DATA disp = GetSharedData();
	if (disp->Signature != SHARED_SIGNATURE)
	{
		KdPrint (("ngvid:" __FUNCTION__ ": Damaged shared block %X signature %X should be %X\n",
			disp, disp->Signature, SHARED_SIGNATURE));

		return;
	}

	if (disp->Trampoline)
	{
		KdPrint(("Trampoline already exists at %X\n", disp->Trampoline));

		TrampolineIsr = (PTRAMPOLINE) disp->Trampoline;
	}
	else
	{
		TrampolineIsr = (PTRAMPOLINE) ExAllocatePool (NonPagedPool, sizeof(TRAMPOLINE));

		KdPrint(("Trampoline allocated at %X\n", TrampolineIsr));
	}

	KIRQL Irql;
	KeRaiseIrql (HIGH_LEVEL, &Irql);
	TrampolineIsr->e1.PushOpcode = 0x68;
	TrampolineIsr->e1.Address = IsrHookRoutine;
	TrampolineIsr->e1.RetOpcode = 0xC3;
	KeLowerIrql (Irql);

	KdPrint(("Trampoline created\n", TrampolineIsr));
	
	if (disp->Trampoline == NULL)
	{
		I8042HookKeyboard  ((PI8042_KEYBOARD_ISR) TrampolineIsr);
		disp->Trampoline = TrampolineIsr;
	}
}

//
// Reset ISR trampoline
//

VOID ResetTrampoline()
{
	PSHARED_DISP_DATA disp = GetSharedData();
	if (disp->Signature != SHARED_SIGNATURE)
	{
		KdPrint (("ngvid:" __FUNCTION__ ": Damaged shared block %X signature %X should be %X\n",
			disp, disp->Signature, SHARED_SIGNATURE));

		return;
	}

	ASSERT (disp->Trampoline);

	TrampolineIsr = (PTRAMPOLINE) disp->Trampoline;

	KdPrint(("Resetting trampoline at %X\n", TrampolineIsr));

	KIRQL Irql;
	KeRaiseIrql (HIGH_LEVEL, &Irql);
/*
		USHORT XorEaxEaxOpcode;		// 33C0			XOR EAX, EAX
		UCHAR IncEaxOpcode;			// 40			INC EAX
		UCHAR MovOpcode[4];			// 8B4C2418		MOV ECX, DWORD PTR SS:[ESP+18]
		UCHAR Mov2Opcode[3];		// C60101		MOV BYTE PTR [ECX], 1
		UCHAR RetOpcode[3];			// C21C00		RETN 1C
*/
	TrampolineIsr->e2.XorEaxEaxOpcode = 0xC033;
	TrampolineIsr->e2.IncEaxOpcode = 0x40;
	TrampolineIsr->e2.MovOpcode[0] = 0x8B;
	TrampolineIsr->e2.MovOpcode[1] = 0x4C;
	TrampolineIsr->e2.MovOpcode[2] = 0x24;
	TrampolineIsr->e2.MovOpcode[3] = 0x18;
	TrampolineIsr->e2.Mov2Opcode[0] = 0xC6;
	TrampolineIsr->e2.Mov2Opcode[1] = 0x01;
	TrampolineIsr->e2.Mov2Opcode[2] = 0x01;
	TrampolineIsr->e2.RetOpcode[0] = 0xC2;
	TrampolineIsr->e2.RetOpcode[1] = 0x1C;
	TrampolineIsr->e2.RetOpcode[2] = 0x00;

	KeLowerIrql (Irql);
}

//
// Driver unload routine
//
void DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
	W32PrepareCall ();

#if KBD_HOOK_ISR
	IoHookInterrupt (OldKbd, OldISR);
#else
	ResetTrampoline();
	//I8042HookKeyboard  ((PI8042_KEYBOARD_ISR) NULL);
#endif
	Cleanup();
	W32ReleaseCall ();

	DbgCleanup();

	KdPrint(("[~] DriverUnload()\n"));
}


UCHAR SplicingBuffer[50];
UCHAR BackupBuffer[5];
ULONG BackupWritten;

//
// new DrvCopyBits splice hook
//

BOOLEAN
NewDrvCopyBits(
   OUT _SURFOBJ *psoDst,
   IN _SURFOBJ *psoSrc,
   IN VOID *pco,
   IN VOID *pxlo,
   IN VOID *prclDst,
   IN VOID *pptlSrc
   )
{
	KdPrint(("NewDrvCopyBits (pdoDst=%X)\n", psoDst));

	if (pPrimarySurf == NULL &&
		psoDst->sizlBitmap.LowPart >= 640 &&
		psoDst->sizlBitmap.HighPart >= 480)
	{
		KdPrint(("Got primary surface %X\n", psoDst));
		pPrimarySurf = psoDst;
		KeSetEvent (&SynchEvent, 0, 0);
	}

	return ((BOOLEAN (*)(SURFOBJ*,SURFOBJ*,VOID*,VOID*,VOID*,VOID*))&SplicingBuffer) (psoDst, psoSrc, pco, pxlo, prclDst, pptlSrc);
}

extern BOOLEAN WindowsNum;
extern BOOLEAN WindowsCaps;
extern BOOLEAN WindowsScroll;

#define IOCTL_KEYBOARD_QUERY_INDICATORS CTL_CODE(FILE_DEVICE_KEYBOARD, 0x0010, METHOD_BUFFERED, FILE_ANY_ACCESS) 

#define KEYBOARD_CAPS_LOCK_ON     4
#define KEYBOARD_NUM_LOCK_ON      2
#define KEYBOARD_SCROLL_LOCK_ON   1

NTSTATUS
KbdWinQueryLeds(
	)
/**
	Query windows current state of LEDs
*/
{
	UNICODE_STRING DeviceName;
	PDEVICE_OBJECT DeviceObject;
	PFILE_OBJECT FileObject;
	NTSTATUS Status;

	RtlInitUnicodeString (&DeviceName, L"\\Device\\KeyboardClass0");

	Status = IoGetDeviceObjectPointer (&DeviceName,
		FILE_READ_ATTRIBUTES,
		&FileObject,
		&DeviceObject);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("IoGetDeviceObjectPointer failed st %X\n", Status));
		return Status;
	}

	PIRP Irp;
	IO_STATUS_BLOCK IoStatus;
	KEVENT Event;

	KeInitializeEvent (&Event, SynchronizationEvent, FALSE);

	KEYBOARD_UNIT_ID_PARAMETER unitID = {0};
	KEYBOARD_INDICATOR_PARAMETERS leds = {0};


	Irp = IoBuildDeviceIoControlRequest (
		IOCTL_KEYBOARD_QUERY_INDICATORS,
		DeviceObject,
		&unitID,
		sizeof(unitID),
		&leds,
		sizeof(leds),
		FALSE,
		&Event,
		&IoStatus );

	Status = IoCallDriver (DeviceObject, Irp);

	if (Status == STATUS_PENDING)
	{
		KeWaitForSingleObject (&Event, Executive, KernelMode, FALSE, NULL);
	}

	if (NT_SUCCESS(Status))
		Status = IoStatus.Status;

	ObDereferenceObject (FileObject);

	if (!NT_SUCCESS(Status))
	{
		KdPrint(("IOCTL_KEYBOARD_QUERY_INDICATORS failed with status %X\n", Status));
		return Status;
	}

	WindowsNum = !!(leds.LedFlags & KEYBOARD_NUM_LOCK_ON);
	WindowsCaps = !!(leds.LedFlags & KEYBOARD_CAPS_LOCK_ON);
	WindowsScroll = !!(leds.LedFlags & KEYBOARD_SCROLL_LOCK_ON);

	KdPrint(("IOCTL_KEYBOARD_QUERY_INDICATORS ok\n"));
	return STATUS_SUCCESS;
}

// Open registry key, ZwOpenKey wrapper
HANDLE RegOpenKey (PWSTR KeyName, ACCESS_MASK DesiredAccess)
{
	OBJECT_ATTRIBUTES Oa;
	UNICODE_STRING uKeyName;
	NTSTATUS Status;
	HANDLE hKey;

	RtlInitUnicodeString (&uKeyName, KeyName);
	InitializeObjectAttributes (
		&Oa, 
		&uKeyName, 
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 
		0, 
		0
		);

	Status = ZwOpenKey (&hKey, DesiredAccess, &Oa);

	if (!NT_SUCCESS(Status))
	{
		KdPrint (("ZwOpenKey(%S) failed with status %X\n", KeyName));
		return NULL;
	}
	return hKey;
}

// Query value from key, ZwQueryValueKey wrapper
BOOLEAN RegQueryValue (HANDLE hKey, PWSTR ValueName, ULONG Type, PVOID Buffer, ULONG *Len)
{
	UNICODE_STRING uValueName;
	NTSTATUS Status;
	UCHAR InfoBuffer[512] = {0};
	KEY_VALUE_PARTIAL_INFORMATION *Info = (KEY_VALUE_PARTIAL_INFORMATION*) InfoBuffer;
	ULONG ResultLength;

	RtlInitUnicodeString (&uValueName, ValueName);

	Status = ZwQueryValueKey (
		hKey, 
		&uValueName, 
		KeyValuePartialInformation,
		Info,
		sizeof(InfoBuffer),
		&ResultLength
		);

	if (NT_SUCCESS(Status))
	{
		if (Type != Info->Type)
		{
			KdPrint(("Type mismatch (%d, %d)\n", Type, Info->Type));
			return FALSE;
		}

		ULONG Length = min (*Len, Info->DataLength);

		memcpy (Buffer, Info->Data, Length);

		*Len = Length;

		return TRUE;
	}

	KdPrint(("ZwQueryValueKey(%S) failed with status %X\n", ValueName, Status));
	return FALSE;
}

PVOID FindImage (PWSTR ImageName);


VOID 
REINITIALIZE_ADAPTER( 
	PVOID 
	)

/*++

Routine Description

	This routine re-initializes display driver
	 to obtains its DrvCoptBits pointer.
	This routine executed as a separate thread in the context of CSRSS.EXE

Arguments

	PVOID

		Thread context, always NULL

Return Value

	None, thread terminates by call PsTerminateSystemThread

Environment

	Separate thread of CSRSS process

--*/

{
	//
	// This routine runs in the context of csrss.exe
	//
	
	KdPrint(("REINITIALIZE_ADAPTER enter\n"));

	HANDLE hDrv = EngLoadImage (L"vid_copy.dll");
	KdPrint(("vid_copy is %X\n", hDrv));
	if (hDrv)
	{
		BOOLEAN (NTAPI *pOriginalDrvEnableDriver)(
			ULONG iEngineVersion,
			ULONG cj,
			PDRVENABLEDATA pded
			);

		*(PVOID*)&pOriginalDrvEnableDriver = EngFindImageProcAddress (hDrv, "DrvEnableDriver");

		KdPrint(("pOriginalDrvEnableDriver = %X\n", pOriginalDrvEnableDriver));

		if (pOriginalDrvEnableDriver)
		{
			BOOLEAN Ret;
			DRVENABLEDATA DrvEnableData = {0};
		
			Ret = pOriginalDrvEnableDriver (DDI_DRIVER_VERSION_NT5_01_SP1,
				sizeof(DrvEnableData),
				&DrvEnableData);

			KdPrint(("pOriginalDrvEnableDriver returned %X\n", Ret));

			if (Ret)
			{
				for (ULONG i = 0; i<DrvEnableData.c; i++)
				{
					if (DrvEnableData.pdrvfn[i].iFunc == INDEX_DrvCopyBits)
					{
						KdPrint(("Found DrvCopyBits: %X\n", DrvEnableData.pdrvfn[i].pfn));

						HANDLE hKey;
						wchar_t value[512];

						hKey = RegOpenKey (L"\\Registry\\Machine\\Software\\NGdbg", KEY_QUERY_VALUE);
						if (hKey)
						{
							ULONG Len = sizeof(value);

							if (RegQueryValue (hKey, L"DisplayDriver", REG_SZ, value, &Len))
							{
								KdPrint(("Display driver: %S\n", value));

								wcscat (value, L".dll");

								PVOID OrigBase = FindImage (value);
								PVOID VidBase = FindImage (L"vid_copy.dll");

								if (OrigBase && VidBase)
								{
									ULONG Offset = (ULONG)DrvEnableData.pdrvfn[i].pfn - (ULONG)VidBase;

									KdPrint(("Offset %X\n", Offset));

									pDrvCopyBits = (PUCHAR)OrigBase + Offset;

									KdPrint(("DrvCopyBits %X\n", pDrvCopyBits));
								}
								else
								{
									KdPrint(("FindImage failed: OrigBase %X, VidBase %X\n", OrigBase, VidBase));
								}
							}
							else
							{
								KdPrint(("RegQueryValue failed\n"));
							}

							ZwClose (hKey);
						}
						else
						{
							KdPrint(("RegOpenKey failed\n"));
						}
					}
				}
			}
		}

		EngUnloadImage (hDrv);
	}

	KdPrint(("REINITIALIZE_ADAPTER exit\n"));

	PsTerminateSystemThread (0);
}
extern PEPROCESS CsrProcess;
extern "C"
{
	extern POBJECT_TYPE *PsProcessType;
	extern POBJECT_TYPE *PsThreadType;
}


//
// Driver entry point
//
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING )
{
	DriverObject->DriverUnload = DriverUnload;
	KdPrint(("[~] DriverEntry()\n"));

	KdPrint (("First hello from nt\n"));

	if(!NT_SUCCESS(W32FindAndSwapIAT ()))
	{
		KdPrint(("could not swap import\n"));
		return STATUS_INVALID_FILE_FOR_SECTION;
	}

	// import something from W32k
	EngPrint ("Second hello from win32k\n");

	//////////////////////////////////////////////////////// !! DEBUG DEBUG !!     ////////////

	HANDLE hCsrProcess;
	NTSTATUS Status;

	Status = ObOpenObjectByPointer (
		CsrProcess,
		OBJ_KERNEL_HANDLE,
		NULL, 
		PROCESS_ALL_ACCESS,
		*PsProcessType, 
		KernelMode, 
		&hCsrProcess
		); 

	if (!NT_SUCCESS(Status))
	{
		KdPrint(("ObOpenObjectByPointer failed with status %X\n", Status));
		W32ReleaseCall();
		return Status;
	}

	KdPrint(("csr opened, handle %X\n", hCsrProcess));

	//
	// EngLoadImage uses KeAttachProcess/KeDetachProcess to attach to csrss process
	// KeDetachProcess detaches to thread's original process, but our thread's
	// original process is System! (because we are running in the context of system
	// worker thread that loads a driver).
	// So we have to run our function in the context of csrss.exe
	//

	HANDLE ThreadHandle;
	CLIENT_ID ClientId;
	OBJECT_ATTRIBUTES Oa;
	InitializeObjectAttributes (&Oa, NULL, OBJ_KERNEL_HANDLE, 0, 0);

	Status = PsCreateSystemThread (
		&ThreadHandle,
		THREAD_ALL_ACCESS,
		&Oa,
		hCsrProcess,
		&ClientId,
		REINITIALIZE_ADAPTER,
		NULL
		);

	if (!NT_SUCCESS(Status))
	{
		KdPrint(("PsCreateSystemThread failed with status %X\n", Status));
		ZwClose (hCsrProcess);
		W32ReleaseCall();
		return Status;
	}

	KdPrint(("thread created, handle %X\n", ThreadHandle));

	PETHREAD Thread;

	Status = ObReferenceObjectByHandle(
		ThreadHandle,
		THREAD_ALL_ACCESS,
		*PsThreadType,
		KernelMode,
		(PVOID*) &Thread,
		NULL
		);

	if (!NT_SUCCESS(Status))
	{
		KdPrint(("ObReferenceObjectByHandle failed with status %X\n", Status));
		// cannot unload because thread is running
		KeBugCheck (0);
	}

	KdPrint(("thread referenced to %X\n", Thread));

	KeWaitForSingleObject (Thread, Executive, KernelMode, FALSE, NULL);

	KdPrint(("Thread terminated\n"));

	ZwClose (hCsrProcess);
	ObDereferenceObject (Thread);
	ZwClose (ThreadHandle);

	KdPrint(("success\n", hCsrProcess));

	if (!pDrvCopyBits)
	{
		KdPrint(("Could not find DrvCopyBits\n"));
		W32ReleaseCall();
		return STATUS_UNSUCCESSFUL;
	}

	//////////////////////////////////////////////////////// !! DEBUG DEBUG !!     ////////////

	if(!NT_SUCCESS(KbdWinQueryLeds()))
	{
		W32ReleaseCall();
		return STATUS_UNSUCCESSFUL;
	}

	PSHARED_DISP_DATA disp = GetSharedData();
	if (!disp)
	{
		EngPrint ("ngvid: could not get shared data\n");
		W32ReleaseCall();
		return STATUS_UNSUCCESSFUL;
	}
	if (disp->Signature != SHARED_SIGNATURE)
	{
		EngPrint ("ngvid: Damaged shared block %X signature %X should be %X\n",
			disp, disp->Signature, SHARED_SIGNATURE);
		//__asm int 3

		W32ReleaseCall();
		return STATUS_UNSUCCESSFUL;
	}

	KdPrint (("Got shared %X Sign %X Surf %X\n", disp, disp->Signature, disp->pPrimarySurf));

#if 0
	//
	// Temporarily hook DrvCopyBits
	//

	pDrvCopyBits = disp->pDrvCopyBits;

#endif

	if (!disp->pPrimarySurf)
	{
		KdPrint(("DrvCopyBits %X\n", pDrvCopyBits));

		KeInitializeEvent (&SynchEvent, SynchronizationEvent, FALSE);

		if (SpliceFunctionStart (pDrvCopyBits, NewDrvCopyBits, SplicingBuffer, sizeof(SplicingBuffer), BackupBuffer, &BackupWritten, FALSE))
		{
			KdPrint(("SpliceFunctionStart FAILED!!!\n"));
			W32ReleaseCall();
			return STATUS_UNSUCCESSFUL;
		}

		KdPrint(("Now you have to move mouse pointer across the display ...\n"));

		KeWaitForSingleObject (&SynchEvent, Executive, KernelMode, FALSE, NULL);

		UnspliceFunctionStart (pDrvCopyBits, BackupBuffer, FALSE);

		KdPrint(("Wait succeeded, so got primary surf %X\n", pPrimarySurf));
		disp->pPrimarySurf = pPrimarySurf;
	}
	else
	{
		KdPrint(("Already have primary surface\n"));
		pPrimarySurf = disp->pPrimarySurf;
	}

#if KBD_HOOK_ISR
	OldKbd = GetIOAPICIntVector (1);
	*(PVOID*)&OldISR = IoHookInterrupt ( (UCHAR)OldKbd, InterruptService);
#else
	CreateTrampoline();
	//I8042HookKeyboard  ((PI8042_KEYBOARD_ISR) IsrHookRoutine);
#endif

	KdPrint(("Keyboard hooked\n"));

	KeInitializeDpc (&HotkeyResetStateDpc, HotkeyResetStateDeferredRoutine, NULL);

	///

	Worker();

	///

	W32ReleaseCall();

	DbgInitialize ();

	KdPrint(("[+] Driver initialization successful\n"));
	return STATUS_SUCCESS;
}
