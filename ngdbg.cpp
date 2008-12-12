/*++

	This is the part of NGdbg kernel debugger
	
	ngdbg.cpp

	This file contains DriverEntry and DriverUnload routines.
	
--*/

#include <ntifs.h>
#include "winnt.h"
#include "win32k.h"
#include "splice.h"
#include "dbgeng.h"
#include "winddi.h"
#include "win32k.h"
#include <stdarg.h>

_SURFOBJ *pPrimarySurf;
PVOID pDrvCopyBits;
KEVENT SynchEvent;


PVOID *GetMem()
{
	return ((PVOID*)&((IMAGE_DOS_HEADER*)W32BaseAddress)->e_res2);
}

PSHARED_DISP_DATA GetSharedData()
{
	PSHARED_DISP_DATA* pData = (PSHARED_DISP_DATA*)GetMem();

	if (!*pData)
	{
		KdPrint(("Shared data not allocated, creating\n"));

		*pData = (PSHARED_DISP_DATA) ExAllocatePool (NonPagedPool, sizeof(SHARED_DISP_DATA));

		if (!*pData)
		{
			KdPrint (("ExAllocatePool failed\n"));
			return NULL;
		}

		memset (*pData, 0, sizeof(SHARED_DISP_DATA));

		(*pData)->Signature = SHARED_SIGNATURE;
	}

	return *pData;
}


VOID _cdecl EngPrint (char *fmt, ...)
{
	va_list va;
	va_start (va, fmt);

	EngDebugPrint ("", fmt, va);
}


VOID
Worker(
	);

UCHAR SplicingBuffer[50];
UCHAR BackupBuffer[5];
ULONG BackupWritten;

extern PEPROCESS CsrProcess;
extern "C"
{
	extern POBJECT_TYPE *PsProcessType;
	extern POBJECT_TYPE *PsThreadType;
}



BOOLEAN
NewDrvCopyBits(
   OUT _SURFOBJ *psoDst,
   IN _SURFOBJ *psoSrc,
   IN VOID *pco,
   IN VOID *pxlo,
   IN VOID *prclDst,
   IN VOID *pptlSrc
   );

VOID 
REINITIALIZE_ADAPTER( 
	PVOID 
	);

NTSTATUS
KbdWinQueryLeds(
	);

VOID
Cleanup(
	);

VOID ResetTrampoline();
VOID CreateTrampoline();

KDPC HotkeyResetStateDpc;
VOID
  HotkeyResetStateDeferredRoutine(
    IN struct _KDPC  *Dpc,
    IN PVOID  DeferredContext,
    IN PVOID  SystemArgument1,
    IN PVOID  SystemArgument2
    );

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


//
// Driver entry point
//
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING )
{
	DriverObject->DriverUnload = DriverUnload;
	KdPrint(("[~] DriverEntry()\n"));

	/*
	if (KeNumberProcessors > 1)
	{
		KdPrint(("Your number of processors : %d\n", KeNumberProcessors));
		KdPrint(("Only UP machines supported\n"));
		return STATUS_NOT_SUPPORTED;
	}
	*/

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
