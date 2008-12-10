/*++

	This is the part of NGdbg kernel debugger

	dngeng.cpp

	This file contains general debug-engine routines.

--*/

#include <ntifs.h>
#include "gui.h"
#include "dbgeng.h"
#include "ldasm.h"
#include "winnt.h"

PVOID
SetVector(
  IN UCHAR Interrupt,
  IN PVOID Handler,
  IN BOOLEAN MakeValid
  );
PVOID
GetVector(
  IN UCHAR Interrupt
  );
VOID
DelVector(
  IN UCHAR Interrupt
  );

PVOID FindImage (PWSTR);
PVOID *ppKiDispatchInterrupt;
VOID (NTAPI *KiDispatchInterrupt)();

BOOLEAN DbgEnteredDebugger;


PVOID 
GetKernelAddress (
	PWSTR Name
	)

/*++

Routine Description

	This routine lookups NT kernel's export function
	by name.
	It simply calls MmGetSystemRoutineAddress, so see
	MmGetSystemRoutineAddress description in MSDN

Arguments

	Name

		Function name to be found

Return Value

	Entry point to the function or NULL

Environment

	This function is usually called at IRQL < DISPATCH_LEVEL

--*/

{
	UNICODE_STRING uName;
	RtlInitUnicodeString (&uName, Name);

	return MmGetSystemRoutineAddress (&uName);
}

VOID 
DbgDispatchInterrupt(
	)

/*++

Routine Description

	CALLBACK

	This is the hook routine for KiDispatchInterrupt.
	HAL's IAT (import address table) is hooked and 
	 address of KiDispatchInterrupt is replaced by address
	 of this function.
	HAL calls KiDispatchInterrupt generally in two cases:

	HalpDipatchInterrupt
		KiDispatchInterrupt
			-> SwapContext
			
	HalpClockInterrupt
		KeUpdateSystemTime
			HalEndSystemInterrupt
				KiDispatchInterrupt
					-> SwapContext

	When debugger is active, dbgeng can sometimes enable
	 interrupts and current thread should NOT be swapped.
	So we hook KiDispatchInterrupt and simply ignore this call
	when debugger is active.

Arguments

	None

Return Value

	None

Environment

	This routine is called generally from hal!HalpDispatchInterrupt or
	 hal!HalEndSystemInterrupt

--*/
					
{
	if (DbgEnteredDebugger == FALSE)
	{
		KiDispatchInterrupt ();		
	}
}

//
// These routines hook or unhook HAL iat
//

VOID DbgUnhookHalImports()
{
	*ppKiDispatchInterrupt = KiDispatchInterrupt;
}

NTSTATUS DbgHookHalImports()
{
	PVOID pHal = FindImage (L"hal.dll");
	NTSTATUS Status = STATUS_NOT_FOUND;

	// Get hal headers
	PIMAGE_NT_HEADERS HalNtHeaders = (PIMAGE_NT_HEADERS) RtlImageNtHeader (pHal);
	ULONG IatSize = 0;

	// Get hal import
	PULONG Iat = (PULONG) 
		RtlImageDirectoryEntryToData( pHal, TRUE, IMAGE_DIRECTORY_ENTRY_IAT, &IatSize);

	*(PVOID*)&KiDispatchInterrupt = GetKernelAddress (L"KiDispatchInterrupt");

	KdPrint(("IAT = %X  Size = %X\n", Iat, IatSize));

	if (Iat == NULL)
	{
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	for ( ULONG i=0; i < IatSize/4; i++ )
	{
		KdPrint(("Function = %X\n", Iat[i]));

		if (Iat[i] == (ULONG)KiDispatchInterrupt)
		{
			KdPrint(("Found KiDispatchInterrupt\n"));

			ppKiDispatchInterrupt = (PVOID*) &Iat[i];
			*(ULONG*)&KiDispatchInterrupt = Iat[i];

			Iat[i] = (ULONG) DbgDispatchInterrupt;

			KdPrint(("KiDispatchInterrupt hooked\n"));

			return STATUS_SUCCESS;
		}
	}

	return Status;
}

typedef struct _KEXCEPTION_FRAME *PKEXCEPTION_FRAME;

BOOLEAN
DbgTrap (
    IN PKTRAP_FRAME TrapFrame,
    IN PKEXCEPTION_FRAME ExceptionFrame,
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN PCONTEXT ContextRecord,
    IN KPROCESSOR_MODE PreviousMode,
    IN BOOLEAN SecondChance
    );

PVOID *KiDebugRoutine;

BOOLEAN
(NTAPI * KdpTrapOrStub)(
    IN PKTRAP_FRAME TrapFrame,
    IN PKEXCEPTION_FRAME ExceptionFrame,
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN PCONTEXT ContextRecord,
    IN KPROCESSOR_MODE PreviousMode,
    IN BOOLEAN SecondChance
    );


BOOLEAN
DbgHookKiDebugRoutine(
	)

/*++

Routine Description

	This routine hooks KiDebugRoutine.
	See DbgTrap for details

Arguments

	None

Return Value

	TRUE if hook was successful, FALSE otherwise

--*/

{
	PVOID KdDisableDebugger = GetKernelAddress (L"KdDisableDebugger");
	PVOID KdDebuggerEnabled = GetKernelAddress (L"KdDebuggerEnabled");

	UCHAR *prev = NULL;

	for (UCHAR *p = (UCHAR*)KdDisableDebugger;
		*p != 0xC3; // retn
		p += size_of_code (p))
	{
		//
		// Search for
		// mov byte ptr [KdDebuggerEnabled], 0
		//

		if (p[0] == 0xC6 &&
			p[1] == 0x05 &&
			*(PVOID*)&p[2] == KdDebuggerEnabled &&
			p[6] == 0)
		{
			KdPrint(("Found MOV BYTE PTR [KdDebuggerEnabled],0 at %X\n", p));
			KdPrint(("Previous instruction at %X\n", prev));

			if (prev[0] == 0xC7 &&
				prev[1] == 0x05)
			{
				KdPrint(("Previous is MOV DWORD PTR [mem32], imm32\n"));

				KiDebugRoutine = *(PVOID**)&prev[2];

				KdPrint(("KiDebugRoutine is %X\n", KiDebugRoutine));

				*(PVOID*)&KdpTrapOrStub = *KiDebugRoutine;
				*KiDebugRoutine = DbgTrap;

				KdPrint(("KiDebugRoutine hooked, KdpTrapOrStub = %X\n", KdpTrapOrStub));
				return TRUE;
			}
		}

		prev = p;
	}

	KdPrint(("KiDebugRoutine NOT hooked!\n"));

	return FALSE;
}

VOID
DbgUnhookKiDebugRoutine(
	)
{
	*KiDebugRoutine = KdpTrapOrStub;
}


PVOID KiTrap03;
BOOLEAN I3HereUser = TRUE;
BOOLEAN I3HereKernel = FALSE;

//
// Debugger engine
//

PVOID Kei386EoiHelper;
UCHAR KTHREAD_DebugActive = 0x2c;

// We don't use interrupt hooking now, but there is a code
// to do this.
#if 0
PKINTERRUPT DbIntObj;

//
// esp + 0x20 or &FirstArg + 0x1c
//

#define INT_TRAP_IN_STACK_OFFSET	0x1c

BOOLEAN
DbgIntBreak(
	PKINTERRUPT InterruptObject,
	PVOID Context
	)
{
	PKTRAP_FRAME TrapFrame = (PKTRAP_FRAME)((PUCHAR)&InterruptObject + INT_TRAP_IN_STACK_OFFSET);

	KdPrint(("INT3! TrapFrame %X DbgArkMark %X current irql %X\n", TrapFrame, TrapFrame->DbgArgMark, KeGetCurrentIrql()));

	DbgTrapBreakPoint (TrapFrame);

	return FALSE;
}

//UCHAR DbVector = 3;
UCHAR DbVector = 0xF3;
#endif

VOID
DbgInitialize(
	)

/*++

Routine Description

	This is initialization routine for debugger engine.
	This routine is called from DriverEntry

Arguments

	None

Return Value

	None, debugger engine cannot fail initialization

--*/

{
#if 0
	KIRQL Irql;
	KAFFINITY Affinity;
	ULONG TempVector = HalGetInterruptVector (Internal, 0, 0, 0, &Irql, &Affinity);

	KdPrint(("TempVector = %x, Irql = %x, Affinity = %x\n", TempVector, Irql, Affinity));

	NTSTATUS Status = IoConnectInterrupt (
		&DbIntObj,
		DbgIntBreak,
		NULL,
		NULL,
		TempVector,
		Irql,
		Irql,
		Latched,
		TRUE,
		Affinity,
		FALSE
		);
	KdPrint(("IoConnectInterrupt %x\n", Status));

	if (!NT_SUCCESS(Status))
	{
		KdPrint(("Cannot connect interrupt\n"));
	}
	else
	{
		KdPrint(("Dispatch code %X\n", DbIntObj->DispatchCode));

		if (DbVector == 0x03)
		{
			KiTrap03 = SetVector (0x03, &DbIntObj->DispatchCode, TRUE);
		}
		else
		{
			SetVector (DbVector, &DbIntObj->DispatchCode, TRUE);
		}
	}
#endif
	
	Kei386EoiHelper = GetKernelAddress (L"Kei386EoiHelper");

	if (!NT_SUCCESS(DbgHookHalImports()))
	{
		KdPrint(("Could not hook hal imports\n"));
	}

	if (!DbgHookKiDebugRoutine())
	{
		KdPrint(("Could not hook KiDebugRoutine\n"));
	}
}

VOID
DbgCleanup(
	)

/*++

Routine description

	This function cleans up all hooks set by DbgInitialize()
	It is called from DriverUnload

Arguments

	None

Return Value

	None

--*/

{
	if (KiDebugRoutine)
	{
		DbgUnhookKiDebugRoutine ();
	}
	else
	{
		KdPrint(("KiDebugRoutine was not hooked!\n"));
	}

	if (KiDispatchInterrupt)
	{
		DbgUnhookHalImports();
	}
	else
	{
		KdPrint(("Hal import was not hooked!\n"));
	}

#if 0
	if (DbIntObj)
	{
		IoDisconnectInterrupt (DbIntObj);

		if (DbVector != 0x03)
		{
			DelVector (DbVector);
		}
		else
		{
			SetVector (0x03, KiTrap03, FALSE);
		}
	}
	else
	{
		KdPrint(("DbIntObj was not connected!\n"));
	}
#endif
}

#if 0
VOID
TrapPossibleVdm(
	PKTRAP_FRAME TrapFrame
	)
{
	KdPrint(("TRAP : possible VDM at KTRAP_FRAME %X\n", TrapFrame));

	KeBugCheckEx (
		NGDBG_INITIATED_CRASH,
		NGDBG_TRAP_POSSIBLE_VDM,
		(ULONG_PTR) TrapFrame,
		0,
		0
		);
}

VOID
TrapMustBeRestored(
	PKTRAP_FRAME TrapFrame
	)
{
	KdPrint(("TRAP : must be restored at KTRAP_FRAME %X\n", TrapFrame));

	KeBugCheckEx (
		NGDBG_INITIATED_CRASH,
		NGDBG_TRAP_MUST_BE_RESTORED,
		(ULONG_PTR) TrapFrame,
		0,
		0
		);
}
#endif

#if 0
VOID
DbgTrapBreakPoint(
	PKTRAP_FRAME TrapFrame
	)
{
	EXCEPTION_RECORD Record;
	NTSTATUS Status;
	KIRQL Irql;

	KeRaiseIrql (HIGH_LEVEL, &Irql);

	KdPrint(("Breakpoint trap at %x\n", TrapFrame->Eip));

	// Increment EIP in stack so it will point to the next
	//  instruction after 0xCC

	if (DbVector == 3)
	{
		TrapFrame->Eip ++;
	}

	Record.ExceptionCode = STATUS_BREAKPOINT;
	Record.ExceptionAddress = (PVOID) TrapFrame->Eip;
	Record.ExceptionFlags = 0;
	Record.NumberParameters = 0;
	Record.ExceptionInformation[0] = 0;

	Status = DbgDispatchException (&Record);

	if (Status == STATUS_SUCCESS)
	{
		//
		// Return to DbgTrap03
		//

		return;
	}

	//
	// Raise system exception
	//

	ExRaiseException (&Record);
}
#endif



VOID WR_ENTER_DEBUGGER(BOOLEAN UserInitiated, PDBG_CALLBACK Callback, PVOID Argument);

/*
VOID
DbgBreakPointCallback(
	BOOLEAN In,
	PVOID Argument,
	BOOLEAN DispatchException
	)
{
	PEXCEPTION_DISPATCH Dispatch = (PEXCEPTION_DISPATCH) Argument;
	PEXCEPTION_RECORD Record = Dispatch->Record;

	if (!In)
	{
		// Successful dispatch, don't raise an exception
		Dispatch->Status = STATUS_SUCCESS;
		return;
	}

	KdPrint(( __FUNCTION__ ": enter (Record %X CODE %X)\n", Record, Record->ExceptionCode));
	GuiPrintf(" -> int3 embedded breakpoint at %x, breaking through..\n", Record->ExceptionAddress);
}
*/

PVOID DisasmAtAddress (PVOID Address, ULONG nCommands);

VOID
DbgAccessViolationCallback(
	BOOLEAN In,
	PVOID Argument,
	BOOLEAN DispatchException
	)

/*++

Routine Description

	CALLBACK

	This routine is called from WR_ENTER_DEBUGGER as callback 
	 (see WR_ENTER_DEBUGGER for details)

Arguments

	In

		Specifies if callback is called before entering of after exit

	Argument

		Callback argument (pointer to EXCEPTION_DISPATCH)

	DispatchException

		If In==FALSE specifies whenever exception should be marked at dispatched
		 or not.
		If In==TRUE, undefined

Return Value

	None

Environment

	Called from WR_ENTER_DEBUGGER at raised IRQL

--*/

{
	PEXCEPTION_DISPATCH Dispatch = (PEXCEPTION_DISPATCH) Argument;
	PEXCEPTION_RECORD Record = Dispatch->Record;

	if (!In)
	{
		// Successful dispatch, don't raise an exception

		if (DispatchException)
		{
			KdPrint(( __FUNCTION__ ": exit (exception dispatched)\n"));
			Dispatch->Status = STATUS_SUCCESS;
		}
		else
		{
			KdPrint(( __FUNCTION__ ": exit (exception NOT dispatched)\n"));
			Dispatch->Status = STATUS_UNSUCCESSFUL;
		}

		return;
	}

	KdPrint(( __FUNCTION__ ": enter (Record %X CODE %X)\n", Record, Record->ExceptionCode));

	GuiPrintf(" -> access violation (%s chance) at %x, the memory %08X could not be %s ..\n", 
		Dispatch->SecondChance ? "second" : "first",
		Record->ExceptionAddress,
		Record->ExceptionInformation[1],
		(Record->ExceptionInformation[0] == 1 ? "written" : "read")
		);

	DisasmAtAddress (Record->ExceptionAddress, 10);
}

NTSTATUS
DbgDispatchException(
	PEXCEPTION_RECORD Record,
	BOOLEAN SecondChance
	)

/*++

Routine Description

	This routine tries to dispatch an exception.
	It calls WR_ENTER_DEBUGGER to wake up debugger

Arguments

	Record

		pointer to EXCEPTION_RECORD of the exception being dispatched

	SecondChance

		Specifies whenever exception is first or second chance

Return Value

	NTSTATUS of dispatch

Environment

	This routine is called from DbgTrap

--*/

{
	EXCEPTION_DISPATCH Dispatch;
	Dispatch.Record = Record;
	Dispatch.SecondChance = SecondChance;
	Dispatch.Status = STATUS_NOT_IMPLEMENTED;

	VOID
	(*pExceptionCallback)(
		BOOLEAN In,
		PVOID Argument,
		BOOLEAN DispatchException
		) = NULL;

	switch (Record->ExceptionCode)
	{	
//	case STATUS_BREAKPOINT:
//		pExceptionCallback = DbgBreakPointCallback;
//		break;

	case STATUS_ACCESS_VIOLATION:
		pExceptionCallback = DbgAccessViolationCallback;
		break;
	}

	// set other exception callbacks for codes such as
	// status_access_violation, etc.

	if (pExceptionCallback)
	{
		WR_ENTER_DEBUGGER (FALSE, pExceptionCallback, &Dispatch);
	}

	return Dispatch.Status;
}

//
// This routine replaces general KiDebugRoutine
//
// Usually this pointer points to KdpStub or KdpTrap
//

BOOLEAN
DbgTrap (
    IN PKTRAP_FRAME TrapFrame,
    IN PKEXCEPTION_FRAME ExceptionFrame,
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN PCONTEXT ContextRecord,
    IN KPROCESSOR_MODE PreviousMode,
    IN BOOLEAN SecondChance
    )

/*++

Routine Description:

	CALLBACK

	This routine is called whenever a exception is dispatched and the kernel
    debugger is active.

	This is a hook routine for KiDebugRoutine.
	Usually KiDebugRoutine points to KdpStub (if kd is inactive)
	 or KdpTrap (if kd is enabled).

Arguments:

    TrapFrame - Supplies a pointer to a trap frame that describes the
        trap.

    ExceptionFrame - Supplies a pointer to a exception frame that describes
        the trap.

    ExceptionRecord - Supplies a pointer to an exception record that
        describes the exception.

    ContextRecord - Supplies the context at the time of the exception.

    PreviousMode - Supplies the previous processor mode.

    SecondChance - Supplies a boolean value that determines whether this is
        the second chance (TRUE) that the exception has been raised.

Return Value:

    A value of TRUE is returned if the exception is handled. Otherwise a
    value of FALSE is returned.

--*/

{
	// We cannot use KdPrint because it causes a recursion :(
//	KdPrint(("DbgTrap! (TRAP %X EXC %X REC %X CTX %X PREV %X CHANCE %X\n",
//		TrapFrame, ExceptionFrame, ExceptionRecord, ContextRecord, PreviousMode, SecondChance
//		));

	if (ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)
	{
		NTSTATUS Status;
		KIRQL Irql;

		KeRaiseIrql (HIGH_LEVEL, &Irql);

		Status = DbgDispatchException (ExceptionRecord, SecondChance);

		KeLowerIrql (Irql);

		return NT_SUCCESS(Status);
	}

	return KdpTrapOrStub (TrapFrame, ExceptionFrame, ExceptionRecord, ContextRecord, PreviousMode, SecondChance);
}