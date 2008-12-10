/*++

	This is the part of NGdbg kernel debugger

	intvect.cpp

	Contains routines that work with APIC and IDT

--*/

#include <ntifs.h>

//
// IDT entry
//

#pragma pack(push, 1)
struct IDTEntry
{
    USHORT OffsetLow;
    USHORT Selector;
    UCHAR ReservedByte;
    UCHAR Type : 3;
    UCHAR D : 1;
    UCHAR UnusedBits2 : 1;
    UCHAR DPL : 2;
    UCHAR Present : 1;
    USHORT OffsetHigh;
};
#pragma pack(pop)

//
// IDTR structure
//

#pragma pack(push, 2)
struct IDTR
{
    USHORT Limit;
    IDTEntry* Table;
};
#pragma pack(pop)


IDTR Idtr;

PVOID
GetVector(
  IN UCHAR Interrupt
  )
/**
	Get IDT vector
*/
{
    ULONG OldHandler;

	if (Idtr.Table == NULL)
		__asm sidt fword ptr [Idtr]

	OldHandler = Idtr.Table[Interrupt].OffsetLow  | ( Idtr.Table[Interrupt].OffsetHigh << 16 );

	if (Idtr.Table[Interrupt].Present)
		return (PVOID) OldHandler;
	else
		return NULL;
}

VOID
DelVector(
  IN UCHAR Interrupt
  )
/**
	Delete IDT vector
*/
{
	if (Idtr.Table == NULL)
		__asm sidt fword ptr [Idtr]

	Idtr.Table[Interrupt].Present = FALSE;
}


ULONG GetAPICValue (PVOID pAPIC, ULONG xOffset)
{
	__asm
	{
		mov ecx, [pAPIC]
		mov eax, [xOffset]

		pushfd
		cli

		mov [ecx], eax
		mov eax, [ecx+10h]

		popfd
	}
}

ULONG GetIOAPICIntVector (ULONG Vector)
{
	PHYSICAL_ADDRESS PhysAPIC = {0xFEC00000, 0};
	PVOID pAPIC;
	ULONG IOAPICVector;

	pAPIC = MmMapIoSpace (PhysAPIC, 0x100, MmNonCached);
	IOAPICVector = GetAPICValue (pAPIC, (Vector*2 + 0x10)) & 0xFF;

	MmUnmapIoSpace (pAPIC, 0x100);
	return IOAPICVector;
}

PVOID 
IoHookInterrupt (
	ULONG Vector, 
	PVOID NewRoutine)
{
	PKINTERRUPT Interrupt;
	PVOID Handler;

	Handler = GetVector ((UCHAR)Vector);
	if (Handler == NULL)
		return NULL;

	Interrupt = CONTAINING_RECORD (Handler, _KINTERRUPT, DispatchCode);
	if (Interrupt->Type != 22)
		return NULL;

	Handler = Interrupt->ServiceRoutine;
	*(PVOID*)&Interrupt->ServiceRoutine = NewRoutine;
	return Handler;
}


ULONG
DisableWP(
	)
/**
	Disable write-protection on system pages
*/
{
	__asm
	{
		mov edx, cr0
		mov eax, edx
		and edx, 0xFFFEFFFF
		mov cr0, edx
	}
}


VOID
WriteCR0(
	ULONG NewCR0
	)
/**
	Write CR0 register value
*/
{
    __asm mov eax, [NewCR0]
	__asm mov cr0, eax
}



PVOID
SetVector(
  IN UCHAR Interrupt,
  IN PVOID Handler,
  IN BOOLEAN MakeValid
  )
/**
	Set IDT vector Interrupt to point to Handler
*/
{
    ULONG OldCr0;
    ULONG OldHandler;
	KIRQL Irql;
    
    //
    // Disable WP and interrupts
    //

	OldCr0 = DisableWP();
	Irql = KfRaiseIrql (HIGH_LEVEL);

	if (Idtr.Table == NULL)
		__asm sidt fword ptr [Idtr]

    //
    // Fill out IDT entry with the corresponding values
    //

    OldHandler = Idtr.Table[Interrupt].OffsetLow  | ( Idtr.Table[Interrupt].OffsetHigh << 16 );
    
    Idtr.Table[Interrupt].OffsetLow  = (USHORT) ( (ULONG)Handler )       & 0xFFFF;
    Idtr.Table[Interrupt].OffsetHigh = (USHORT) ( (ULONG)Handler >> 16 ) & 0xFFFF;

	if (MakeValid)
	{
		Idtr.Table[Interrupt].Present    = 1;
		Idtr.Table[Interrupt].D		     = 1;
		Idtr.Table[Interrupt].DPL        = 3;
		Idtr.Table[Interrupt].Selector   = 0x0008;
	}
   
    //
    // Restore interrupts and CR0 value
    //

    KfLowerIrql (Irql);

	WriteCR0 (OldCr0);

    return (PVOID) OldHandler;
}

