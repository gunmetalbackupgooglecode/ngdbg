/*++

	This is the part of NGdbg kernel debugger

	worker.cpp

	This file contains initialization/clean routines for graphics debugger part,
	 main WR_ENTER_DEBUGGER routine and another routines, which
	 control user interface of the debugger.

--*/

#define NT_BUILD_ENVIRONMENT
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <winddi.h>

#define KERNEL_DEBUGGER_VERSION "0.1"

VOID
W32PrepareCall(
/*++

Routine Description

	This function prepares thread for calling WIN32

Arguments

	None

Return Value

	None

--*/
	);

VOID
W32ReleaseCall(
/*++

Routine Description

	This function unprepares thread from calling WIN32

Arguments

	None

Return Value

	None

--*/
	);

#include "gui.h"	
#include "symbols.h"

//
// Declarations
//

VOID _cdecl EngPrint (char*, ...);
#define KdPrint(X) EngPrint X

extern SURFOBJ *pPrimarySurf;
extern PVOID pDrvCopyBits;

BOOL (APIENTRY *xxxDrvCopyBits)(
   OUT SURFOBJ *psoDst,
   IN SURFOBJ *psoSrc,
   IN CLIPOBJ *pco,
   IN XLATEOBJ *pxlo,
   IN RECTL *prclDst,
   IN POINTL *pptlSrc
   );

//
// We cannot include ntddk.h, because
// it conflicts with windows.h, which is necessary
//  for win32k routines :(
//

extern "C"
{
UCHAR __fastcall KfRaiseIrql (UCHAR Irql);
VOID __fastcall KfLowerIrql (UCHAR Irql);
}

//
// Debugger global vars
//

// Drawing surface, it's handle, it's MDL
SURFOBJ* pGDISurf;
HBITMAP hBitmap;
PMDL SurfMdl;
//PVOID pBitmap;
//ULONG_PTR idMappedBitmap;

// Backup surface where the part of the screen being 
//  overwritten is saved
HBITMAP hBackupBitmap;
SURFOBJ* pBackupSurface;
PMDL BackupMdl;

// We don't need it now...
//HBITMAP hFillBitmap;
//SURFOBJ *pFillSurface;
//PMDL FillMdl;

//
// Parameters of main debugger 'window'
//

ULONG Width = 900;			// width
ULONG Height = 600;			// height
ULONG StartX = 100;			// x coordinate
ULONG StartY = 100;			// y coordinate
ULONG SpareX = 10;			// reserved vertical space
ULONG SpareY = 10;			// reserved horizontal space


//
// In the previous version i tried to use
// XLATEOBJ to translate 24bpp images to 32bpp.
// But win32k uses extended undocumented structure EXLATEOBJ.
// So, I have to make all bitmaps 32bpp to avoid any runtime 
// translation between pictures when we call DrvCopyBits
//

//XLATEOBJ XlateObj;

// We don't need it now..
/*
#pragma pack (push,2)
typedef struct tagBITMAPFILEHEADER {
        USHORT    bfType;
        ULONG   bfSize;
        USHORT    bfReserved1;
        USHORT    bfReserved2;
        ULONG   bfOffBits;
} BITMAPFILEHEADER, *PBITMAPFILEHEADER;
#pragma pack (pop)
*/

//
// Declare vars as 'extern "C"'.
// This will make them accessible from Disasm.c
//

extern "C" extern PVOID pNtBase;
//extern "C" extern PVOID pNtSymbols;
//extern "C" extern PMOD_SYM pNtSymbols;

//
// Base load address of nt kernel and
//  pointer to loaded symbols for it
//

PVOID pNtBase;
//PVOID pNtSymbols;		// pointer to mapped sym file
//ULONG_PTR iNtSymbols;	// ID of mapped sym file, it will be passed in EngUnmapFile
//PMDL SymMdl;			// MDL for symbols
//PMOD_SYM pNtSymbols;

//
// Some declarations..
//

PVOID FindImage (PWSTR);

#undef RegOpenKey
#undef RegQueryValue
HANDLE RegOpenKey (PWSTR KeyName, ACCESS_MASK DesiredAccess);
BOOLEAN RegQueryValue (HANDLE hKey, PWSTR ValueName, ULONG Type, PVOID Buffer, ULONG *Len);

extern "C"
BOOLEAN
FindBaseAndSize(
	IN PVOID SomePtr,
	OUT PVOID *BaseAddress OPTIONAL, 
	OUT ULONG *ImageSize OPTIONAL
	);

extern "C"
NTSTATUS 
ZwClose (
	HANDLE
	);

PVOID GetKernelAddress (PWSTR);

//
// Single entry in symbol file
//

typedef struct _SYMINFO
{
	ULONG NextEntryDelta;
	ULONG SymOffset;
	char SymName[1];
} SYMINFO, *PSYMINFO;


VOID 
Worker(
	)

/*++

Routine Description

	Initialization routine for this part of the debugger.
	This function is called from DriverEntry in the context
	 of CSRSS process, so we can use Eng*** routines exported
	 by the win32k.sys

Arguments

	None

Return Value

	None, this function should always succeed initizaliation.

Environment

	This function is called at PASSIVE_LEVEL in the context of CSRSS process.

--*/

{
	SURFOBJ *Surf = pPrimarySurf;
	*(PVOID*)&xxxDrvCopyBits = pDrvCopyBits;

	KdPrint(("PrimarySurf=%X ..\n", Surf));
	KdPrint(("DrvCopyBits=%X ..\n", xxxDrvCopyBits));

	KdPrint(("Surf->iBitmapFormat = %X\n", Surf->iBitmapFormat));
	KdPrint(("Size X %d Y %d\n", Surf->sizlBitmap.cx, Surf->sizlBitmap.cy));

	//
	// Initialize
	//

	/*
	pBitmap = EngMapFile (L"\\??\\C:\\sample.bmp", 0, &idMappedBitmap);

	KdPrint(("EngLoadModule = %X, idMappedBitmap = %X\n", pBitmap, idMappedBitmap));
	if (!pBitmap)
		return;

	PBITMAPFILEHEADER hdr = (PBITMAPFILEHEADER) pBitmap;
	PVOID pvBits = (PUCHAR)pBitmap + hdr->bfOffBits;
	
	KdPrint(("Loaded bitmap\nHeader:\n"
		"bfType = %c%c\n"
		"bfSize = %d\n"
		"bfOffBits = %d\n"
		"Pointer pvBits = %X\n"
		"First pixel is %X\n"
		,
		hdr->bfType >> 8, hdr->bfType & 0xFF,
		hdr->bfSize,
		hdr->bfOffBits,
		pvBits,
		*(ULONG*)pvBits
		));
	*/

	//
	// Initialize main drawing surface
	//


	// Create bitmap for drawing
	SIZEL Size;

	Size.cx = Width;
	Size.cy = Height;

	hBitmap = EngCreateBitmap (
		Size, 
		Size.cx * 4, 
		BMF_32BPP,
		0,
		NULL //pvBits 
		);

	KdPrint(("EngCreateBitmap (image) = %X\n", hBitmap));
	if (!hBitmap)
		return;

	//
	// Initialize backup surface
	//

	hBackupBitmap = EngCreateBitmap(
		Size, 
		Size.cx * 4,
		Surf->iBitmapFormat,
		0,
		NULL
		);

	KdPrint(("EngCreateBitmap (backup) = %X\n", hBitmap));
	if (!hBackupBitmap)
		return;

	/*
	hFillBitmap = EngCreateBitmap(
		Size, 
		Size.cx * 4,
		Surf->iBitmapFormat,
		0,
		NULL
		);

	KdPrint(("EngCreateBitmap (fill) = %X\n", hFillBitmap));
	if (!hFillBitmap)
		return;
	*/

	//
	// Lock main drawing surface
	//

	// Lock bitmap to SURFOBJ
	pGDISurf = EngLockSurface ((HSURF)hBitmap);
	KdPrint(("EngLockSurface (image) = %X\n", pGDISurf));

	//
	// Lock backup surface
	//

	pBackupSurface = EngLockSurface ((HSURF)hBackupBitmap);
	KdPrint(("EngLockSurface (backup) = %X\n", pBackupSurface));

	/*
	pFillSurface = EngLockSurface ((HSURF)hFillBitmap);
	KdPrint(("EngLockSurface (fill) = %X\n", pFillSurface));
	*/

	//
	// Erase backup surface
	//

	RECTL Rect;
	Rect.left = 0;
	Rect.top = 0;
	Rect.right = Width;
	Rect.bottom = Height;

	BOOL s = EngEraseSurface (pBackupSurface, &Rect, RGB(0xFF,0xFF,0xFF));
	KdPrint(("EngEraseSurface (backup) %d\n", s));

	//
	// Erase drawing surface
	//

	s = EngEraseSurface (pGDISurf, &Rect, RGB(0xFF,0xFF,0xFF));
	KdPrint(("EngEraseSurface (main) %d\n", s));

	//
	// Lock all surfaces in memory
	//

	// lock pages
	SurfMdl = LockMem (pGDISurf->pvBits, pGDISurf->cjBits);
	BackupMdl = LockMem (pBackupSurface->pvBits, pBackupSurface->cjBits);
//	FillMdl = LockMem (pFillSurface->pvBits, pFillSurface->cjBits);

	//
	// Load active font
	//

	NTSTATUS Status = GuiLoadActiveFont ();
	if (!NT_SUCCESS(Status))
		return;

	GuiTextOut ("NGdbg kernel debugger v" KERNEL_DEBUGGER_VERSION "\n");

	//
	// Find NT base
	//

	if(!FindBaseAndSize (GetKernelAddress(L"DbgPrint"), &pNtBase, NULL))
	{
		KdPrint(("Could not get nt base\n"));
		return;
	}

	//
	// Load NT symbols
	//

	/*
	PIMAGE_DOS_HEADER NtDos = (PIMAGE_DOS_HEADER) pNtBase;
	PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)NtDos + NtDos->e_lfanew);

	HANDLE hKey = RegOpenKey (L"\\Registry\\Machine\\Software\\NGdbg\\Symbols", KEY_QUERY_VALUE);
	if (hKey == NULL)
	{
		KdPrint(("Could not open symbols key\n"));
	}
	else
	{
		WCHAR SymbolPath[512];
		ULONG Len = sizeof(SymbolPath)-8;
		wcscpy (SymbolPath, L"\\??\\");

		KdPrint (("Opened 'symbols' key, hk=%X\n", hKey));

		if(!RegQueryValue (hKey, L"nt", REG_SZ, SymbolPath+4, &Len))
		{
			KdPrint(("Could not query value for nt symbols\n"));
		}
		else
		{
			KdPrint(("nt symbols: %S\n", SymbolPath));

			pNtSymbols = EngMapFile (SymbolPath, 0, &iNtSymbols);
			if (!pNtSymbols)
			{
				KdPrint(("Could not load nt symbols\n"));
			}
			else
			{
				KdPrint(("nt symbols mapped at %X\n", pNtSymbols));

				// are symbols correct?

				if( *(ULONG*)pNtSymbols == NtHeaders->FileHeader.TimeDateStamp )
				{
					KdPrint(("Symbols are correct\n"));

					// Lock symbols in memory
					ULONG Size = 4;

					PSYMINFO info = (PSYMINFO) ((PUCHAR)pNtSymbols + 4);

					while (info->NextEntryDelta)
					{
						Size += info->NextEntryDelta;
						*(ULONG*)&info += info->NextEntryDelta;
					}

					SymMdl = LockMem (pNtSymbols, Size);

					KdPrint(("Symbols locked\n"));
				}
				else
				{
					KdPrint(("Incorrect symbols! nt timestamp %X, sym timestamp %X\n",
						pNtSymbols,
						NtHeaders->FileHeader.TimeDateStamp
						));

					EngUnmapFile (iNtSymbols);
					pNtSymbols = NULL;
				}
			}
		}

		ZwClose (hKey);
	}
	*/

	SymInitialize();

	Status = SymLoadSymbolFile (L"nt", pNtBase);
	KdPrint(("nt symbols loaded with status %X\n", Status));

	Status = SymLoadSymbolFile (L"hal.dll", NULL);
	KdPrint(("hal.dll symbols loaded with status %X\n", Status));

	//
	// Initialization completed.
	//
}

typedef struct _EPROCESS EPROCESS, *PEPROCESS;

extern PEPROCESS CsrProcess;
extern ULONG Lock;

ULONG PsDirectoryTableBase = 0x18;

VOID 
EngFastAttachProcess (
	PEPROCESS Process, 
	PULONG Pdbr
	)

/*++

Routine Description

	Fast routine to attach to the specified process.
	Because KeStackAttachProcess makes many other critical things
	 that we cannot allow at raised IRQL we have to simply
	 swap CR3 (PDBR) register.
	This function SHOULD be called at raised IRQL (not less that DISPATCH_LEVEL)
	to avoid context switches from code with changed CR3.
	Each call to this routine should have corresponding EngFastDetachProcess call

Arguments

	Process

		EPROCESS to attach

	Pdbr

		Place where current CR3 value should be saved.
		This value should be passed to EngFastDetachProcess later

Return Value

	None

Environment

	This function MUST be called at raised IRQL (not less DISPATCH_LEVEL).
	
	For internal use by this module ONLY.

--*/

{
	ULONG NewCR3 = *(ULONG*)(&((UCHAR*)Process)[PsDirectoryTableBase]);
	__asm
	{
		mov eax, cr3
		mov ecx, [Pdbr]
		mov [ecx], eax
		mov eax, [NewCR3]
		mov cr3, eax
	}
}

VOID 
EngFastDetachProcess (
	ULONG Pdbr
	)

/*++

Routine Description

	This routine performs fast detach from the process, previously 
	attached by EngFastAttachProcess.
	It simply restores CR3 value

Arguments

	Pdbr

		Old CR3 value to restore previously obtained by EngFastAttachProcess

Return Value

	None

Environment

	This function MUST be called at raised IRQL (not less DISPATCH_LEVEL).
	
	For internal use by this module ONLY.

--*/

{
	__asm
	{
		mov eax, [Pdbr]
		mov cr3, eax
	}
}

VOID 
Cleanup(
	)

/*++

Routine Description

	This routine performs clean up for all resources
	 allocated by Worker() for this module.
	It is called from DriverUnload routine.

Arguments

	None

Return Value

	None

Environment

	This function is called at PASSIVE_LEVEL.
	DriverUnload attaches to CSRSS process before call Cleanup()

--*/

{
	KdPrint(( __FUNCTION__ " : unloading symbol tables\n"));
	SymFreeSymbolTables ();

	KdPrint(( __FUNCTION__ " : unlocking MDLs for surfaces\n"));
	UnlockMem (SurfMdl);
	UnlockMem (BackupMdl);
//	UnlockMem (FillMdl);

	KdPrint(( __FUNCTION__ " : unlocking surfaces\n"));
//	EngUnlockSurface (pFillSurface);
	EngUnlockSurface (pBackupSurface);
	EngUnlockSurface (pGDISurf);

	KdPrint(( __FUNCTION__ " : deleting surfaces\n"));
//	EngDeleteSurface ((HSURF)hFillBitmap);
	EngDeleteSurface ((HSURF)hBackupBitmap);
	EngDeleteSurface ((HSURF)hBitmap);

//	EngUnmapFile (idMappedBitmap);

	KdPrint(( __FUNCTION__ " : unloading font\n"));
	GuiUnloadFont ();

	KdPrint(( __FUNCTION__ " : completed\n"));
}

UCHAR KbdGetKeyPolled();

BOOLEAN
DisplayBuffer(
	)

/*++

Routine Description

	This function flushes drawing surface by copying it to the main 
	 screen surface.
    It uses DrvCopyBits of display driver to perform this copying.

Arguments

	None

Return Value

	BOOLEAN returned by DrvCopyBits

Environment

	This routine is usually called at raised IRQL

--*/

{
	RECTL Rect;
	POINTL Point;

	Point.x = 0;
	Point.y = 0;
	Rect.left = StartX;
	Rect.top = StartY;
	Rect.right =  StartX + Width;
	Rect.bottom = StartY + Height;

	return xxxDrvCopyBits(
			pPrimarySurf, 
			pGDISurf, 
			NULL,
			NULL, //&XlateObj,		// no translation now
			&Rect,
			&Point
			);
}

extern "C" extern void _cdecl _snprintf (char*, int, const char*, ...);
extern "C" VOID KeStallExecutionProcessor (ULONG);

UCHAR KeybdScanCodeToAsciiCode (UCHAR ScanCode);

VOID KeybProcessUserInputLocked (UCHAR ScanCode);

extern BOOLEAN WindowsNum;
extern BOOLEAN WindowsCaps;
extern BOOLEAN WindowsScroll;

extern BOOLEAN DbgNum;
extern BOOLEAN DbgCaps;

VOID
KbdSetLeds(
	BOOLEAN Num,
	BOOLEAN Caps,
	BOOLEAN Scroll
	);

LARGE_INTEGER PrevBlinkTickCount;


VOID 
PollIdle (
	)

/*++

Routine Description

	This routine is called when WR_ENTER_DEBUGGER have nothing
	 to do at raised IRQL when debugger is active.
    This routine can blink cursor on the screen and do another
	 things, which should be done periodically.

Arguments

	None

Return Value

	None

Environment

	This routine is called at raised IRQL from WR_ENTER_DEBUGGER

--*/

{
	// Now we have nothing to do
}


typedef 
VOID
(NTAPI
 *PDBG_CALLBACK)(
	BOOLEAN In,
	PVOID Argument,
	BOOLEAN DispatchException
	);

VOID
ProcessCommand(
	CHAR* Command
	);

BOOLEAN ExceptionShouldBeDispatched = FALSE;
BOOLEAN StopProcessingCommands = FALSE;

extern BOOLEAN DbgEnteredDebugger;

VOID DisasmAtAddress (PVOID Address, ULONG nCommands);


VOID 
WR_ENTER_DEBUGGER(
	BOOLEAN UserInitiated,
	PDBG_CALLBACK Callback,
	PVOID Argument
	)

/*++

Routine Description

	This function enters kernel debugger and starts to process
	 commands from keyboard.
	Debugger can be entered by Ctrl-Alt-Shift-F12 or when
	some exception (or another fault) occurrs in the system.
	This function is always called at raised IRQL, usually
	 DIRQL for keyboard (if debugger is initiated manually from keyboard)
	 or HIGH_LEVEL (from exception or bugcheck handler)

Arguments

	UserInitiated
	
		Specifies whenever debugger is initiated by user or not.

	Callback
	
		Callback which should be called before entering debugger
		 and immediately after exit from the debugger.
		dbgeng module uses this callback to handle exceptions

	Argument

		Argument to be passed to callback routine

Return Value

	None

Environment

	This function is always called (and MUST be called) at raied IRQL,
	 not less than keyboard's DIRQL.

-- */

{
	BOOL s;
	ULONG State;
//	KAPC_STATE State;

	EngFastAttachProcess (CsrProcess, &State);
//	KeStackAttachProcess (CsrProcess, &State);

	KdPrint(("WR_ENTER_DEBUGGER enter\n"));

	DbgEnteredDebugger = TRUE;

	KdPrint(("Surf->pvBits = %X\n", pPrimarySurf->pvBits));
	KdPrint(("pGDISurf->pvBits = %X\n", pGDISurf->pvBits));

	KdPrint(("Backing up..\n"));

	RECTL Rect;
	POINTL Point = {StartX, StartY};

	Rect.left = 0;
	Rect.top = 0;
	Rect.right =  Width;
	Rect.bottom = Height;

	s = xxxDrvCopyBits (
		pBackupSurface,
		pPrimarySurf,
		NULL,
		NULL,
		&Rect,
		&Point
		);

	KdPrint(("Backed up with status %X\n", s));

	//
	// Settings keyboard leds.
	//

	KbdSetLeds (DbgNum, DbgCaps, 1);
	
	//
	// We are within kernel debugger.
	// Callback the specified routine
	//

	if (!UserInitiated)
		Callback (TRUE, Argument, FALSE);
	else
		GuiTextOut ("User-break by Ctrl-Alt-Shift-F12\n");

	GuiTextOut ("> ");

	DisplayBuffer();

	//
	// Directly wait on keyboard at VERY HIGH IRQL !!!
	// IRQL not is at DIRQL level for keyboard IRQ, but
	// we cannot setup a DPC or something else to wait
	// when IRQL will be lowered by system, alse we cannot
	// lower IRQL manually because system will become 
	// unstable. So we have to loop until the key is pressed.
	//

	StopProcessingCommands = FALSE;
	ExceptionShouldBeDispatched = FALSE;

	KdPrint(("Waiting for user input\n"));

	//
	// Poll until escape is pressed.
	//

	UCHAR Byte;

	char command[200];
	int iPos = 0;
	command[0] = 0;

	do
	{
		PollIdle ();

		Byte = KbdGetKeyPolled();

		if (Byte == 0)
			continue;

		if (Byte == 1)
			break;

		KeybProcessUserInputLocked (Byte);

		// get ascii code
		UCHAR AsciiCode[2];
		AsciiCode[0] = KeybdScanCodeToAsciiCode (Byte);

		if (Byte == 0x0E)
		{	
			if (iPos != 0)
			{
				iPos --;
				GuiTextOut ("\b");
				DisplayBuffer();
			}
			// don't save this char
			AsciiCode[0] = 0;
		}

		if (AsciiCode[0] == 10)
		{
			command[iPos] = 0;
			AsciiCode[1] = 0;
			GuiTextOut ((PCHAR)AsciiCode);

			//KdPrint(("Endl, got string '%s'\n", command));
			ProcessCommand (command);

			if (StopProcessingCommands)
				break;

			GuiTextOut("> ");
			DisplayBuffer();

			iPos = 0;
			AsciiCode[0] = 0;
		}

		if (AsciiCode[0])
		{
			AsciiCode[1] = 0;
			GuiTextOut ((PCHAR)AsciiCode);
			DisplayBuffer();

			command[iPos++] = AsciiCode[0];
		}
	}
	while (TRUE);


	KdPrint(("Leaving debugger (BYTE %X StopProcessingCommands %X)\n", Byte, StopProcessingCommands));

	//
	// We are going to return from debugger
	//

	if (!UserInitiated)
	{
		Callback (FALSE, Argument, ExceptionShouldBeDispatched);
	}

	//
	// Resetting kbd leds
	//
	// Win LEDs vulues will be set by DPC routine
	//

//	KbdSetLeds (WindowsNum, WindowsCaps, WindowsScroll);

	//
	// Restore screen
	//

	Point.x = 0;
	Point.y = 0;
	Rect.left = StartX;
	Rect.top = StartY;
	Rect.right =  StartX + Width;
	Rect.bottom = StartX + Height;

	s = xxxDrvCopyBits(
			pPrimarySurf, 
			pBackupSurface, 
			NULL,
			NULL,
			&Rect,
			&Point
			);

	KdPrint(("WR_ENTER_DEBUGGER exit\n"));

	DbgEnteredDebugger = FALSE;

	EngFastDetachProcess (State);
//	KeUnstackDetachProcess (&State);
}

