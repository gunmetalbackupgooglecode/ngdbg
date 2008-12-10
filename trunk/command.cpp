/*++

	This is the part of NGdbg kernel debugger

	command.cpp

	This file contains routines to process commands typed by user.

--*/

#include <ntifs.h>
#include "dbgeng.h"
#include <stdlib.h>
#include <stdio.h>
#include "gui.h"
typedef int BOOL;
extern "C"
{
#include "disasm.h"
}
#include "symbols.h"

//
// Declarations
//

int explode (char *input, char* symset, char** output, int maxarray);

UCHAR hexchr (char hx);
ULONG hextol (char *hex);
BOOLEAN isstrhex (char *str);

extern BOOLEAN ExceptionShouldBeDispatched;
extern BOOLEAN StopProcessingCommands;

extern "C" extern PVOID pNtBase;
extern "C" extern PVOID pNtSymbols;

struct _KPRCB
{
	USHORT MinorVersion;
	USHORT MajorVersion;
	PKTHREAD CurrentThread;
};

BOOLEAN DisplayBuffer();

PVOID LastUnassemble;
PVOID LastDump;


PVOID
DisasmAtAddress (
	PVOID Address, 
	ULONG nCommands
	)

/*++
	
Routine Description

	This routine disassembles code at the specified address 
	 and prints listing to the main debugger output

 Arguments

	Address

		Address of code to be disassembled

	nCommands

		Number of commands to disassemble

Return Value

	Function returns virtual address where it has been stopped.

Environment

	This function can be called at any IRQL if code being disassembled
	 is locked in physical memory

--*/

{
	if (MmIsAddressValid(Address))
	{
		PUCHAR ptr = (PUCHAR) Address;
		TMnemonicOptions opts = {0};
		char buff[512];

		opts.RealtiveOffsets = FALSE;
		opts.AddHexDump = TRUE;
		opts.AlternativeAddres = 0;
		opts.AddAddresPart = FALSE;
		opts.MnemonicAlign = 23;
		
		for (ULONG line=0; line<nCommands; line++)
		{
			TDisCommand dis = {0};
			TInstruction instr = {0};

			char Symbol[32];
			ULONG symlen = sizeof(Symbol);

			if (SymGetSymbolByAddress (pNtSymbols, pNtBase, ptr, Symbol, &symlen) == 0)
			{
				GuiPrintf("%s:\n", Symbol);
			}

			ULONG len = InstrDecode (ptr, &instr, FALSE);
			if(!InstrDasm (&instr, &dis, FALSE))
			{
				GuiPrintf("%08X : invalid opcode\n", ptr);
			}
			else
			{
				MakeMnemonic (buff, &dis, &opts);
				GuiPrintf("%08X : %s\n", ptr, buff);
			}

			ptr += len;
		}

		return ptr;
	}
	else
	{
		GuiPrintf ("%08X : ???\n", Address);
		return NULL;
	}
}

BOOLEAN 
Sym (
	char *a, 
	PVOID *pSym
	)

/*++

Routine Description

	This routine lookups string to be used in commands like 'u' or 'dd'.
	It can be symbol, hexadecimal value or CPU register (not suppored yet).

Arguments

	a

		String, which value should be calculated.

	pSym

		Place where value should be stored.

Return Value

	TRUE if expression was evaluated successfully, FALSE otherwise

Environment

	This function can be called at any IRQL.
	Debugger environment should contain valid trap frame if specified string
	 is CPU register.
	Symbol tables should be locked in physical memory if specified string
	 is a symbol name.

--*/

{
	NTSTATUS Status;

	if (pNtSymbols)
	{
		Status = SymGetSymbolByName (pNtSymbols, pNtBase, a, (ULONG*)pSym);
		if (NT_SUCCESS(Status))
			return TRUE;
	}

	if (isstrhex(a))
	{
		*pSym = (PVOID) hextol (a);
		return TRUE;
	}

	return FALSE;
}


VOID
ProcessCommand(
	CHAR* Command
	)

/*++

Routine Description

	Process user command.
	This function is called from WR_ENTER_DEBUGGER when
	 it receives the whole string from 8042 PS/2 minidriver

Arguments
	
	Command

		Command received from keyboard.

Return Value

	None

--*/
	
{
	char *output[20];
	int nItems = explode (Command, " \r\n", output, 20);

	char *cmd = output[0];

	_strlwr (cmd);

	if (!_stricmp (cmd, "i3hereuser"))
	{
		if (nItems < 2)
		{
			GuiTextOut ("this command requires an argument\n");
			return;
		}
		ULONG Value = atoi (output[1]);

		I3HereUser = !!(Value);
	}
	else if (!_stricmp (cmd, "i3herekernel"))
	{
		if (nItems < 2)
		{
			GuiTextOut ("this command requires an argument\n");
			return;
		}
		ULONG Value = atoi (output[1]);

		I3HereKernel = !!(Value);
	}
	else if (!_stricmp (cmd, "de"))
	{
		GuiTextOut ("Dispatching exception\n");
		ExceptionShouldBeDispatched = TRUE;
		StopProcessingCommands = TRUE;
	}
	else if (!_stricmp (cmd, "g"))
	{
		StopProcessingCommands = TRUE;
	}
	else if (!_stricmp (cmd, "dd"))
	{
		PVOID Address;

		if (nItems < 2)
		{
			Address = LastDump;
		}
		else
		{
			if (!Sym(output[1], &Address))
			{
				GuiPrintf("could not find symbol %s\n", output[1]);
				return;
			}
		}
		
		GuiPrintf ("dumping memory at %08X\n", Address);

		if (MmIsAddressValid(Address))
		{
			PULONG ptr = (PULONG) Address;

			for (ULONG line=0; line<5; line++)
			{
				char Symbol[32];
				ULONG symlen = sizeof(Symbol);

				if (SymGetSymbolByAddress (pNtSymbols, pNtBase, ptr, Symbol, &symlen) == 0)
				{
					GuiPrintf("%s:\n%08X : %08X %08X %08X %08X\n",
						Symbol, ptr, ptr[0], ptr[1], ptr[2], ptr[3]);
				}
				else
				{
					GuiPrintf("%08X : %08X %08X %08X %08X\n",
						ptr, ptr[0], ptr[1], ptr[2], ptr[3]);
				}

				ptr += 4;
			}
		
			LastDump = (PVOID)ptr;
		}
		else
		{
			GuiPrintf ("%08X : ???\n", Address);
		}
		GuiTextOut ("End of dump\n");
	}
	else if (!_stricmp(cmd, "u"))
	{
		PVOID Address;

		if (nItems < 2)
		{
			Address = LastUnassemble;
		}
		else
		{
			if (!Sym(output[1], &Address))
			{
				GuiPrintf("could not find symbol %s\n", output[1]);
			}
		}
		GuiPrintf ("disassembly dump at %08X\n", Address);

		PVOID p = DisasmAtAddress (Address, 10);
		if (p)
			LastUnassemble = p;

		GuiTextOut ("End of dump\n");
	}
	else if (!_stricmp(cmd, "prcb"))
	{
		PKPCR Pcr = (PKPCR) KIP0PCRADDRESS;

		GuiPrintf(
			"Processor control region %08X:\n"
			" NT_TIB\n"
			"  ExceptionList   %08X\n"
			"  StackBase       %08X\n"
			"  StackLimit      %08X\n"
			"  SumSystemTib    %08X\n"
			"  FiberData/Ver   %08X\n"
			"  ArbUserPointer  %08X\n"
			"  Teb             %08X\n"
			" SelfPcr         %08X\n"
			" Prcb            %08X\n"
			" Irql            %02X\n"
			" IRR             %08X\n"
			" IrrActive       %08X\n"
			" IDR             %08X\n"
			" KdVersionBlock  %08X\n"
			" IDT             %08X\n"
			" GDT             %08X\n"
			" TSS             %08X\n"
			" MajorVersion    %04X\n"
			" MinorVersion    %04X\n"
			" Affinity        %08X\n"
			" DebugActive     %02X\n"
			" Number          %02X\n"
			"Processor control block at %08X:\n"
			"  CurrentThread    %08X\n"
			,
			Pcr, Pcr->NtTib.ExceptionList, Pcr->NtTib.StackBase,
			Pcr->NtTib.StackLimit, Pcr->NtTib.SubSystemTib,
			Pcr->NtTib.FiberData, Pcr->NtTib.ArbitraryUserPointer,
			Pcr->NtTib.Self, Pcr->SelfPcr, Pcr->Prcb, Pcr->Irql,
			Pcr->IRR, Pcr->IrrActive, Pcr->IDR, Pcr->KdVersionBlock,
			Pcr->IDT, Pcr->GDT, Pcr->TSS, Pcr->MajorVersion,
			Pcr->MinorVersion, Pcr->SetMember, Pcr->DebugActive,
			Pcr->Number, Pcr->Prcb, Pcr->Prcb->CurrentThread
			);
	}
	else if (!_stricmp(cmd, "help"))
	{
		GuiTextOut (
			"NGdbg debugger command help\n"
			"Available commands:\n"
			" u ADDRESS       display disassemble dump at the specified address\n"
			" dd ADDRESS      display raw ULONG dump at the specified address\n"
			" db ADDRESS      display raw UCHAR dump at the specified address\n"
			" prcb            display KPRCB dump <NOT IMPLEMENTED>\n"
			" g               go (if within exception, does not handle it)\n"
			" de              dipatch the exception\n"
			" i3hereuser B    sets action for usermode INT3's (B = 0 or 1)\n"
			" i3herekernel B  sets action for kernelmode INT3's (B = 0 or 1)\n"
			);
	}
	else
	{
		GuiPrintf ("Unknown command: %s\n", cmd);
	}
}
