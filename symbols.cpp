/*++

	This is the part of NGdbg kernel debugger

	symbols.cpp

	This file contains routines that work with symbol tables.
	Routines can look up symbol by name or lookup symbol by address.

--*/

#include <ntifs.h>
#include "symbols.h"

//
// Symbol information
//

typedef struct SYMINFO
{
	ULONG NextEntryDelta;
	ULONG SymOffset;
	char SymName[1];
} *PSYMINFO;

//
// .sym file structure
//

typedef struct LOADED_SYMBOLS
{
	ULONG TimeDateStamp;
	SYMINFO SymInfo[1];
} *PLOADED_SYMBOLS;

//
// Loaded symbols
//

typedef struct MOD_SYM
{
	PLOADED_SYMBOLS LoadedSymbols;
	PVOID ImageBase;
	PMDL Mdl;
	ULONG_PTR iMappedSymbols;
} *PMOD_SYM;




NTSTATUS
SymGetSymbolByAddress(
	IN PVOID LoadedSymbols,
	IN PVOID ImageBase,
	IN PVOID Address,
	OUT PCHAR Symbol,
	IN OUT ULONG *SymLen
	)

/*++

Routine Description

	Lookup symbol by address

Arguments

	LoadedSymbols

		Pointer to loaded symbol information

	ImageBase

		Base address of the image to search symbols in

	Address

		Address being looked up

	Symbol

		String receiving symbol name

	SymLen
	
		On input contains length of buffer pointed by Symbol
		On output contains number of actually written characters in Symbol

Return Value

	NTSTATUS of operation

Environment

	This function can be executed at any IRQL.
	However, symbol table should be locked in the physical memory.

--*/

{
	ULONG Offset = (ULONG)Address - (ULONG)ImageBase;
	SYMINFO* pSym = (SYMINFO*) ((PUCHAR)LoadedSymbols + 4);
	NTSTATUS Status = STATUS_NOT_FOUND;

	while (pSym->NextEntryDelta)
	{
		if (pSym->SymOffset == Offset)
		{
			ULONG len = pSym->NextEntryDelta - FIELD_OFFSET (SYMINFO,SymName);
			if (*SymLen < len)
			{
				Status = STATUS_BUFFER_OVERFLOW;
				goto exit;
			}

			KdPrint(("Found sym %s\n", pSym->SymName));

			memcpy (Symbol, pSym->SymName, len);
			Symbol[len] = 0;

			*SymLen = len+1;

			Status = STATUS_SUCCESS;
			goto exit;
		}

		*(ULONG*)&pSym += pSym->NextEntryDelta;
	}

exit:
	return Status;
}

NTSTATUS
SymGetSymbolByName(
	IN PVOID LoadedSymbols,
	IN PVOID ImageBase,
	IN PCHAR Symbol,
	OUT ULONG *SymAddr
	)

/*++

Routine Description

	Lookup symbol by name

Arguments

	LoadedSymbols
	
		Pointer to loaded symbol table

	ImageBase

		Image base address

	Symbol

		Symbol name to be looked up

	SymAddr

		Receives symbol's virtual address

Return Value

	NTSTATUS of operation

Environment

	This function can be called at any IRQL
	However, symbol table should be locked in the physical memory.

--*/

{
	SYMINFO* pSym = (SYMINFO*) ((PUCHAR)LoadedSymbols + 4);
	NTSTATUS Status = STATUS_NOT_FOUND;

	while (pSym->NextEntryDelta)
	{
		if (!_strnicmp (pSym->SymName, Symbol, pSym->NextEntryDelta-FIELD_OFFSET(SYMINFO,SymName)))
		{
			*SymAddr = (ULONG)ImageBase + pSym->SymOffset;
			Status = STATUS_SUCCESS;
			goto exit;
		}

		*(ULONG*)&pSym += pSym->NextEntryDelta;
	}

exit:
	return Status;
}
