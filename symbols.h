#ifndef _SYMBOLS_H_
#define _SYMBOLS_H_

extern "C"
{

NTSTATUS
SymGetSymbolByAddress(
	IN PVOID LoadedSymbols,
	IN PVOID ImageBase,
	IN PVOID Address,
	OUT PCHAR Symbol,
	OUT ULONG *SymLen
	);


NTSTATUS
SymGetSymbolByName(
	IN PVOID LoadedSymbols,
	IN PVOID ImageBase,
	IN PCHAR Symbol,
	OUT ULONG *SymAddr
	);	

}

#endif
