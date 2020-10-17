package ghidra.app.util.bin.format.elf.relocation;

import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfRelocation;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.NotFoundException;

public class Blackfin_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_BLACKFIN;
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation, Address relocationAddress)
			throws MemoryAccessException, NotFoundException {

		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (!canRelocate(elf)) {
			return;
		}
		
		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();
		int type = relocation.getType();

		ElfSymbol sym = null;
		long symbolValue = 0;
		String symbolName = null;
		
		int symbolIndex = relocation.getSymbolIndex();
		if (symbolIndex != 0) {
			sym = elfRelocationContext.getSymbol(symbolIndex);
		}
		
		if (sym != null) {
			symbolValue = elfRelocationContext.getSymbolValue(sym);
			symbolName = sym.getNameAsString();
		}
		
		switch (type) {
			case Blackfin_ElfRelocationConstants.R_BFIN_FUNCDESC:
				markAsWarning(program, relocationAddress, "R_BFIN_FUNCDESC", symbolName, symbolIndex,
						"TODO, needs support ", elfRelocationContext.getLog());
				break;
				
			case Blackfin_ElfRelocationConstants.R_BFIN_FUNCDESC_VALUE:
				memory.setInt(relocationAddress, (int)symbolValue);
				break;
				
			default:
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, elfRelocationContext.getLog());
				break;
		}
		
		
	}

}
