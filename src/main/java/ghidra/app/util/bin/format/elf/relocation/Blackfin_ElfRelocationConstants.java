package ghidra.app.util.bin.format.elf.relocation;

public class Blackfin_ElfRelocationConstants {
	
	public static final int R_BFIN_UNUSED0 = 0x00; // Not defined/used
	public static final int R_BFIN_PCREL5M2 = 0x01;
	public static final int R_BFIN_UNUSED1 = 0x02; // Not defined/used
	public static final int R_BFIN_PCREL10 = 0x03;
	public static final int R_BFIN_PCREL12_JUMP = 0x04;
	public static final int R_BFIN_RIMM16 = 0x05;
	public static final int R_BFIN_LUIMM16 = 0x06;
	public static final int R_BFIN_HUIMM16 = 0x07;
	public static final int R_BFIN_PCREL12_JUMP_S = 0x08;
	public static final int R_BFIN_PCREL24_JUMP_X = 0x09;
	public static final int R_BFIN_PCREL24 = 0x0a;
	public static final int R_BFIN_UNUSEDB = 0x0b; // Not defined/used
	public static final int R_BFIN_UNUSEDC = 0x0c; // Not defined/used
	public static final int R_BFIN_PCREL24_JUMP_L = 0x0d;
	public static final int R_BFIN_PCREL24_CALL_X = 0x0e;
	public static final int R_BFIN_VAR_EQ_SYMB = 0x0f;
	public static final int R_BFIN_BYTE_DATA = 0x10;
	public static final int R_BFIN_BYTE2_DATA = 0x11;
	public static final int R_BFIN_BYTE4_DATA = 0x12;
	public static final int R_BFIN_PCREL11 = 0x13;
	public static final int R_BFIN_GOT17M4 = 0x14;
	public static final int R_BFIN_GOTHI = 0x15;
	public static final int R_BFIN_GOTLO = 0x16;
	public static final int R_BFIN_FUNCDESC = 0x17;
	public static final int R_BFIN_FUNCDESC_GOT17M4 = 0x18;
	public static final int R_BFIN_FUNCDESC_GOTHI = 0x19;
	public static final int R_BFIN_FUNCDESC_GOTLO = 0x1a;
	public static final int R_BFIN_FUNCDESC_VALUE = 0x1b;
	public static final int R_BFIN_FUNCDESC_GOTOFF17M4 = 0x1c;
	public static final int R_BFIN_FUNCDESC_GOTOFFHI = 0x1d;
	public static final int R_BFIN_FUNCDESC_GOTOFFLO = 0x1e;
	public static final int R_BFIN_GOTOFF17M4 = 0x1f;
	public static final int R_BFIN_GOTOFFHI = 0x20;
	public static final int R_BFIN_GOTOFFLO = 0x21;

	public static final int R_BFIN_PUSH = 0xE0;
	public static final int R_BFIN_CONST = 0xE1;
	public static final int R_BFIN_ADD = 0xE2;
	public static final int R_BFIN_SUB = 0xE3;
	public static final int R_BFIN_MULT = 0xE4;
	public static final int R_BFIN_DIV = 0xE5;
	public static final int R_BFIN_MOD = 0xE6;
	public static final int R_BFIN_LSHIFT = 0xE7;
	public static final int R_BFIN_RSHIFT = 0xE8;
	public static final int R_BFIN_AND = 0xE9;
	public static final int R_BFIN_OR = 0xEA;
	public static final int R_BFIN_XOR = 0xEB;
	public static final int R_BFIN_LAND = 0xEC;
	public static final int R_BFIN_LOR = 0xED;
	public static final int R_BFIN_LEN = 0xEE;
	public static final int R_BFIN_NEG = 0xEF;
	public static final int R_BFIN_COMP = 0xF0;
	public static final int R_BFIN_PAGE = 0xF1;
	public static final int R_BFIN_HWPAGE = 0xF2;
	public static final int R_BFIN_ADDR = 0xF3;
	
	public static final int R_BFIN_PLTPC = 0x40;         /* PLT gnu only relocation */
	public static final int R_BFIN_GOT = 0x41;           /* GOT gnu only relocation */
	public static final int R_BFIN_GNU_VTINHERIT = 0x42; /* C++ = gnu only */
	public static final int R_BFIN_GNU_VTENTRY = 0x43;   /* C++ = gnu only */
	
}
