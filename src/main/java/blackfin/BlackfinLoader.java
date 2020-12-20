/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package blackfin;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.Msg;


public class BlackfinLoader extends AbstractLibrarySupportLoader {

	private class BlockHeader {
		
		public static final int BFLAG_FINAL     = 0x8000;
		public static final int BFLAG_FIRST     = 0x4000;
		public static final int BFLAG_INDIRECT  = 0x2000;
		public static final int BFLAG_IGNORE    = 0x1000;
		public static final int BFLAG_INIT      = 0x800;
		public static final int BFLAG_CALLBACK  = 0x400;
		public static final int BFLAG_QUICKBOOT = 0x200;
		public static final int BFLAG_FILL      = 0x100;
		
		public static final int BFLAG_AUX       = 0x20;
		public static final int BFLAG_SAVE      = 0x10;
		
		int flags;
		byte checksum;
		byte magic;
		long targetAddress;
		long byteCount;
		long argument;
		byte[] rawHeader;
		
		BlockHeader(BinaryReader reader) throws IOException {
			rawHeader = reader.readByteArray(reader.getPointerIndex(), 16);
			flags = reader.readNextUnsignedShort();
			checksum = reader.readNextByte();
			magic = reader.readNextByte();
			targetAddress = reader.readNextUnsignedInt();
			byteCount = reader.readNextUnsignedInt();
			argument = reader.readNextUnsignedInt();			
		}
		
		public boolean check() {
			
			if (magic != -83)
				return false;
			
			byte xorcksm = 0;
			for (int i=0; i<16; i++) {
				xorcksm = (byte) (xorcksm ^ rawHeader[i]);
			}
			
			if (xorcksm != 0)
				return false;
			
			return true;
		}
		
		public String getComment() {
			return "Flags: "+Integer.toHexString(flags)+
					"; Argument: "+Long.toHexString(argument);
		}
	}
	
	@Override
	public String getName() {
		return "Blackfin boot stream";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		BinaryReader reader = new BinaryReader(provider, true);
		
		// Check if the file is large enough to contain at least one complete block header
		if (reader.length() < 16)
			return loadSpecs;
		
		BlockHeader bh = new BlockHeader(reader);
		
		if (bh.check() == false)
			return loadSpecs;

		if ((bh.flags & BlockHeader.BFLAG_FIRST) == 0)
			return loadSpecs;
		
		// Argument of the first block contains the offset of the start of the next stream
		if (reader.length() < bh.argument+16) {
			Msg.info(BlackfinLoader.class, "BF loader: not a complete boot stream.");
		}
		
		// All tests ok, so build the loadSpecs list
		List<QueryResult> queries = QueryOpinionService.query(getName(), "1", null);
		for (QueryResult result : queries) {
			loadSpecs.add(new LoadSpec(this, 0, result));
		}
		
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		
		BinaryReader reader = new BinaryReader(provider, true);
		long nextDxeOffset = 0;
		
		int i=0;

		do {
			i++;
			long startOfBlock = reader.getPointerIndex();
			BlockHeader bh = new BlockHeader(reader);
			
			if (bh.check() == false) {
				log.appendMsg("Incorrect block header encountered.");
				break;
			}
			
			Address target = program.getAddressFactory().getDefaultAddressSpace().getAddress(bh.targetAddress);
			
			if (((bh.flags & BlockHeader.BFLAG_FIRST) != 0) && (startOfBlock != nextDxeOffset)) {
				log.appendMsg("Unexpected start of stream (BFLAG_FIRST) detected at offset "+Long.toHexString(startOfBlock));
				break;
			}
			
			if (((bh.flags & BlockHeader.BFLAG_FIRST) == 0) && (startOfBlock == nextDxeOffset)) {
				log.appendMsg("Missing BFLAG_FIRST on DXE.");
				break;
			}			
			
			if (((bh.flags & BlockHeader.BFLAG_FIRST) != 0) && (startOfBlock == nextDxeOffset)) {
				// bh.argument: start of next stream
				// bh.targetAddress: entry point
				setEntryPoint(program, target, "_entry");
				nextDxeOffset = bh.argument + reader.getPointerIndex();
			}
			
			if ((bh.flags & BlockHeader.BFLAG_INIT) != 0) {
				setEntryPoint(program, target, "_init"+Integer.toString(i));
			}
			
			if ((bh.byteCount != 0) && ((bh.flags & BlockHeader.BFLAG_FILL) == 0) && ((bh.flags & BlockHeader.BFLAG_IGNORE) == 0)) {
				
				long offset = reader.getPointerIndex();
				reader.setPointerIndex(offset+bh.byteCount);
				
				try {
					MemoryBlock mem = program.getMemory().createInitializedBlock("block"+Integer.toString(i), target, provider.getInputStream(offset), bh.byteCount, monitor, false);
					mem.setPermissions(true, true, true);
					mem.setComment(bh.getComment());
				} catch (MemoryConflictException e) {
					// retry as overlay
					try {
						MemoryBlock mem = program.getMemory().createInitializedBlock("block"+Integer.toString(i), target, provider.getInputStream(offset), bh.byteCount, monitor, true);
						mem.setPermissions(true, true, true);
						mem.setComment(bh.getComment());
					} catch (Exception f) {
						Msg.error(this, f.getMessage());
					}				
				} catch (Exception e) {
					Msg.error(this, e.getMessage());
				}
			}

			if ((bh.flags & BlockHeader.BFLAG_CALLBACK) != 0) {
				log.appendMsg("Block number "+i+" with flag 'BFLAG_CALLBACK' might contain encrypted or compressed data.");
			}
			
			if ((bh.flags & BlockHeader.BFLAG_IGNORE) != 0) {
				long offset = reader.getPointerIndex();
				reader.setPointerIndex(offset+bh.byteCount);	
			}
			
			if ((bh.flags & BlockHeader.BFLAG_FILL) != 0) {
				try {
					MemoryBlock mem = program.getMemory().createInitializedBlock("block"+Integer.toString(i), target, bh.byteCount, (byte)0, monitor, false);
					mem.setPermissions(true, true, true);
					mem.setComment(bh.getComment());
					
					if (bh.argument != 0) {
						Address pos = target;
						byte[] b = {(byte)bh.argument, (byte)(bh.argument >> 8), (byte)(bh.argument >> 16), (byte)(bh.argument >> 24)};

						do {
							mem.putBytes(pos, b);
							pos = pos.add(4);
						} while (pos.getOffset() < target.add(bh.byteCount).getOffset());
					}
					
				} catch (Exception e) {
					Msg.error(this, e.getMessage());
				}
			}
			
			if ((bh.flags & BlockHeader.BFLAG_FINAL) != 0) {
				long offset = reader.getPointerIndex();
				
				if (offset != nextDxeOffset)
					log.appendMsg("Boot stream end does not match DXE size.");
				
				if (offset < reader.length())
					log.appendMsg("Data present after end of boot stream. Beginning at offset "+offset);
				
				break;
			}
			
		} while (true);
		
	}

	private void setEntryPoint(Program program, Address entry, String label) {
		try {
			program.getSymbolTable().createLabel(entry, label, SourceType.IMPORTED);
			program.getSymbolTable().addExternalEntryPoint(entry);
		} catch (InvalidInputException e) {
			Msg.error(this, e.getMessage());
		}		
	}
	
	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
