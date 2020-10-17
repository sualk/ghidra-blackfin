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

import java.math.BigInteger;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class BlackfinAnalyzer extends AbstractAnalyzer {

    private static final String REGISTER_P3 = "P3";
    private Register p3;
	
	public BlackfinAnalyzer() {

		// TODO: Name the analyzer and give it a description.

		super("Blackfin P3 PLTGOT Pointer", "Add assumption for the content of P3 register to all funtions", AnalyzerType.FUNCTION_ANALYZER);
		
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.before());
	}

	@Override
	public boolean getDefaultEnablement(Program program) {

		// TODO: Return true if analyzer should be enabled by default

		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {

		boolean canAnalyze = program.getLanguage().getProcessor().equals(Processor.findOrPossiblyCreateProcessor("Blackfin"));

		if (!canAnalyze) {
			return false;
		}
		
		p3 = program.getRegister(REGISTER_P3);
		
		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {

		// TODO: If this analyzer has custom options, register them here

		//options.registerOption("Option name goes here", false, null,
		//	"Option description goes here");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		Listing listing = program.getListing();

		Symbol symbol = SymbolUtilities.getLabelOrFunctionSymbol(program,
				"__DT_PLTGOT",
				err -> Msg.error(this, err));
		
		if (symbol == null) {
			return false;
		}
		
		RegisterValue p3Val = new RegisterValue(p3, BigInteger.valueOf(symbol.getAddress().getOffset()));
		
		for (Function function : listing.getFunctions(set, true)) {
			try {
				program.getProgramContext().setRegisterValue(function.getEntryPoint(),
						function.getEntryPoint(), p3Val);
			} catch (ContextChangeException e) {
				throw new AssertException("unexpected", e);
			}
		}
		
		return true;
	}
}
