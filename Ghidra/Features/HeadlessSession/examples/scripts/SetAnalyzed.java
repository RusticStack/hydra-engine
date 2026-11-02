//Multi-project bench setup: mark a reused, auto-analysed program as analysed (the project was produced by a
//time-capped import+analysis; this flips Ghidra's flag and changes no function, symbol or byte).
//@category Bench
import ghidra.app.script.GhidraScript;
import ghidra.program.util.GhidraProgramUtilities;

public class SetAnalyzed extends GhidraScript {
	@Override
	public void run() throws Exception {
		GhidraProgramUtilities.markProgramAnalyzed(currentProgram);
		println("set-analyzed " + currentProgram.getName() + " "
			+ GhidraProgramUtilities.isAnalyzed(currentProgram));
	}
}
