//Multi-project bench: the function name, plate comment and prototype at each argument address (read only).
//@category Bench
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class CheckEdit extends GhidraScript {
	@Override
	public void run() throws Exception {
		for (String a : getScriptArgs()) {
			Address addr = toAddr(a);
			Function f = getFunctionAt(addr);
			if (f == null) {
				println(a + " no-function");
				continue;
			}
			String c = f.getComment();
			println(a + " name=" + f.getName() + " comment=" + (c == null ? "" : c)
				+ " sig=" + f.getPrototypeString(false, false));
		}
	}
}
