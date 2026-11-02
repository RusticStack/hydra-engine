//Multi-agent bench: bytes, references and symbols at each address in the script arguments (read only).
//@category Bench
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class BenchRead extends GhidraScript {
	@Override
	public void run() throws Exception {
		for (String a : getScriptArgs()) {
			Address addr = toAddr(a);
			StringBuilder bytes = new StringBuilder();
			try {
				for (byte x : getBytes(addr, 16)) {
					bytes.append(String.format("%02x", x & 0xff));
				}
			}
			catch (Exception e) {
				bytes.append("unreadable");
			}
			Reference[] refs = getReferencesTo(addr);
			StringBuilder rs = new StringBuilder();
			for (int i = 0; i < refs.length && i < 8; i++) {
				rs.append(refs[i].getFromAddress()).append(':').append(refs[i].getReferenceType()).append(' ');
			}
			StringBuilder syms = new StringBuilder();
			for (Symbol s : currentProgram.getSymbolTable().getSymbols(addr)) {
				syms.append(s.getName(true)).append(' ');
			}
			println(a + " bytes=" + bytes + " refs=" + refs.length + " [" + rs + "] syms=" + syms);
		}
	}
}
