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
package ghidra.app.decompiler;

import static org.junit.Assert.*;

import java.io.*;

import org.junit.*;

import generic.jar.ResourceFile;
import ghidra.app.decompiler.DecompInterface.SpecStrings;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.UniqueLayout;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeDataTypeManager;
import ghidra.program.model.pcode.XmlEncode;
import ghidra.program.model.symbol.IdentityNameTransformer;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

/**
 * The specification strings sent to each new decompiler process are cached per program state
 * and must be exactly what building them from scratch gives
 */
public class DecompInterfaceSpecCacheTest extends AbstractGhidraHeadlessIntegrationTest {

	private ProgramBuilder builder;
	private Program program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("test", ProgramBuilder._X86, this);
		builder.createMemory(".text", "0x1001000", 0x100);
		program = builder.getProgram();
	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	@Test
	public void testSpecStringsSharedByInterfaces() throws Exception {
		SpecStrings first = open().getSpecStrings();
		SpecStrings second = open().getSpecStrings();

		assertSame(first.tspec, second.tspec);
		assertSame(first.coretypes, second.coretypes);
		assertBuiltFromScratch(first);
	}

	@Test
	public void testCompilerSpecExtensionInstalledAfterOptionsChange() throws Exception {
		DecompInterface ifc = open();
		String fixup = "<callfixup name=\"mynewthing\">\n" + "  <target name=\"targ1\"/>\n" +
			"  <pcode>\n" + "    <body><![CDATA[\n" + "    ESP = ESP + 4;\n" + "    ]]></body>\n" +
			"  </pcode>\n" + "</callfixup>\n";

		// Adding an extension first sets the program options, which bumps the modification
		// number, and only then installs the extension into the compiler spec in place.
		// Build the strings in between, as a concurrent decompiler start could.
		int tx = program.startTransaction("extension");
		try {
			Options specOptions = program.getOptions(SpecExtension.SPEC_EXTENSION);
			specOptions.setString("callfixup_mynewthing", fixup);
			specOptions.setInt(SpecExtension.VERSION_COUNTER_OPTIONNAME,
				SpecExtension.getVersionCounter(program) + 1);
			ifc.getSpecStrings();
			invokeInstanceMethod("installExtensions", program);

			SpecStrings after = ifc.getSpecStrings();
			assertTrue(after.cspecxml.contains("mynewthing"));
			assertBuiltFromScratch(after);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	@Test
	public void testSpecStringsRebuiltAfterProgramChange() throws Exception {
		DecompInterface ifc = open();
		SpecStrings before = ifc.getSpecStrings();

		// An overlay adds an address space to the translator spec
		builder.createOverlayMemory("ov1", "0x2000", 0x10);
		SpecStrings after = ifc.getSpecStrings();

		assertNotSame(before, after);
		assertNotEquals(before.tspec, after.tspec);
		assertBuiltFromScratch(after);
	}

	/**
	 * Open the program in an interface whose process is a stand-in: these tests need only the
	 * strings that registerProgram would send
	 * @return the interface
	 */
	private DecompInterface open() {
		DecompInterface ifc = new DecompInterface() {
			@Override
			protected void initializeProcess() {
				decompProcess = new DecompileProcess("unused") {
					@Override
					public synchronized boolean isReady() {
						return true;
					}
				};
			}
		};
		assertTrue(ifc.openProgram(program));
		return ifc;
	}

	private void assertBuiltFromScratch(SpecStrings specs) throws IOException {
		SleighLanguage language = (SleighLanguage) program.getLanguage();
		XmlEncode xmlEncode = new XmlEncode(false);
		language.encodeTranslator(xmlEncode, program.getAddressFactory(),
			UniqueLayout.SLEIGH_BASE.getOffset(language));
		assertEquals(xmlEncode.toString(), specs.tspec);

		xmlEncode.clear();
		new PcodeDataTypeManager(program, new IdentityNameTransformer())
				.encodeCoreTypes(xmlEncode);
		assertEquals(xmlEncode.toString(), specs.coretypes);

		xmlEncode.clear();
		program.getCompilerSpec().encode(xmlEncode);
		assertEquals(xmlEncode.toString(), specs.cspecxml);

		ResourceFile pspecFile = language.getLanguageDescription().getSpecFile();
		StringBuilder pspec = new StringBuilder();
		try (BufferedReader reader =
			new BufferedReader(new InputStreamReader(pspecFile.getInputStream()))) {
			String line;
			while ((line = reader.readLine()) != null) {
				pspec.append(line);
			}
		}
		assertEquals(pspec.toString(), specs.pspecxml);
	}
}
