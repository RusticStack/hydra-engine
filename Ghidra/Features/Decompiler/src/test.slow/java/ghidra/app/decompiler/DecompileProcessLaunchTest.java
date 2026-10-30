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
import java.util.concurrent.TimeUnit;

import org.junit.*;

import ghidra.app.decompiler.DecompileProcess.DisposeState;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

/**
 * Starts {@link DecompileProcess} on scripted processes instead of the decompiler executable
 */
public class DecompileProcessLaunchTest extends AbstractGhidraHeadlessIntegrationTest {

	// The answer to registerProgram: a response holding the architecture id "0"
	private static final byte[] REGISTER_RESPONSE =
		{ 0, 0, 1, 6, 0, 0, 1, 14, '0', 0, 0, 1, 15, 0, 0, 1, 7 };

	private ProgramBuilder builder;
	private Program program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("test", ProgramBuilder._TOY, this);
		program = builder.getProgram();
	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	@Test
	public void testStartupDoesNotWaitOnLiveProcess() throws Exception {
		ScriptedProcess process = new ScriptedProcess(REGISTER_RESPONSE, Integer.MAX_VALUE);
		DecompileProcess decompProcess = new ScriptedDecompileProcess(process);

		decompProcess.registerProgram(null, "", "", "", "", program);

		assertTrue(decompProcess.isReady());
		assertEquals(DisposeState.NOT_DISPOSED, decompProcess.getDisposeState());
		assertEquals("startup waited on a process that was running", 0, process.timedWaits);
	}

	@Test
	public void testProcessDeadAtStartIsStartupFailure() throws Exception {
		ScriptedProcess process = new ScriptedProcess(new byte[0], 0);
		DecompileProcess decompProcess = new ScriptedDecompileProcess(process);

		assertLaunchFails(decompProcess);
	}

	@Test
	public void testProcessExitingBeforeHandshakeIsStartupFailure() throws Exception {
		// Alive when started, but it exits without answering registerProgram
		ScriptedProcess process = new ScriptedProcess(new byte[0], 1);
		DecompileProcess decompProcess = new ScriptedDecompileProcess(process);

		assertLaunchFails(decompProcess);
		assertTrue(process.destroyed);
	}

	private void assertLaunchFails(DecompileProcess decompProcess) throws Exception {
		try {
			decompProcess.registerProgram(null, "", "", "", "", program);
			fail("registerProgram succeeded on a process that failed to launch");
		}
		catch (IOException e) {
			assertEquals("Decompiler process failed to launch (see log for details)",
				e.getMessage());
		}
		assertFalse(decompProcess.isReady());
		assertEquals(DisposeState.DISPOSED_ON_STARTUP_FAILURE, decompProcess.getDisposeState());
	}

	private static class ScriptedDecompileProcess extends DecompileProcess {
		private final Process process;

		ScriptedDecompileProcess(Process process) {
			super("scripted");
			this.process = process;
		}

		@Override
		Process launch() {
			return process;
		}
	}

	/**
	 * A process that writes a fixed answer and is alive for a given number of isAlive calls
	 */
	private static class ScriptedProcess extends Process {
		private final InputStream in;
		private final OutputStream out = new ByteArrayOutputStream();
		private final InputStream err = new ByteArrayInputStream("scripted failure".getBytes());
		private int aliveChecks;
		private volatile boolean destroyed;
		private int timedWaits;

		ScriptedProcess(byte[] answer, int aliveChecks) {
			this.in = new ByteArrayInputStream(answer);
			this.aliveChecks = aliveChecks;
		}

		@Override
		public synchronized boolean isAlive() {
			if (destroyed || aliveChecks <= 0) {
				return false;
			}
			aliveChecks--;
			return true;
		}

		@Override
		public synchronized boolean waitFor(long timeout, TimeUnit unit) {
			timedWaits++;
			return destroyed || aliveChecks <= 0;
		}

		@Override
		public int waitFor() {
			return 0;
		}

		@Override
		public OutputStream getOutputStream() {
			return out;
		}

		@Override
		public InputStream getInputStream() {
			return in;
		}

		@Override
		public InputStream getErrorStream() {
			return err;
		}

		@Override
		public int exitValue() {
			return 0;
		}

		@Override
		public void destroy() {
			destroyed = true;
		}
	}
}
