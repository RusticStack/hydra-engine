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
package ghidra.app.plugin.core.analysis;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.framework.options.ToolOptions;

/**
 * The deferred ordered-writes mode is only deterministic when every worker-time write of the
 * analyzer is deferred. Processor subclasses whose evaluators still write immediately (ARM,
 * MIPS, PPC, ...) must neither offer nor honour the option, even when the system property
 * turns it on by default.
 */
public class ConstantPropagationDeferredOptInTest {

	/** Stands for an unconverted processor analyzer (ARM, MIPS, ...). */
	private static class UnconvertedAnalyzer extends ConstantPropagationAnalyzer {
		UnconvertedAnalyzer() {
			super("unconverted");
		}
	}

	@Test
	public void testGenericAnalyzerSupportsDeferredWrites() {
		assertTrue(new ConstantPropagationAnalyzer().supportsDeferredWrites());
	}

	@Test
	public void testUnconvertedSubclassDoesNotOfferOrHonourOption() {
		UnconvertedAnalyzer analyzer = new UnconvertedAnalyzer();
		assertFalse(analyzer.supportsDeferredWrites());

		ToolOptions options = new ToolOptions("test");
		analyzer.registerOptions(options, null);
		assertFalse(options.isRegistered(AbstractAnalyzer.DEFERRED_WRITES_OPTION_NAME));

		// even if the option is set (e.g. carried over from another analyzer), it is ignored
		options.setBoolean(AbstractAnalyzer.DEFERRED_WRITES_OPTION_NAME, true);
		analyzer.deferredWrites = true; // as if -Dhydra.analysis.deferredWrites=true
		analyzer.optionsChanged(options, null);
		assertFalse(analyzer.deferredWrites);
	}

	@Test
	public void testGenericAnalyzerRegistersAndHonoursOption() {
		ConstantPropagationAnalyzer analyzer = new ConstantPropagationAnalyzer();
		ToolOptions options = new ToolOptions("test");
		analyzer.registerOptions(options, null);
		assertTrue(options.isRegistered(AbstractAnalyzer.DEFERRED_WRITES_OPTION_NAME));
		options.setBoolean(AbstractAnalyzer.DEFERRED_WRITES_OPTION_NAME, true);
		analyzer.optionsChanged(options, null);
		assertTrue(analyzer.deferredWrites);
	}
}
