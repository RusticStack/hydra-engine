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
package ghidra.program.database.mem;

/**
 * A byte-pattern and string scanner over a byte buffer. Two implementations exist with one
 * contract: {@link #JAVA} (the reference) and the native SIMD scanner ({@link NativeByteScanner},
 * the Rust crate {@code src/main/rust/hydra_scan}). They return the same matches in the same
 * order; the tests compare them on random and fixture data.
 */
public interface ByteScanner {

	/** All matches of a {@link #findAll} call, sorted by (offset, pattern index). */
	public record Matches(long[] offsets, int[] patterns) {
		public int size() {
			return offsets.length;
		}
	}

	/**
	 * Find the first ({@code forward}) or last window start {@code k} in {@code [0, count)} such
	 * that {@code data[k + i] & mask[i] == pattern[i] & mask[i]} for every {@code i} (no mask:
	 * all bits). {@code data} must hold at least {@code count + pattern.length - 1} bytes.
	 *
	 * @param data the bytes
	 * @param count number of candidate window starts
	 * @param pattern the pattern, at least one byte
	 * @param mask null or a mask of {@code pattern.length} bytes
	 * @param forward true for the lowest match, false for the highest
	 * @return the window start, or -1
	 */
	int find(byte[] data, int count, byte[] pattern, byte[] mask, boolean forward);

	/**
	 * Every occurrence of every pattern in {@code data[0, dataLen)}, overlapping, sorted by
	 * offset and then by pattern index (a pattern given twice is reported twice).
	 *
	 * @param data the bytes
	 * @param dataLen number of bytes of {@code data} to scan
	 * @param patterns one or more non-empty patterns
	 * @param asciiCaseInsensitive true to compare ASCII letters case-insensitively
	 * @return the matches
	 */
	Matches findAll(byte[] data, int dataLen, byte[][] patterns, boolean asciiCaseInsensitive);

	/** @return a short name for logs and measurements */
	String name();

	/** The Java reference implementation. */
	public static final ByteScanner JAVA = new JavaByteScanner();

	/**
	 * The scanner to use: the native one when its library is loaded and the system property
	 * {@code hydra.scan.native} is not {@code false}, the Java one otherwise. Results are the
	 * same either way.
	 *
	 * @return the preferred scanner
	 */
	public static ByteScanner preferred() {
		ByteScanner n = NativeByteScanner.instance();
		return n != null ? n : JAVA;
	}
}
