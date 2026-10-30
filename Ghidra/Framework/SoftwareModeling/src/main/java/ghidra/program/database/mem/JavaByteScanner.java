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

import java.util.Arrays;

/**
 * Java reference implementation of {@link ByteScanner}; see {@link ByteScanner#JAVA}.
 */
final class JavaByteScanner implements ByteScanner {

	@Override
	public int find(byte[] data, int count, byte[] pattern, byte[] mask, boolean forward) {
		int len = pattern.length;
		if (count <= 0 || len == 0) {
			return -1;
		}
		if (data.length < count + len - 1) {
			throw new IllegalArgumentException("data shorter than count + pattern length - 1");
		}
		if (mask == null) {
			byte b0 = pattern[0];
			if (forward) {
				for (int k = 0; k < count; k++) {
					if (data[k] == b0 && Arrays.equals(data, k, k + len, pattern, 0, len)) {
						return k;
					}
				}
			}
			else {
				for (int k = count - 1; k >= 0; k--) {
					if (data[k] == b0 && Arrays.equals(data, k, k + len, pattern, 0, len)) {
						return k;
					}
				}
			}
			return -1;
		}
		if (forward) {
			for (int k = 0; k < count; k++) {
				if (maskedAt(data, k, pattern, mask)) {
					return k;
				}
			}
		}
		else {
			for (int k = count - 1; k >= 0; k--) {
				if (maskedAt(data, k, pattern, mask)) {
					return k;
				}
			}
		}
		return -1;
	}

	private static boolean maskedAt(byte[] data, int k, byte[] pattern, byte[] mask) {
		for (int i = 0; i < pattern.length; i++) {
			if ((data[k + i] & mask[i]) != (pattern[i] & mask[i])) {
				return false;
			}
		}
		return true;
	}

	@Override
	public Matches findAll(byte[] data, int dataLen, byte[][] patterns,
			boolean asciiCaseInsensitive) {
		if (patterns.length == 0) {
			throw new IllegalArgumentException("no patterns");
		}
		for (byte[] p : patterns) {
			if (p.length == 0) {
				throw new IllegalArgumentException("empty pattern");
			}
		}
		long[] offs = new long[16];
		int[] pats = new int[16];
		int n = 0;
		for (int o = 0; o < dataLen; o++) {
			for (int i = 0; i < patterns.length; i++) {
				byte[] p = patterns[i];
				if (o + p.length > dataLen || !equalAt(data, o, p, asciiCaseInsensitive)) {
					continue;
				}
				if (n == offs.length) {
					offs = Arrays.copyOf(offs, n * 2);
					pats = Arrays.copyOf(pats, n * 2);
				}
				offs[n] = o;
				pats[n] = i;
				n++;
			}
		}
		return new Matches(Arrays.copyOf(offs, n), Arrays.copyOf(pats, n));
	}

	private static boolean equalAt(byte[] data, int o, byte[] p, boolean ci) {
		for (int i = 0; i < p.length; i++) {
			byte a = data[o + i];
			byte b = p[i];
			if (a != b && !(ci && fold(a) == fold(b))) {
				return false;
			}
		}
		return true;
	}

	private static int fold(byte b) {
		return (b >= 'A' && b <= 'Z') ? b + ('a' - 'A') : b;
	}

	@Override
	public String name() {
		return "java";
	}
}
