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
package ghidra.app.util.headless.session;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

/**
 * Addresses as the protocol writes and reads them.
 */
final class Addresses {

	private Addresses() {
		// static helpers
	}

	static String hex(Address a) {
		if (a.getAddressSpace().isMemorySpace() &&
			a.getAddressSpace() == a.getAddressSpace().getPhysicalSpace() &&
			!a.getAddressSpace().isOverlaySpace()) {
			return "0x" + Long.toHexString(a.getOffset());
		}
		return a.toString(true);
	}

	/** Accepts {@code 0x140001000}, {@code va:0x...}, {@code rva:0x...} or {@code space:offset}. */
	static Address address(Program p, String text) {
		String t = text.trim();
		try {
			if (t.startsWith("rva:")) {
				return p.getImageBase().add(Long.decode(t.substring(4)));
			}
			if (t.startsWith("va:")) {
				t = t.substring(3);
			}
			if (!t.contains(":")) {
				String h = t.startsWith("0x") || t.startsWith("0X") ? t.substring(2) : t;
				return p.getAddressFactory()
						.getDefaultAddressSpace()
						.getAddress(Long.parseUnsignedLong(h, 16));
			}
			Address a = p.getAddressFactory().getAddress(t);
			if (a != null) {
				return a;
			}
		}
		catch (NumberFormatException | AddressOutOfBoundsException e) {
			// fall through
		}
		throw new SessionException(SessionException.BAD_REQUEST,
			"bad address '" + text + "': use 0x<hex>, va:0x<hex>, rva:0x<hex> or space:offset");
	}
}
