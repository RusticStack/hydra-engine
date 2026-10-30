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

import java.nio.charset.StandardCharsets;

import com.google.gson.JsonElement;
import com.google.gson.JsonPrimitive;

/**
 * A reply value that is already encoded: UTF-8 JSON bytes (Hydra reply-encode). It travels in a
 * reply tree as the number of a {@link JsonPrimitive}, and {@link Connection#encodeParts} writes
 * its bytes as they are, without a copy, where Gson would have written the value it stands for.
 * <p>
 * Only the connection's encoder knows it: Gson itself refuses to write it (it is not a trusted
 * number type and its text is not a number), so a reply that reached another writer fails loudly
 * instead of carrying a wrong value.
 */
final class RawJson extends Number {

	private final transient byte[] bytes;

	private RawJson(byte[] bytes) {
		this.bytes = bytes;
	}

	/** The reply value whose JSON is {@code utf8}. */
	static JsonPrimitive of(byte[] utf8) {
		return new JsonPrimitive(new RawJson(utf8));
	}

	/** The bytes of {@code e} when it is a raw value, else null. */
	static byte[] bytes(JsonElement e) {
		if (e instanceof JsonPrimitive p && p.isNumber() && p.getAsNumber() instanceof RawJson r) {
			return r.bytes;
		}
		return null;
	}

	@Override
	public String toString() {
		return new String(bytes, StandardCharsets.UTF_8);
	}

	@Override
	public int intValue() {
		throw unsupported();
	}

	@Override
	public long longValue() {
		throw unsupported();
	}

	@Override
	public float floatValue() {
		throw unsupported();
	}

	@Override
	public double doubleValue() {
		throw unsupported();
	}

	private static UnsupportedOperationException unsupported() {
		return new UnsupportedOperationException("an encoded reply value is not a number");
	}
}
