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

import java.lang.reflect.Field;

import ghidra.program.database.ProgramDB;

/**
 * The database format versions this engine reads and writes, in one place (PROTOCOL-3.md 3.2):
 * {@code hello}'s {@code analysisIdentity.dbVersions} reports them, and the upgrade cache and the
 * upgrade gate compare stored versions with them.
 */
final class DbVersions {

	private static final int PROGRAM = readProgram();
	private static final int DATA_TYPES = readStatic("ghidra.program.database.data.DataTypeManagerDB");

	private DbVersions() {
	}

	/**
	 * The current program database version ({@code ProgramDB.DB_VERSION}, read reflectively because
	 * the field is private), or -1 when it cannot be read. A caller must treat -1 as unknown, never
	 * as "current": {@code stored < program()} is false for -1.
	 */
	static int program() {
		return PROGRAM;
	}

	/**
	 * The current data type database version ({@code DataTypeManagerDB.DB_VERSION}, read
	 * reflectively like {@link #program()}), or {@code null} when it cannot be read: a number is
	 * never guessed. The version a program <i>stores</i> is read from its database header by
	 * {@link ProjectFormat} and tested against stock 12.1.4 data (E2).
	 */
	static Integer dataTypes() {
		return DATA_TYPES < 0 ? null : DATA_TYPES;
	}

	private static int readProgram() {
		try {
			Field f = ProgramDB.class.getDeclaredField("DB_VERSION");
			f.setAccessible(true);
			return f.getInt(null);
		}
		catch (ReflectiveOperationException | RuntimeException e) {
			return -1;
		}
	}

	private static int readStatic(String className) {
		try {
			Field f = Class.forName(className).getDeclaredField("DB_VERSION");
			f.setAccessible(true);
			return f.getInt(null);
		}
		catch (ReflectiveOperationException | RuntimeException e) {
			return -1;
		}
	}
}
