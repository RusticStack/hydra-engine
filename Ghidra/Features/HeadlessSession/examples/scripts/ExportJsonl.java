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
// Writes a large JSONL file outside the project while reporting progress: the shape of a bulk
// export run through the session's "script" command. See the README, "Scripts".
//
//   args: <output path> [lines=500000] [throttleMillisPer1000Lines=0]
//
// The output path is the caller's choice and is announced to the session with the request's
// "artifact" field, so "status" shows it next to the running job. Lines go to "<path>.part" and
// the file is renamed to <path> only when the script finishes, so a cancelled, timed-out or
// interrupted export leaves a partial file at "<path>.part" that is valid JSONL up to its last
// complete line (batches of 1000 lines are written whole and flushed). Nothing here is capped by
// the "maxChars" of the script's result: that limit applies to the text the script prints.
// @category HeadlessSession.Examples
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

import ghidra.app.script.GhidraScript;

public class ExportJsonl extends GhidraScript {
	private static final int BATCH = 1000;

	@Override
	protected void run() throws Exception {
		String[] a = getScriptArgs();
		if (a.length < 1) {
			throw new IllegalArgumentException("usage: <output path> [lines] [throttleMs]");
		}
		Path out = Paths.get(a[0]).toAbsolutePath();
		long lines = a.length > 1 ? Long.parseLong(a[1]) : 500_000;
		long throttleMs = a.length > 2 ? Long.parseLong(a[2]) : 0;
		Path part = out.resolveSibling(out.getFileName() + ".part");
		Files.createDirectories(out.getParent());

		monitor.initialize(lines);
		monitor.setMessage("exporting " + lines + " lines to " + out);
		long written = 0;
		try (BufferedWriter w = Files.newBufferedWriter(part, StandardCharsets.UTF_8)) {
			StringBuilder sb = new StringBuilder(BATCH * 120);
			while (written < lines) {
				monitor.checkCancelled();
				sb.setLength(0);
				long n = Math.min(BATCH, lines - written);
				for (long i = 0; i < n; i++) {
					long k = written + i;
					sb.append("{\"i\":").append(k).append(",\"addr\":\"0x")
							.append(Long.toHexString(0x140000000L + k * 16)).append("\",\"name\":\"sym_")
							.append(k).append("\",\"note\":\"padding padding padding padding\"}\n");
				}
				w.write(sb.toString());
				w.flush(); // whole lines only: a reader never sees half a batch
				written += n;
				monitor.setProgress(written);
				monitor.setMessage("exported " + written + " of " + lines);
				if (throttleMs > 0) {
					Thread.sleep(throttleMs);
				}
			}
		}
		Files.move(part, out, StandardCopyOption.REPLACE_EXISTING);
		println("exported " + written + " lines, " + Files.size(out) + " bytes to " + out);
	}
}
