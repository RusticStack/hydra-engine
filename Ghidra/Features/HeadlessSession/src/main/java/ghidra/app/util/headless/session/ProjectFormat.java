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

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import com.google.gson.JsonObject;

import ghidra.app.util.headless.session.UpgradeCache.Stored;
import ghidra.framework.model.*;
import ghidra.program.model.listing.Program;

/**
 * The {@code format} block of a project (PROTOCOL-3.md 3.4), computed from the same reads as the
 * upgrade cache ({@link UpgradeCache#readStored}): each program's stored program database
 * version and data type manager version, read from the database header <b>without opening the
 * program</b>, cached per project {@link Revision}. At most {@link #MAX_PROGRAMS} programs are
 * scanned ({@code truncated:true} beyond that). It writes nothing.
 * <p>
 * Unlike {@code olderFormat} (which reads an unreadable header as "current"), it tells
 * <b>unknown</b> from <b>current</b>: an unreadable header or an unreadable engine constant gives
 * {@code upgradeRequired:null}, and the upgrade gate treats null as required.
 */
final class ProjectFormat {

	static final int MAX_PROGRAMS = 64;
	private static final Map<String, JsonObject> CACHE = new ConcurrentHashMap<>();

	private ProjectFormat() {
	}

	/** What the gate needs to know of one program. */
	record Need(boolean required, boolean unknown, Stored stored) {
	}

	/**
	 * Whether the program needs an upgrade: {@code required} when its stored versions are older
	 * than this engine's or cannot be told (then also {@code unknown}).
	 */
	static Need need(ProjectData pd, DomainFile df) {
		Stored st = UpgradeCache.readStored(pd, df);
		int cur = DbVersions.program();
		if (!st.readable() || cur < 0) {
			return new Need(true, true, st);
		}
		boolean older = st.programDb() < cur || st.languageReason() != null ||
			(st.dataTypeDb() != null && DbVersions.dataTypes() != null &&
				st.dataTypeDb() < DbVersions.dataTypes());
		return new Need(older, false, st);
	}

	/** The {@code format} object of a project, cached per revision. */
	static JsonObject of(ProjectEntry p) {
		String rev = p.revision();
		String key = p.canonical + "|" + rev;
		if (rev != null) {
			JsonObject hit = CACHE.get(key);
			if (hit != null) {
				return hit.deepCopy();
			}
		}
		JsonObject o;
		try {
			o = compute(p.data());
		}
		catch (RuntimeException e) {
			o = unknown(e.getClass().getSimpleName() + ": " + e.getMessage());
		}
		if (rev != null) {
			if (CACHE.size() > 256) {
				CACHE.clear();
			}
			CACHE.put(key, o.deepCopy());
		}
		return o;
	}

	private static JsonObject unknown(String why) {
		JsonObject o = Json.of("programDb", Json.of("min", null, "max", null, "current",
			DbVersions.program() < 0 ? null : DbVersions.program()), "dataTypeDb", null,
			"upgradeRequired", null, "oneWay", null, "newerThanEngine", false, "programsScanned",
			0, "truncated", false, "engine", engine());
		Json.put(o, "error", why);
		return o;
	}

	private static JsonObject engine() {
		return Json.of("hydraVersion", HydraInfo.hydraVersion(), "ghidraVersion",
			ghidra.framework.Application.getApplicationVersion());
	}

	/**
	 * The {@code format} of a project that is not open in this daemon: a read-only view is opened
	 * for the reads and closed again (a read-only open takes no project lock and writes nothing).
	 */
	static JsonObject ofClosed(ProjectResolver.Resolved r) {
		SessionProject sp = null;
		try {
			sp = SessionProject.open(new ProjectLocator(r.dir().getPath(), r.name()), false);
			return compute(sp.getProjectData());
		}
		catch (Exception e) {
			return unknown(e.getClass().getSimpleName() + ": " + e.getMessage());
		}
		finally {
			if (sp != null) {
				sp.close();
			}
		}
	}

	static JsonObject compute(ProjectData pd) {
		List<DomainFile> programs = new ArrayList<>();
		boolean[] truncated = { false };
		collect(pd.getRootFolder(), programs, truncated);
		int cur = DbVersions.program();
		Integer curDt = DbVersions.dataTypes();
		Integer min = null;
		Integer max = null;
		Integer dtMin = null;
		Integer dtMax = null;
		boolean unknown = cur < 0;
		boolean required = false;
		boolean newer = false;
		for (DomainFile df : programs) {
			Stored st = UpgradeCache.readStored(pd, df);
			if (!st.readable()) {
				unknown = true;
				continue;
			}
			min = min == null ? st.programDb() : Math.min(min, st.programDb());
			max = max == null ? st.programDb() : Math.max(max, st.programDb());
			if (st.dataTypeDb() != null) {
				dtMin = dtMin == null ? st.dataTypeDb() : Math.min(dtMin, st.dataTypeDb());
				dtMax = dtMax == null ? st.dataTypeDb() : Math.max(dtMax, st.dataTypeDb());
			}
			if (cur >= 0 && (st.programDb() < cur || st.languageReason() != null)) {
				required = true;
			}
			if (cur >= 0 && st.programDb() > cur ||
				curDt != null && st.dataTypeDb() != null && st.dataTypeDb() > curDt) {
				newer = true;
			}
			if (curDt != null && st.dataTypeDb() != null && st.dataTypeDb() < curDt) {
				required = true;
			}
		}
		// unknown is not current: only a project with every header read and none older is false
		Boolean upgrade = required ? Boolean.TRUE : unknown ? null : Boolean.FALSE;
		JsonObject o = new JsonObject();
		o.add("programDb",
			Json.of("min", min, "max", max, "current", cur < 0 ? null : cur));
		o.add("dataTypeDb", dtMin == null ? null
				: Json.of("min", dtMin, "max", dtMax, "current", curDt));
		Json.put(o, "upgradeRequired", upgrade);
		Json.put(o, "oneWay", upgrade);
		Json.put(o, "newerThanEngine", newer);
		Json.put(o, "programsScanned", programs.size());
		Json.put(o, "truncated", truncated[0]);
		o.add("engine", engine());
		return o;
	}

	private static void collect(DomainFolder f, List<DomainFile> out, boolean[] truncated) {
		for (DomainFile df : f.getFiles()) {
			if (out.size() >= MAX_PROGRAMS) {
				truncated[0] = true;
				return;
			}
			if (!df.isLink() && Program.class.isAssignableFrom(df.getDomainObjectClass())) {
				out.add(df);
			}
		}
		for (DomainFolder sub : f.getFolders()) {
			if (out.size() >= MAX_PROGRAMS) {
				truncated[0] = true;
				return;
			}
			collect(sub, out, truncated);
		}
	}

	/** The summary a backup manifest keeps: {@code stored} (3.4). */
	static JsonObject stored(JsonObject format) {
		JsonObject pdb = format.has("programDb") ? format.getAsJsonObject("programDb") : null;
		JsonObject st = new JsonObject();
		if (pdb != null && Json.has(pdb, "min")) {
			st.add("programDb", Json.of("min", pdb.get("min"), "max", pdb.get("max")));
		}
		st.add("programs", format.get("programsScanned"));
		st.add("scanned", format.get("programsScanned"));
		st.add("truncated", format.get("truncated"));
		return st;
	}
}
