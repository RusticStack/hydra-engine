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

import java.io.IOException;

import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.project.DefaultProject;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.framework.store.LockException;
import ghidra.util.NotOwnerException;
import ghidra.util.exception.NotFoundException;

/**
 * The project a session works in, opened one of two ways.
 * <ul>
 * <li><b>Read-only</b> (the default): the project data is opened the way the window's
 * <i>File &gt; View Project</i> opens it ({@code new DefaultProjectData(locator, false, false)}):
 * no project lock is taken and no file in the project is written, so any number of sessions, and a
 * Ghidra window, can read the same project at once. {@code analyzeHeadless} cannot do this: it
 * always opens the project writable and locked, even with {@code -readOnly}.</li>
 * <li><b>Writable</b>: the project is opened as the window's <i>File &gt; Open Project</i> does,
 * which takes the project's lock. Only one process can hold it.</li>
 * </ul>
 */
final class SessionProject extends DefaultProject {

	private final boolean writable;

	private SessionProject(Manager manager, ProjectLocator locator)
			throws IOException, NotFoundException, NotOwnerException, LockException {
		super(manager, locator, false);
		this.writable = true;
		AppInfo.setActiveProject(this);
	}

	private SessionProject(Manager manager, DefaultProjectData data) {
		super(manager, data);
		this.writable = false;
		AppInfo.setActiveProject(this);
	}

	static SessionProject open(ProjectLocator locator, boolean writable)
			throws IOException, NotFoundException, NotOwnerException, LockException {
		Manager manager = new Manager();
		if (writable) {
			return new SessionProject(manager, locator);
		}
		return new SessionProject(manager, new DefaultProjectData(locator, false, false));
	}

	boolean isWritable() {
		return writable;
	}

	/**
	 * Like the headless analyzer's project manager: never touches the user's GUI preferences
	 * (last opened project, recent projects).
	 */
	private static final class Manager extends DefaultProjectManager {
		@Override
		public void setLastOpenedProject(ProjectLocator projectLocator) {
			// a session must not change what the window reopens
		}

		@Override
		public ProjectLocator getLastOpenedProject() {
			return null;
		}

		@Override
		protected void updatePreferences() {
			// nothing to save
		}
	}
}
