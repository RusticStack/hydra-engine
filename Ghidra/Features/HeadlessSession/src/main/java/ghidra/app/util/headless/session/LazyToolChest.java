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

import java.util.Objects;
import java.util.function.Supplier;

import ghidra.framework.model.*;

/**
 * A tool chest that is built the first time it is used.
 * <p>
 * {@code DefaultProjectManager}'s constructor builds the user's tool chest at once: it lists the
 * user's tools folder and parses every {@code .tool} file in it (XML), and seeds that folder with the
 * default tools when it is empty. A headless session never shows a tool, so every project open paid
 * for that parse and threw it away. This chest defers the same work, done by the same code, to the
 * first call that needs it; a caller that does ask for the chest gets exactly what it got before.
 */
final class LazyToolChest implements ToolChest {

	private final Supplier<ToolChest> loader;
	private volatile ToolChest chest;

	LazyToolChest(Supplier<ToolChest> loader) {
		this.loader = Objects.requireNonNull(loader);
	}

	/** True once the real chest has been built. */
	boolean isLoaded() {
		return chest != null;
	}

	private ToolChest chest() {
		ToolChest c = chest;
		if (c == null) {
			synchronized (this) {
				c = chest;
				if (c == null) {
					c = Objects.requireNonNull(loader.get(), "tool chest loader returned null");
					chest = c;
				}
			}
		}
		return c;
	}

	@Override
	public ToolTemplate getToolTemplate(String toolName) {
		return chest().getToolTemplate(toolName);
	}

	@Override
	public ToolTemplate[] getToolTemplates() {
		return chest().getToolTemplates();
	}

	@Override
	public void addToolChestChangeListener(ToolChestChangeListener l) {
		chest().addToolChestChangeListener(l);
	}

	@Override
	public void removeToolChestChangeListener(ToolChestChangeListener l) {
		chest().removeToolChestChangeListener(l);
	}

	@Override
	public boolean addToolTemplate(ToolTemplate template) {
		return chest().addToolTemplate(template);
	}

	@Override
	public boolean remove(String toolName) {
		return chest().remove(toolName);
	}

	@Override
	public int getToolCount() {
		return chest().getToolCount();
	}

	@Override
	public boolean replaceToolTemplate(ToolTemplate template) {
		return chest().replaceToolTemplate(template);
	}

	@Override
	public String toString() {
		ToolChest c = chest;
		return c != null ? c.toString() : "LazyToolChest[not loaded]";
	}
}
