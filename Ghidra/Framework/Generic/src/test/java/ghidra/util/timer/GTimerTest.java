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
package ghidra.util.timer;

import static org.junit.Assert.*;

import java.util.Timer;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

import generic.test.AbstractGTest;
import generic.test.TestUtils;

public class GTimerTest extends AbstractGTest {

	private static final long ONE_HOUR = 60 * 60 * 1000;

	private Timer timer() {
		return (Timer) TestUtils.getInstanceField("timer", GTimer.class);
	}

	@Test
	public void testCancelledTaskLeavesTimerQueue() {
		// The timer thread drops a cancelled task at the head of its queue by itself, so the
		// cancelled task is queued behind one that is still pending
		GTimerMonitor pending = GTimer.scheduleRunnable(ONE_HOUR, () -> {
			// not run
		});
		GTimerMonitor monitor = GTimer.scheduleRunnable(2 * ONE_HOUR, () -> {
			// not run
		});

		assertTrue(monitor.cancel());
		assertTrue(monitor.wasCancelled());
		assertFalse(monitor.didRun());
		assertEquals("cancelled task still queued", 0, timer().purge());
		assertTrue(pending.cancel());
	}

	@Test
	public void testTaskRunsAndCannotBeCancelledAfter() throws Exception {
		CountDownLatch ran = new CountDownLatch(1);
		GTimerMonitor monitor = GTimer.scheduleRunnable(1, ran::countDown);

		assertTrue(ran.await(DEFAULT_WAIT_TIMEOUT, TimeUnit.MILLISECONDS));
		waitForCondition(monitor::didRun);
		assertFalse(monitor.cancel());
		assertFalse(monitor.wasCancelled());
	}

	@Test
	public void testRepeatingTaskStopsWhenCancelledFromItself() throws Exception {
		CountDownLatch ran = new CountDownLatch(3);
		GTimerMonitor[] monitor = new GTimerMonitor[1];
		CountDownLatch scheduled = new CountDownLatch(1);
		monitor[0] = GTimer.scheduleRepeatingRunnable(1, 1, () -> {
			ran.countDown();
			if (ran.getCount() == 0) {
				try {
					scheduled.await();
				}
				catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
				monitor[0].cancel();
			}
		});
		scheduled.countDown();

		assertTrue(ran.await(DEFAULT_WAIT_TIMEOUT, TimeUnit.MILLISECONDS));
		waitForCondition(monitor[0]::wasCancelled);
		assertEquals(0, timer().purge());
	}
}
