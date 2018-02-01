// Copyright (c) 2010 - 2018, Yaler Gmbh, Switzerland. All rights reserved.

package org.yaler.core;

import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public final class Tasks {
	private Tasks () {}

	public static final class Executor {
		private Executor () {}

		private final ScheduledThreadPoolExecutor
			executor = new ScheduledThreadPoolExecutor(1);

		private Runnable exceptionSafeRunnable (final Runnable r) {
			return new Runnable() {
				public void run () {
					try {
						r.run();
					} catch (Throwable t) {
						Thread.getDefaultUncaughtExceptionHandler().uncaughtException(
							Thread.currentThread(), t);
					}
				}
			};
		}

		public void execute (Runnable r) {
			executor.execute(exceptionSafeRunnable(r));
		}

		public void schedule (Runnable r, long delay, TimeUnit unit) {
			executor.schedule(exceptionSafeRunnable(r), delay, unit);
		}

		public void scheduleAtFixedRate (
			Runnable r, long initialDelay, long period, TimeUnit unit)
		{
			executor.scheduleAtFixedRate(
				exceptionSafeRunnable(r), initialDelay, period, unit);
		}

		public void scheduleWithFixedDelay (
			Runnable r, long initialDelay, long delay, TimeUnit unit)
		{
			executor.scheduleWithFixedDelay(
				exceptionSafeRunnable(r), initialDelay, delay, unit);
		}
	}

	public static void setupExceptionHandling () {
		Thread.setDefaultUncaughtExceptionHandler(
			new Thread.UncaughtExceptionHandler () {
				public void uncaughtException(Thread t, Throwable e) {
					System.err.print("Exception in thread \"" + t.getName() + "\" ");
					e.printStackTrace();
					System.exit(1);
				}
			});
	}

	public static Executor newSingleThreadExecutor () {
		return new Executor();
	}
}
