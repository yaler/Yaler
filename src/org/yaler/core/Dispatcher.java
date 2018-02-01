// Copyright (c) 2010 - 2018, Yaler Gmbh, Switzerland. All rights reserved.

package org.yaler.core;

import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.yaler.core.StateMachines.State;
import org.yaler.core.StateMachines.StateMachine;

public final class Dispatcher {
	private Dispatcher () {}

	private static final Selector
		selector = newSelector();
	private static final ConcurrentLinkedQueue<Runnable>
		tasks = new ConcurrentLinkedQueue<Runnable>();

	private static Selector newSelector () {
		try {
			return Selector.open();
		} catch (Exception e) { throw new Error(e); }
	}

	public static final class Selection {
		public int readyOps;
	}

	public static void start (final StateMachine m, final State initialState) {
		assert m != null;
		tasks.offer(new Runnable () {
			public void run () {
				m.start(initialState);
			}
		});
		selector.wakeup();
	}

	public static void dispatch (final StateMachine m, final Object o) {
		assert m != null;
		tasks.offer(new Runnable () {
			public void run () {
				m.dispatch(o);
			}
		});
		selector.wakeup();
	}

	public static void register (SelectableChannel c, int ops, StateMachine m) {
		assert c != null;
		assert m != null;
		try {
			c.register(selector, ops, m);
		} catch (Exception e) { throw new Error(e); }
	}

	public static void run () {
		while (true) {
			Runnable r = tasks.poll();
			while (r != null) {
				r.run();
				r = tasks.poll();
			}
			try {
				selector.select();
			} catch (Exception e) { throw new Error(e); }
			for (SelectionKey k: selector.selectedKeys()) {
				if (k.isValid()) {
					Selection s = new Selection();
					s.readyOps = k.readyOps();
					((StateMachine) k.attachment()).dispatch(s);
				}
			}
			selector.selectedKeys().clear();
		}
	}
}
