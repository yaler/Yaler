// Copyright (c) 2010, Oberon microsystems AG, Switzerland
// All rights reserved

package org.yaler;

import java.io.IOError;
import java.io.IOException;
import java.nio.channels.SelectableChannel;
import java.nio.channels.Selector;
import java.nio.channels.SelectionKey;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.yaler.Assertions;
import org.yaler.StateMachines.StateMachine;

public final class Dispatcher {
	private Dispatcher () {}

	private static final Selector selector;
	private static final ConcurrentLinkedQueue<Runnable> tasks;

	static {
		Assertions.enable();
		try {
			selector = Selector.open();
		} catch (IOException e) { throw new IOError(e); }
		tasks = new ConcurrentLinkedQueue<Runnable>();
	}

	public static final class Selection {
		public int readyOps;
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
		} catch (IOException e) { throw new IOError(e); }
	}

	public static void run () {
		do {
			Runnable r = tasks.poll();
			while (r != null) {
				r.run();
				r = tasks.poll();
			}
			try {
				selector.select();
			} catch (IOException e) { throw new IOError(e); }
			Set<SelectionKey> ks = selector.selectedKeys();
			for (SelectionKey k: ks) {
				if (k.isValid()) {
					Selection s = new Selection();
					s.readyOps = k.readyOps();
					((StateMachine) k.attachment()).dispatch(s);
				}
			}
			ks.clear();
		} while (true);
	}
}
