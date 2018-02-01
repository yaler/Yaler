// Copyright (c) 2010 - 2018, Yaler Gmbh, Switzerland. All rights reserved.

// Cluster membership is managed based on Scuttlebutt, an efficient anti-entropy
// protocol by van Renesse et al., 2004. Failure detection is based on ideas
// described by van Renesse et al., 1996, Hayashibara et al., 2004, and Lakshman
// et al., 2009. See References.txt

package org.yaler.core;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.charset.Charset;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import javax.crypto.Mac;

import org.yaler.core.Tasks;
import org.yaler.core.Tasks.Executor;

public final class Cluster {
	private Cluster () {}

	public static interface EventHandler {
		public void nodeJoined (String hostname, int tokencount);
		public void nodeLost (String hostname, int tokencount);
	}

	private static final class Node {
		Node next;
		InetSocketAddress endpoint;
		String hostname;
		int tokencount;
		boolean seed, reachable;
		long uuid0, uuid1, clock, last, sum;
		long[] samples = new long[1200];
		int position, size;
	}

	private static final class Digest {
		int size;
		Node[] nodes = new Node[20];
		InetSocketAddress reachableTarget, unreachableTarget;
	}

	private static final class Datagram {
		InetSocketAddress target;
		ByteBuffer data;

		Datagram (InetSocketAddress a, ByteBuffer b) {
			target = a;
			data = b;
		}
	}

	private static final byte
		DIGEST = 0, DELTA_DIGEST = 1, DELTA_VALUES = 2;
	private static final int
		NEUTRAL = 0, SELECTABLE = 1, DISPOSABLE = 2,
		DATAGRAM_LENGTH = 512, MAC_LENGTH = 20, PHI = 10;
	private static final Charset
		ASCII = Charset.forName("US-ASCII");

	private static final Random
		random = new Random();
	private static final Selector
		selector = newSelector();
	private static final Executor
		executor = Tasks.newSingleThreadExecutor();
	private static final ConcurrentLinkedQueue<Datagram>
		outbox = new ConcurrentLinkedQueue<Datagram>();

	private static Mac mac;
	private static Node nodes, localnode;
	private static InetSocketAddress[] seeds;
	private static EventHandler eventHandler;

	private static Selector newSelector () {
		try {
			return Selector.open();
		} catch (Exception e) { throw new Error(e); }
	}

	private static int compare (long x0, long x1, long y0, long y1) {
		return
			x0 < y0? -1:
			x0 > y0? +1:
			x1 < y1? -1:
			x1 > y1? +1:
			0;
	}

	private static boolean contains (Object[] a, Object o) {
		int i = 0, n = a.length;
		while ((i != n) && !o.equals(a[i])) {
			i++;
		}
		return i != n;
	}

	private static byte[] mac (ByteBuffer b) {
		int p = b.position();
		b.position(0);
		b.limit(b.limit() - MAC_LENGTH);
		mac.update(b);
		b.position(p);
		b.limit(b.limit() + MAC_LENGTH);
		return mac.doFinal();
	}

	private static String getString (ByteBuffer b) {
		byte[] bytes = new byte[b.get() & 0xff];
		b.get(bytes);
		return new String(bytes, ASCII);
	}

	private static InetSocketAddress getEndpoint (ByteBuffer b) {
		try {
			byte[] address = new byte[4];
			b.get(address);
			return new InetSocketAddress(
				InetAddress.getByAddress(address), b.getShort() & 0xffff);
		} catch (Exception e) { throw new Error(e); }
	}

	private static void putMac (ByteBuffer b) {
		assert b.remaining() >= MAC_LENGTH;
		b.position(b.limit() - MAC_LENGTH);
		b.put(mac(b));
	}

	private static int length (Node n) {
		return 32 + n.hostname.length();
	}

	private static void putNode (ByteBuffer b, Node n) {
		b.putLong(n.uuid0).putLong(n.uuid1).putLong(n.clock);
		b.put(n.endpoint.getAddress().getAddress());
		b.putShort((short) n.endpoint.getPort());
		b.put((byte) n.hostname.length());
		b.put(n.hostname.getBytes(ASCII));
		b.put((byte) n.tokencount);
	}

	private static int compare (Node x, Node y) {
		return compare(x.uuid0, x.uuid1, y.uuid0, y.uuid1);
	}

	private static void sort (Node[] a, int n) {
		// Insertion sort, see References.txt
		for (int i = 1; i < n; i++) {
			int j = i;
			Node x = a[j];
			while ((j != 0) && (compare(x, a[j - 1]) < 0)) {
				a[j] = a[j - 1];
				j--;
			}
			a[j] = x;
		}
	}

	private static void selectTarget (Digest d, Node n, int t) {
		if (!n.seed) {
			if (n.reachable) {
				if ((d.reachableTarget == null) || (random.nextInt(t) == 0)) {
					d.reachableTarget = n.endpoint;
				}
			} else {
				if ((d.unreachableTarget == null) || (random.nextInt(t) == 0)) {
					d.unreachableTarget = n.endpoint;
				}
			}
		}
	}

	private static int check (Node n, long t) {
		int state = NEUTRAL;
		if (n != localnode) {
			boolean r = n.reachable;
			long s = t - n.last;
			double m = n.size == 0? 1000: (double) n.sum / n.size;
			n.reachable = (n.size != 0) && (s <= m * PHI);
			if ((n.size != 0) && (s <= m * 2 * PHI)) {
				state = SELECTABLE;
			} else if (s > m * 6 * PHI) {
				state = DISPOSABLE;
			}
			if ((n.reachable != r) && (eventHandler != null)) {
				if (n.reachable) {
					eventHandler.nodeJoined(n.hostname, n.tokencount);
				} else {
					eventHandler.nodeLost(n.hostname, n.tokencount);
				}
			}
		}
		return state;
	}

	private static Digest digest () {
		// Random sampling with a reservoir, see References.txt
		Digest d = new Digest();
		Node p = null, n = nodes;
		long t = System.currentTimeMillis();
		while ((n != null) && (d.size < d.nodes.length - 1)) {
			int state = check(n, t);
			if (state == DISPOSABLE) {
				if (p == null) {
					nodes = n.next;
				} else {
					p.next = n.next;
				}
			} else {
				if (state == SELECTABLE) {
					selectTarget(d, n, d.size);
					d.nodes[d.size] = n;
					d.size++;
				}
				p = n;
			}
			n = n.next;
		}
		int s = d.size;
		while (n != null) {
			int state = check(n, t);
			if (state == DISPOSABLE) {
				if (p == null) {
					nodes = n.next;
				} else {
					p.next = n.next;
				}
			} else {
				if (state == SELECTABLE) {
					s++;
					selectTarget(d, n, s);
					int m = random.nextInt(s);
					if (m < d.nodes.length - 1) {
						d.nodes[m] = n;
					}
				}
				p = n;
			}
			n = n.next;
		}
		d.nodes[d.size] = localnode;
		d.size++;
		sort(d.nodes, d.size);
		return d;
	}

	private static void gossip (Digest d) {
		ByteBuffer b = ByteBuffer.allocate(DATAGRAM_LENGTH);
		b.put(DIGEST);
		b.put((byte) d.size);
		for (int i = 0; i != d.size; i++) {
			Node n = d.nodes[i];
			b.putLong(n.uuid0).putLong(n.uuid1).putLong(n.clock);
		}
		putMac(b);
		b.flip();
		if (d.reachableTarget != null) {
			outbox.offer(new Datagram(d.reachableTarget, b.duplicate()));
		}
		if (d.unreachableTarget != null) {
			outbox.offer(new Datagram(d.unreachableTarget, b.duplicate()));
		}
		for (InetSocketAddress seed: seeds) {
			outbox.offer(new Datagram(seed, b.duplicate()));
		}
	}

	private static void stamp (Node n) {
		long t = System.currentTimeMillis();
		if (n.last != 0) {
			long s = t - n.last;
			n.sum += s - n.samples[n.position];
			assert n.sum >= 0;
			n.samples[n.position] = s;
			n.position++;
			if (n.position == n.samples.length) {
				n.position = 0;
			}
			if (n.size != n.samples.length) {
				n.size++;
			}
		}
		n.last = t;
	}

	private static void handleValues (ByteBuffer b, InetSocketAddress source) {
		Node p = null, n = nodes;
		for (int i = b.get() & 0xff; i != 0; i--) {
			long uuid0 = b.getLong();
			long uuid1 = b.getLong();
			long clock = b.getLong();
			InetSocketAddress endpoint = getEndpoint(b);
			String hostname = getString(b);
			int tokencount = b.get();
			while ((n != null) && (compare(uuid0, uuid1, n.uuid0, n.uuid1) > 0)) {
				p = n;
				n = n.next;
			}
			if ((n != null) && (compare(uuid0, uuid1, n.uuid0, n.uuid1) == 0)) {
				if (clock > n.clock) {
					assert n != localnode;
					n.clock = clock;
					stamp(n);
				}
				p = n;
				n = n.next;
			} else {
				Node x = new Node();
				x.next = n;
				x.endpoint = endpoint;
				x.hostname = hostname;
				x.tokencount = tokencount;
				x.seed = contains(seeds, endpoint);
				x.uuid0 = uuid0;
				x.uuid1 = uuid1;
				x.clock = clock;
				stamp(x);
				if (p == null) {
					nodes = x;
				} else {
					p.next = x;
				}
				p = x;
			}
		}
	}

	private static void dispatch (InetSocketAddress a, ByteBuffer b) {
		putMac(b);
		b.flip();
		outbox.offer(new Datagram(a, b));
	}

	private static void handleDigest (ByteBuffer b, InetSocketAddress source) {
		ByteBuffer values = ByteBuffer.allocate(DATAGRAM_LENGTH);
		values.put(DELTA_VALUES);
		values.put((byte) 0);
		ByteBuffer digest = ByteBuffer.allocate(DATAGRAM_LENGTH);
		digest.put(DELTA_DIGEST);
		digest.put((byte) 0);
		Node n = nodes;
		for (int i = b.get() & 0xff; i != 0; i--) {
			long uuid0 = b.getLong();
			long uuid1 = b.getLong();
			long clock = b.getLong();
			while ((n != null) && (compare(uuid0, uuid1, n.uuid0, n.uuid1) > 0)) {
				n = n.next;
			}
			if ((n != null) && (compare(uuid0, uuid1, n.uuid0, n.uuid1) == 0)) {
				if (clock == 0) {
					if (values.remaining() < length(n) + MAC_LENGTH) {
						dispatch(source, values);
						values = ByteBuffer.allocate(DATAGRAM_LENGTH);
						values.put(DELTA_VALUES);
						values.put((byte) 0);
					}
					putNode(values, n);
					values.put(1, (byte) (values.get(1) + 1));
				} else if (clock < n.clock) {
					digest.putLong(n.uuid0).putLong(n.uuid1).putLong(n.clock);
					digest.put(1, (byte) (digest.get(1) + 1));
				} else if (clock > n.clock) {
					assert n != localnode;
					n.clock = clock;
					stamp(n);
				}
				n = n.next;
			} else {
				digest.putLong(uuid0).putLong(uuid1).putLong(0);
				digest.put(1, (byte) (digest.get(1) + 1));
			}
		}
		if (values.get(1) != 0) {
			dispatch(source, values);
		}
		if ((digest.get(1) != 0) && (b.get(0) == DIGEST)) {
			dispatch(source, digest);
		}
	}

	private static void handleDatagram (
		final ByteBuffer b, final InetSocketAddress source)
	{
		executor.execute(new Runnable() {
			public void run () {
				if (b.remaining() > MAC_LENGTH) {
					b.position(b.limit() - MAC_LENGTH);
					byte[] c = mac(b);
					int i = 0;
					while ((i != MAC_LENGTH) && (c[i] == b.get())) {
						i++;
					}
					if (i == MAC_LENGTH) {
						b.flip();
						byte x = b.get();
						if ((x == DIGEST) || (x == DELTA_DIGEST)) {
							handleDigest(b, source);
						} else if (x == DELTA_VALUES) {
							handleValues(b, source);
						}
						if (!outbox.isEmpty()) {
							selector.wakeup();
						}
					}
				}
			}
		});
	}

	private static void startGossip (
		final InetSocketAddress endpoint, final String hostname,
		final int tokencount, final InetSocketAddress[] seeds, final Mac mac)
	{
		executor.execute(new Runnable() {
			public void run () {
				Cluster.mac = mac;
				Cluster.seeds = seeds;
				UUID uuid = UUID.randomUUID();
				localnode = new Node();
				localnode.endpoint = endpoint;
				localnode.hostname = hostname;
				localnode.tokencount = tokencount;
				localnode.seed = contains(seeds, endpoint);
				localnode.uuid0 = uuid.getMostSignificantBits();
				localnode.uuid1 = uuid.getLeastSignificantBits();
				localnode.clock++;
				nodes = localnode;
				executor.scheduleWithFixedDelay(new Runnable() {
					public void run () {
						localnode.clock++;
						gossip(digest());
						if (!outbox.isEmpty()) {
							selector.wakeup();
						}
					}
				}, 1, 1, TimeUnit.SECONDS);
			}
		});
	}

	public static void join (
		final InetSocketAddress endpoint, String hostname,
		int tokencount, InetSocketAddress[] seeds, Mac mac)
	{
		assert endpoint != null;
		assert endpoint.getAddress().getAddress().length == 4;
		assert hostname != null;
		assert hostname.length() < 256;
		assert tokencount >= 0;
		assert tokencount < 256;
		assert seeds != null;
		assert mac != null;
		assert mac.getMacLength() == MAC_LENGTH;
		startGossip(endpoint, hostname, tokencount, seeds, mac);
		Tasks.newSingleThreadExecutor().execute(new Runnable() {
			public void run () {
				DatagramChannel c;
				try {
					c = DatagramChannel.open();
					c.configureBlocking(false);
					c.socket().setReuseAddress(true);
					c.socket().bind(endpoint);
				} catch (Exception e) { throw new Error(e); }
				while (true) {
					try {
						c.register(selector, outbox.isEmpty()?
							SelectionKey.OP_READ:
							SelectionKey.OP_READ | SelectionKey.OP_WRITE);
						selector.select();
					} catch (Exception e) { throw new Error(e); }
					for (SelectionKey k: selector.selectedKeys()) {
						if (k.isValid()) {
							int readyOps = k.readyOps();
							if ((readyOps & SelectionKey.OP_READ) != 0) {
								Object source = null;
								ByteBuffer b = ByteBuffer.allocate(DATAGRAM_LENGTH);
								try {
									source = c.receive(b);
								} catch (IOException e) {}
								if (source != null) {
									b.flip();
									handleDatagram(b, (InetSocketAddress) source);
								}
							}
							if ((readyOps & SelectionKey.OP_WRITE) != 0) {
								Datagram d = outbox.poll();
								try {
									c.send(d.data, d.target);
								} catch (IOException e) {}
							}
						}
					}
					selector.selectedKeys().clear();
				}
			}
		});
	}

	public static void register (final EventHandler h) {
		executor.execute(new Runnable() {
			public void run () {
				eventHandler = h;
				if (eventHandler != null) {
					for (Node n = nodes; n != null; n = n.next) {
						if (n.reachable) {
							eventHandler.nodeJoined(n.hostname, n.tokencount);
						}
					}
				}
			}
		});
	}
}
