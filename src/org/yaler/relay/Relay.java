// Copyright (c) 2011, Yaler GmbH, Switzerland
// All rights reserved

package org.yaler.relay;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Comparator;
import java.util.Date;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.TimeZone;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import org.yaler.core.Cluster;
import org.yaler.core.Cluster.EventHandler;
import org.yaler.core.Connections.CompletionHandler;
import org.yaler.core.Connections.Connection;
import org.yaler.core.Dispatcher;
import org.yaler.core.StateMachines.State;
import org.yaler.core.StateMachines.StateMachine;
import org.yaler.core.Tasks;
import org.yaler.core.Tasks.Executor;

public final class Relay {
	private Relay () {}

	private static final char[] DIGITS = "0123456789abcdef".toCharArray();

	// Consistent hash ring, see References.txt
	private static final ConcurrentSkipListMap<byte[], String>
		ring = new ConcurrentSkipListMap<byte[], String>(new Comparator<byte[]>() {
			public int compare (byte[] x, byte[] y) {
				int i = 0, nx = x.length, ny = y.length, s = 0;
				while ((i != nx) && (i != ny) && (s == 0)) {
					s = (x[i] & 0xff) - (y[i] & 0xff);
					i++;
				}
				return s != 0? s: nx - ny;
			}
		});

	private static volatile String hostname, root;
	private static volatile Semaphore capacity;

	private static String timestamp () {
		SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
		f.setTimeZone(TimeZone.getTimeZone("UTC"));
		return f.format(new Date());
	}

	private static Entry<byte[], String> ceilingRingEntry (byte[] key) {
		Entry<byte[], String> e = ring.ceilingEntry(key);
		if (e == null) {
			e = ring.firstEntry();
		}
		return e;
	}

	private static void logRing () {
		StringBuilder s = new StringBuilder();
		s.append(timestamp());
		s.append(":");
		s.append("{\"ring\":[");
		int n = 0;
		for (Entry<byte[], String> e: ring.entrySet()) {
			if (n != 0) {
				s.append(",");
			}
			s.append("{\"key\":\"");
			byte[] key = e.getKey();
			for (int i = 0; i != key.length; i++) {
				s.append(DIGITS[(key[i] >> 4) & 0xf]);
				s.append(DIGITS[(key[i] >> 0) & 0xf]);
			}
			s.append("\",\"value\":\"");
			s.append(e.getValue());
			s.append("\"}");
			n++;
		}
		s.append("]}");
		System.out.println(s.toString());
	}

	private static byte[] bytes (String s) {
		try {
			return s.getBytes("US-ASCII");
		} catch (Exception e) { throw new Error(e); }
	}

	private static MessageDigest sha1 () {
		try {
			return MessageDigest.getInstance("SHA1");
		} catch (Exception e) { throw new Error(e); }
	}

	private static final class Handler {
		static final Object
			SIGNAL = new Object();
		static final int // handler states
			RECEIVING = 1, CONNECTING = 2, ACCEPTING = 3, RENEWING = 4, UPGRADING = 5,
			RELAYING = 6, SENDING = 7, CLOSED = 8,
			MARKED = 1 << 30, SIGNALED = 1 << 31;
		static final int
			HT = 9, LF = 10, CR = 13, SP = 32;
		static final byte[]
			HTTP101 = new byte[] {
				'H','T','T','P','/','1','.','1', SP,'1','0','1', SP, CR, LF,'U','p','g',
				'r','a','d','e',':', SP,'P','T','T','H','/','1','.','0', CR, LF,'C','o',
				'n','n','e','c','t','i','o','n',':', SP,'U','p','g','r','a','d','e', CR,
				 LF, CR, LF},
			HTTP204 = new byte[] {
				'H','T','T','P','/','1','.','1', SP,'2','0','4', SP, CR, LF, CR, LF},
			HTTP504 = new byte[] {
				'H','T','T','P','/','1','.','1', SP,'5','0','4', SP, CR, LF, CR, LF},
			HTTP307 = new byte[] {
				'H','T','T','P','/','1','.','1', SP,'3','0','7', SP, CR, LF,'L','o','c',
				'a','t','i','o','n',':', SP},
			CRLF_CRLF = new byte[] {CR, LF, CR, LF};

		static final class SendCompletion {
			Connection connection;
			ByteBuffer buffer;
			boolean error;
		}

		static final class ReceiveCompletion {
			Connection connection;
			ByteBuffer buffer;
			boolean error;
		}

		static final class Client {
			Connection connection;
			ByteBuffer buffer;
		}

		static final AtomicLong
			count = new AtomicLong();
		static final ConcurrentLinkedQueue<Handler>
			handlers = new ConcurrentLinkedQueue<Handler>();
		static final Executor
			executor = newSingleThreadExecutor();

		final long
			ID = count.getAndIncrement();
		final StateMachine
			stateMachine = new StateMachine();
		Connection connection;
		InetSocketAddress endpoint;
		volatile int state;
		volatile Object domain;
		volatile byte[] hash;
		volatile Client client;
		volatile long inflow, outflow;

		static void signal (Handler h) {
			h.state = SIGNALED | h.state;
			Dispatcher.dispatch(h.stateMachine, SIGNAL);
		}

		static Executor newSingleThreadExecutor () {
			Executor e = Tasks.newSingleThreadExecutor();
			e.scheduleWithFixedDelay(new Runnable() {
				StringBuilder s = new StringBuilder();
				int n, m;
				public void run () {
					if (n == 0) {
						m = 0;
						logRing();
						s.setLength(0);
						s.append(timestamp());
						s.append(":");
						s.append("{\"connections\":[");
					}
					Iterator<Handler> i = handlers.iterator();
					while (i.hasNext()) {
						Handler h = i.next();
						if (n == 0) {
							if (m != 0) {
								s.append(",");
							}
							s.append("{\"id\":");
							s.append(String.valueOf(h.ID));
							s.append(",\"domain\":\"");
							s.append(String.valueOf(h.domain));
							s.append("\",\"state\":\"");
							s.append(String.valueOf(h.state));
							s.append("\",\"inflow\":");
							s.append(String.valueOf(h.inflow));
							s.append("\",\"outflow\":");
							s.append(String.valueOf(h.outflow));
							s.append("}");
							if (h.state == CLOSED) {
								i.remove();
							} else if (h.state != (MARKED | h.state)) {
								h.state = MARKED | h.state;
							} else if (h.state != (SIGNALED | h.state)) {
								signal(h);
							}
							m++;
						}
						if ((h.state == ACCEPTING) || (h.state == (MARKED | ACCEPTING))) {
							Entry<byte[], String> e = ceilingRingEntry(h.hash);
							if ((e == null) || (e.getValue() != hostname)) {
								signal(h);
							}
						}
					}
					if (n == 0) {
						s.append("]}");
						System.out.println(s.toString());
					}
					n = (n + 1) % 6;
				}
			}, 0, 5, TimeUnit.SECONDS);
			return e;
		}

		Handler (Connection connection, InetSocketAddress endpoint) {
			this.connection = connection;
			this.endpoint = endpoint;
			Dispatcher.start(stateMachine, receiving);
			handlers.offer(this);
		}

		final CompletionHandler sendCompleted = new CompletionHandler() {
			public void handle (Connection c, ByteBuffer b, boolean error) {
				SendCompletion sc = new SendCompletion();
				sc.connection = c;
				sc.buffer = b;
				sc.error = error;
				Dispatcher.dispatch(stateMachine, sc);
			}
		};

		final CompletionHandler receiveCompleted = new CompletionHandler() {
			public void handle (Connection c, ByteBuffer b, boolean error) {
				ReceiveCompletion rc = new ReceiveCompletion();
				rc.connection = c;
				rc.buffer = b;
				rc.error = error;
				Dispatcher.dispatch(stateMachine, rc);
			}
		};

		final State open = new State() {
			void close (Connection c) {
				capacity.release();
				c.shutdownOutput();
				c.close();
			}

			public void handle (StateMachine m, Object o) {
				if (o == SIGNAL) {
					m.transitionTo(closed);
				} else if (o == EXIT) {
					if (connection != null) {
						close(connection);
						connection = null;
					}
					if (client != null) {
						close(client.connection);
						client = null;
					}
				} else {
					m.upwardTo(TOP);
				}
			}
		};

		final State receiving = new State() {
			static final int // parser states
				BEFORE_TARGET = 0, HOST = 1, TARGET_DOMAIN = 2, TARGET = 3,
				AFTER_TARGET = 4, UPGRADE_HEADER = 5, UPGRADE_HEADER_LF = 6,
				HOST_HEADER = 7, DONE = 8;

			int parserState, parserPosition, targetPosition, targetLength,
				hostPosition, hostLength;
			boolean upgrade;

			int compare (ByteBuffer x, int offset, int length, String y) {
				int i = 0, nx = length, ny = y.length(), s = 0;
				while ((i != nx) && (i != ny) && (s == 0)) {
					s = (x.get(offset + i) & 0xff) - (y.charAt(i) & 0xff);
					i++;
				}
				return s != 0? s: nx - ny;
			}

			void parse (ByteBuffer b) {
				assert parserState != DONE;
				int s = parserState;
				int p = parserPosition;
				int q = b.position();
				do {
					int x = b.get(p);
					if (s == BEFORE_TARGET) {
						if (x == ':') {
							hostPosition = p + 1;
							s = HOST;
						} else if (x == '/') {
							domain = new StringBuilder("/");
							targetPosition = p;
							s = TARGET_DOMAIN;
						}
					} else if (s == HOST) {
						if (x == '/') {
							if (p == hostPosition) {
								hostPosition++;
							} else {
								domain = new StringBuilder("/");
								targetPosition = p;
								s = TARGET_DOMAIN;
							}
						} else if (x == ':') {
							s = BEFORE_TARGET;
						} else {
							hostLength++;
						}
					} else if (s == TARGET_DOMAIN) {
						StringBuilder d = (StringBuilder) domain;
						if (('a' <= x) && (x <= 'z') || ('0' <= x) && (x <= '9')
							|| (x == '-') || (x == '.') || (x == '_') || (x == '~')
							|| (x == '%') || (x == '!') || (x == '$') || (x == '&')
							|| (x == '\'')|| (x == '(') || (x == ')') || (x == '*')
							|| (x == '+') || (x == ',') || (x == ';') || (x == '='))
						{
							d.append((char) x);
						} else if (('A' <= x) && (x <= 'Z')) {
							d.append((char) (x + 32));
						} else {
							domain = d.toString();
							if ((x == SP) || (x == HT) || (x == LF) || (x == CR)) {
								targetLength = p - targetPosition;
								s = AFTER_TARGET;
							} else {
								s = TARGET;
							}
						}
					} else if (s == TARGET) {
						if ((x == SP) || (x == HT) || (x == LF) || (x == CR)) {
							targetLength = p - targetPosition;
							s = AFTER_TARGET;
						}
					} else if (s == AFTER_TARGET) {
						if (x == LF) {
							if ((p >= 1) && (b.get(p - 1) == LF)
								|| (p >= 2) && (b.get(p - 2) == LF))
							{
								s = DONE;
							}
						} else if (x == ':') {
							if ((p >= 8) && (b.get(p - 8) == LF)
								&& ((b.get(p - 7) == 'U') || (b.get(p - 7) == 'u'))
								&& ((b.get(p - 6) == 'p') || (b.get(p - 6) == 'P'))
								&& ((b.get(p - 5) == 'g') || (b.get(p - 5) == 'G'))
								&& ((b.get(p - 4) == 'r') || (b.get(p - 4) == 'R'))
								&& ((b.get(p - 3) == 'a') || (b.get(p - 3) == 'A'))
								&& ((b.get(p - 2) == 'd') || (b.get(p - 2) == 'D'))
								&& ((b.get(p - 1) == 'e') || (b.get(p - 1) == 'E')))
							{
								s = UPGRADE_HEADER;
							} else if ((p >= 17) && (b.get(p - 17) == LF)
								&& ((b.get(p - 16) == 'X') || (b.get(p - 16) == 'x'))
								&& (b.get(p - 15) == '-')
								&& ((b.get(p - 14) == 'R') || (b.get(p - 14) == 'r'))
								&& ((b.get(p - 13) == 'e') || (b.get(p - 13) == 'E'))
								&& ((b.get(p - 12) == 'l') || (b.get(p - 12) == 'L'))
								&& ((b.get(p - 11) == 'a') || (b.get(p - 11) == 'A'))
								&& ((b.get(p - 10) == 'y') || (b.get(p - 10) == 'Y'))
								&& (b.get(p - 9) == '-')
								&& ((b.get(p - 8) == 'P') || (b.get(p - 8) == 'p'))
								&& ((b.get(p - 7) == 'r') || (b.get(p - 7) == 'R'))
								&& ((b.get(p - 6) == 'o') || (b.get(p - 6) == 'O'))
								&& ((b.get(p - 5) == 't') || (b.get(p - 5) == 'T'))
								&& ((b.get(p - 4) == 'o') || (b.get(p - 4) == 'O'))
								&& ((b.get(p - 3) == 'c') || (b.get(p - 3) == 'C'))
								&& ((b.get(p - 2) == 'o') || (b.get(p - 2) == 'O'))
								&& ((b.get(p - 1) == 'l') || (b.get(p - 1) == 'L')))
							{
								s = UPGRADE_HEADER;
							} else if ((p >= 5) && (b.get(p - 5) == LF)
								&& ((b.get(p - 4) == 'H') || (b.get(p - 4) == 'h'))
								&& ((b.get(p - 3) == 'o') || (b.get(p - 3) == 'O'))
								&& ((b.get(p - 2) == 's') || (b.get(p - 2) == 'S'))
								&& ((b.get(p - 1) == 't') || (b.get(p - 1) == 'T')))
							{
								if (hostLength == 0) {
									s = HOST_HEADER;
									hostPosition = p + 1;
								}
							}
						}
					} else if (s == UPGRADE_HEADER) {
						if ((x == ',') || (x == SP) || (x == HT) || (x == LF) || (x == CR))
						{
							if (p >= 9) {
								int y = b.get(p - 9);
								if (((y == ':') || (y == ',') || (y == SP) || (y == HT))
									&& (b.get(p - 8) == 'P') && (b.get(p - 7) == 'T')
									&& (b.get(p - 6) == 'T') && (b.get(p - 5) == 'H')
									&& (b.get(p - 4) == '/') && (b.get(p - 3) == '1')
									&& (b.get(p - 2) == '.') && (b.get(p - 1) == '0'))
								{
									upgrade = true;
								}
							}
							if (x == LF) {
								s = UPGRADE_HEADER_LF;
							}
						}
					} else if (s == UPGRADE_HEADER_LF) {
						if ((x == SP) || (x == HT)) {
							s = UPGRADE_HEADER;
						} else if (x == LF) {
							s = DONE;
						} else {
							s = AFTER_TARGET;
						}
					} else {
						assert s == HOST_HEADER;
						if ((x == SP) || (x == HT)) {
							if (p == hostPosition) {
								hostPosition++;
							} else {
								s = AFTER_TARGET;
							}
						} else if ((x == ':') || (x == LF) || (x == CR)) {
							s = AFTER_TARGET;
						} else {
							hostLength++;
						}
					}
					p++;
				} while ((p != q) && (s != DONE));
				parserPosition = p;
				parserState = s;
			}

			public void handle (StateMachine m, Object o) {
				if (o == ENTER) {
					state = RECEIVING;
					domain = null;
					parserState = 0;
					parserPosition = 0;
					targetPosition = 0;
					targetLength = 0;
					hostPosition = 0;
					hostLength = 0;
					upgrade = false;
					connection.receive(null, receiveCompleted);
				} else if (o instanceof ReceiveCompletion) {
					ReceiveCompletion rc = (ReceiveCompletion) o;
					if (!rc.error) {
						ByteBuffer b = rc.buffer;
						parse(b);
						if (parserState != DONE) {
							if (b.position() < 2048) {
								state = RECEIVING;
								connection.receive(b, receiveCompleted);
							} else {
								m.transitionTo(closed);
							}
						} else {
							byte[] h = sha1().digest(bytes((String) domain));
							Entry<byte[], String> e = ceilingRingEntry(h);
							if (e != null) {
								if ((e.getValue() == hostname) && ((hostname == "")
									|| (compare(b, hostPosition, hostLength, hostname) == 0)))
								{
									if (upgrade) {
										hash = h;
										m.transitionTo(accepting);
									} else {
										if ((root != null) && domain.equals("/")) {
											byte[] location = bytes(root);
											ByteBuffer redirection = ByteBuffer.allocate(
												HTTP307.length + location.length + 4);
											redirection.put(HTTP307).put(location);
											redirection.put(CRLF_CRLF).flip();
											connection.send(redirection, sendCompleted);
											m.transitionTo(sending);
										} else {
											b.flip();
											client = new Client();
											client.connection = connection;
											client.buffer = b;
											connection = null;
											m.transitionTo(connecting);
										}
									}
								} else {
									byte[] location = bytes(
										(connection.isSecure()? "https://": "http://")
										+ e.getValue() + ":" + endpoint.getPort());
									ByteBuffer redirection = ByteBuffer.allocate(
										HTTP307.length + location.length + targetLength + 4);
									redirection.put(HTTP307).put(location);
									int p = targetPosition, q = p + targetLength;
									while (p != q) {
										redirection.put(b.get(p));
										p++;
									}
									redirection.put(CRLF_CRLF).flip();
									connection.send(redirection, sendCompleted);
									m.transitionTo(sending);
								}
							} else {
								m.transitionTo(closed);
							}
						}
					} else {
						m.transitionTo(closed);
					}
				} else {
					m.upwardTo(open);
				}
			}
		};

		final State connecting = new State() {
			public void handle (StateMachine m, Object o) {
				if (o == ENTER) {
					state = CONNECTING;
					final Object clientDomain = domain;
					executor.execute(new Runnable() {
						public void run () {
							Handler server = null;
							Iterator<Handler> i = handlers.iterator();
							while ((server == null) && i.hasNext()) {
								Handler h = i.next();
								if (
									((h.state == ACCEPTING) || (h.state == (MARKED | ACCEPTING)))
									&& h.domain.equals(clientDomain))
								{
									server = h;
									h.client = client;
									client = null;
									signal(h);
								}
							}
							Dispatcher.dispatch(stateMachine, server);
						}
					});
				} else if (o instanceof Handler) {
					m.transitionTo(closed);
				} else if (o == null) {
					client.connection.send(ByteBuffer.wrap(HTTP504), sendCompleted);
					m.transitionTo(sending);
				} else if (o != SIGNAL) {
					m.upwardTo(open);
				}
			}
		};

		final State accepting = new State() {
			public void handle (StateMachine m, Object o) {
				if (o == ENTER) {
					state = ACCEPTING;
				} else if (o == SIGNAL) {
					if (client == null) {
						m.transitionTo(renewing);
					} else {
						m.transitionTo(upgrading);
					}
				} else {
					m.upwardTo(open);
				}
			}
		};

		final State renewing = new State() {
			public void handle (StateMachine m, Object o) {
				if (o == ENTER) {
					state = RENEWING;
					connection.send(ByteBuffer.wrap(HTTP204), sendCompleted);
				} else if (o instanceof SendCompletion) {
					SendCompletion sc = (SendCompletion) o;
					if (!sc.error) {
						m.transitionTo(receiving);
					} else {
						m.transitionTo(closed);
					}
				} else {
					m.upwardTo(open);
				}
			}
		};

		final State upgrading = new State() {
			public void handle (StateMachine m, Object o) {
				if (o == ENTER) {
					state = UPGRADING;
					connection.send(ByteBuffer.wrap(HTTP101), sendCompleted);
				} else if (o instanceof SendCompletion) {
					SendCompletion sc = (SendCompletion) o;
					if (!sc.error) {
						m.transitionTo(relaying);
					} else {
						m.transitionTo(connecting);
					}
				} else {
					m.upwardTo(open);
				}
			}
		};

		final State relaying = new State() {
			boolean error;

			Connection peer (Connection c) {
				Connection result;
				if (c == connection) {
					result = client.connection;
				} else {
					assert c == client.connection;
					result = connection;
				}
				return result;
			}

			public void handle (StateMachine m, Object o) {
				if (o == ENTER) {
					state = RELAYING;
					error = false;
					inflow += client.buffer.remaining();
					connection.send(client.buffer, sendCompleted);
					connection.receive(null, receiveCompleted);
					client.buffer = null;
				} else if (o instanceof SendCompletion) {
					SendCompletion sc = (SendCompletion) o;
					if (!sc.error) {
						ByteBuffer b = sc.buffer;
						outflow += b.position();
						b.clear();
						state = RELAYING;
						peer(sc.connection).receive(b, receiveCompleted);
					} else if (!error) {
						error = true;
					} else {
						m.transitionTo(closed);
					}
				} else if (o instanceof ReceiveCompletion) {
					ReceiveCompletion rc = (ReceiveCompletion) o;
					if (!rc.error) {
						ByteBuffer b = rc.buffer;
						inflow += b.position();
						b.flip();
						state = RELAYING;
						peer(rc.connection).send(b, sendCompleted);
					} else if (!error) {
						peer(rc.connection).shutdownOutput();
						error = true;
					} else {
						m.transitionTo(closed);
					}
				} else {
					m.upwardTo(open);
				}
			}
		};

		final State sending = new State() {
			public void handle (StateMachine m, Object o) {
				if (o == ENTER) {
					state = SENDING;
				} else if (o instanceof SendCompletion) {
					m.transitionTo(closed);
				} else {
					m.upwardTo(open);
				}
			}
		};

		final State closed = new State() {
			public void handle (StateMachine m, Object o) {
				if (o == ENTER) {
					state = CLOSED;
				}
			}
		};
	}

	public static void open (
		final InetSocketAddress endpoint, final SSLContext sslc)
	{
		assert endpoint != null;
		Tasks.newSingleThreadExecutor().execute(new Runnable() {
			public void run () {
				ServerSocketChannel sc;
				try {
					sc = ServerSocketChannel.open();
					sc.socket().setReuseAddress(true);
					sc.socket().bind(endpoint, 64);
				} catch (Exception e) { throw new Error(e); }
				while (true) {
					SocketChannel c;
					try {
						capacity.acquire();
						c = sc.accept();
						c.configureBlocking(false);
						c.socket().setTcpNoDelay(true);
					} catch (Exception e) { throw new Error(e); }
					SSLEngine e = null;
					if (sslc != null) {
						e = sslc.createSSLEngine();
						e.setUseClientMode(false);
					}
					new Handler(new Connection(c, e), endpoint);
				}
			}
		});
	}

	public static void init (
		String hostname, String root, int capacity, int tokencount)
	{
		assert capacity >= 0;
		if (hostname == null) {
			hostname = "";
		}
		Relay.hostname = hostname;
		Relay.root = root;
		Relay.capacity = new Semaphore(capacity, true);
		MessageDigest d = sha1();
		for (int i = 0; i < tokencount; i++) {
			d.reset();
			ring.put(d.digest(bytes(hostname + "." + i)), hostname);
		}
		logRing();
		Cluster.register(new EventHandler() {
			public void nodeJoined (String hostname, int tokencount) {
				MessageDigest d = sha1();
				for (int i = 0; i < tokencount; i++) {
					d.reset();
					ring.put(d.digest(bytes(hostname + "." + i)), hostname);
				}
				logRing();
			}
			public void nodeLost (String hostname, int tokencount) {
				MessageDigest d = sha1();
				for (int i = 0; i < tokencount; i++) {
					d.reset();
					ring.remove(d.digest(bytes(hostname + "." + i)));
				}
				logRing();
			}
		});
	}
}
