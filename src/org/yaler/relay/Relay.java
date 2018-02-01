// Copyright (c) 2010 - 2018, Yaler Gmbh, Switzerland. All rights reserved.

package org.yaler.relay;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
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

	private static final boolean
		LOGGING_LEVEL_OFF = Boolean.getBoolean(
			"yaler.relay.logging_level_off");

	private static final int
		DATAGRAM_BUFFER_SIZE =
			16512; // max. DTLSPlaintext.length (2^14 bytes) + protocol overhead

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

	private static volatile String[] hostnames;
	private static volatile String root;
	private static volatile Semaphore capacity;

	private static void log (String s) {
		if (!LOGGING_LEVEL_OFF) {
			System.out.print(s.toString());
		}
	}

	private static String stamp () {
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
		s.append("{\"stamp\":\"");
		s.append(stamp());
		s.append("\",\"ring\":[");
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
		s.append("]}\n");
		log(s.toString());
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

	private static int compare (ByteBuffer x, int offset, int length, String y) {
		int i = 0, nx = length, ny = y.length(), s = 0;
		while ((i != nx) && (i != ny) && (s == 0)) {
			s = (x.get(offset + i) & 0xff) - (y.charAt(i) & 0xff);
			i++;
		}
		return s != 0? s: nx - ny;
	}

	private static String getSubdomain (
		ByteBuffer b, int offset, int length)
	{
		String result = null;
		if ((hostnames[0] != "") && (length != 0)
			&& !isHostIPv4Address(b, offset, length))
		{
			int i = 0;
			int j = hostnames.length;
			while ((i != j) && (compare(b, offset, length, hostnames[i]) != 0)) {
				i++;
			}
			if (i == j) {
				StringBuilder r = new StringBuilder("/");
				int p = offset;
				int q = p + length;
				while ((p != q) && (b.get(p) != '.')) {
					int x = b.get(p);
					if (('A' <= x) && (x <= 'Z')) {
						r.append((char) (x + 32));
					} else {
						r.append((char) x);
					}
					p++;
				}
				if (r.length() > 1) {
					int n = 0;
					while (p != q) {
						n++;
						do {
							p++;
						} while ((p != q) && (b.get(p) != '.'));
					}
					if (n >= 2) {
						result = r.toString();
					}
				}
			}
		}
		return result;
	}

	private static int readDigits (ByteBuffer b, int offset, int length) {
		int i = offset;
		int j = offset + length;
		if (i != j) {
			int x;
			do {
				x = b.get(i);
				if (('0' <= x) && (x <= '9')) {
					i++;
				} else {
					x = -1;
				}
			} while ((x != -1) && (i != j));
		}
		return i - offset;
	}

	private static int readDecOctet (ByteBuffer b, int offset, int length) {
		int i = offset;
		int j = offset + length;
		if (i != j) {
			int x = b.get(i);
			if (x == '0') {
				i++;
			} else if (x == '1') {
				i++;
				if (i != j) {
					x = b.get(i);
					if (('0' <= x) && (x <= '9')) {
						i++;
						if (i != j) {
							x = b.get(i);
							if (('0' <= x) && (x <= '9')) {
								i++;
							}
						}
					}
				}
			} else if (x == '2') {
				i++;
				if (i != j) {
					x = b.get(i);
					if (('0' <= x) && (x <= '4')) {
						i++;
						if (i != j) {
							x = b.get(i);
							if (('0' <= x) && (x <= '9')) {
								i++;
							}
						}
					} else if (x == '5') {
						i++;
						if (i != j) {
							x = b.get(i);
							if (('0' <= x) && (x <= '5')) {
								i++;
							}
						}
					}
				}
			} else if (('3' <= x) && (x <= '9')) {
				i++;
				if (i != j) {
					x = b.get(i);
					if (('0' <= x) && (x <= '9')) {
						i++;
					}
				}
			}
		}
		return i - offset;
	}

	private static boolean isHostIPv4Address (
		ByteBuffer b, int offset, int length)
	{
		boolean result = false;
		int i = offset;
		int j = offset + length;
		int n = readDecOctet(b, i, j - i);
		if ((n > 0) && (i < j - n) && (b.get(i + n) == '.')) {
			i += n + 1;
			n = readDecOctet(b, i, j - i);
			if ((n > 0) && (i < j - n) && (b.get(i + n) == '.')) {
				i += n + 1;
				n = readDecOctet(b, i, j - i);
				if ((n > 0) && (i < j - n) && (b.get(i + n) == '.')) {
					i += n + 1;
					n = readDecOctet(b, i, j - i);
					if (n > 0) {
						if ((i < j - n) && (b.get(i + n) == ':')) {
							i += n + 1;
							n = readDigits(b, i, j - i);
							if ((n > 0) && (i == j - n)) {
								result = true;
							}
						} else if (i == j - n) {
							result = true;
						}
					}
				}
			}
		}
		return result;
	}

	private static final class ConnectionHandler {
		static final Object
			SIGNAL = new Object();
		static final int // handler states
			STATE_RECEIVING = 1,
			STATE_CONNECTING = 2,
			STATE_COUNTING = 3,
			STATE_ACCEPTING = 4,
			STATE_RENEWING = 5,
			STATE_UPGRADING = 6,
			STATE_RELAYING_STREAMS = 7,
			STATE_RELAYING_DATAGRAMS = 8,
			STATE_SENDING = 9,
			STATE_CLOSING = 10,
			STATE_CLOSED = 11;
		static final int // context values for transitions to state 'closed'
			CONTEXT_SIGNALED = 1,
			CONTEXT_RECEIVING_REQUEST_TOO_LARGE = 2,
			CONTEXT_RECEIVING_NODE_NOT_FOUND = 3,
			CONTEXT_RECEIVING_RECEIVE_COMPLETION_ERROR = 4,
			CONTEXT_CONNECTING = 5,
			CONTEXT_COUNTING = 6,
			CONTEXT_RENEWING = 7,
			CONTEXT_UPGRADING = 8,
			CONTEXT_RELAYING_STREAMS = 9,
			CONTEXT_RELAYING_STREAMS_SENDING = 10,
			CONTEXT_RELAYING_STREAMS_SEND_COMPLETION_ERROR = 11,
			CONTEXT_RELAYING_STREAMS_RECEIVE_COMPLETION_ERROR = 12,
			CONTEXT_RELAYING_DATAGRAMS_SEND_COMPLETION_ERROR = 13,
			CONTEXT_RELAYING_DATAGRAMS_RECEIVE_COMPLETION_ERROR = 14,
			CONTEXT_SENDING = 15,
			CONTEXT_SENDING_SEND_COMPLETION_ERROR = 16,
			CONTEXT_CLOSING = 17;
		static final int // relay protocol values
			PROTOCOL_CLIENT = 0,
			PROTOCOL_PTTH = 1,
			PROTOCOL_DPTTH = 2;
		static final int // relay security values
			TRANSPORT_PASSTHROUGH = 1;
		static final int
			HT = 9, LF = 10, CR = 13, SP = 32;
		static final byte[]
			HTTP101_PTTH = new byte[] {
				'H','T','T','P','/','1','.','1', SP,'1','0','1', SP, CR, LF,'U','p','g',
				'r','a','d','e',':', SP,'P','T','T','H','/','1','.','0', CR, LF,'C','o',
				'n','n','e','c','t','i','o','n',':', SP,'U','p','g','r','a','d','e', CR,
				 LF, CR, LF},
			HTTP101_DPTTH = new byte[] {
				'H','T','T','P','/','1','.','1', SP,'1','0','1', SP, CR, LF,'U','p','g',
				'r','a','d','e',':', SP,'D','P','T','T','H','/','1','.','0', CR, LF,'C',
				'o','n','n','e','c','t','i','o','n',':', SP,'U','p','g','r','a','d','e',
				 CR, LF, CR, LF},
			HTTP204 = new byte[] {
				'H','T','T','P','/','1','.','1', SP,'2','0','4', SP, CR, LF, CR, LF},
			HTTP307 = new byte[] {
				'H','T','T','P','/','1','.','1', SP,'3','0','7', SP, CR, LF,'L','o','c',
				'a','t','i','o','n',':', SP},
			HTTP401 = new byte[] {
				'H','T','T','P','/','1','.','1', SP,'4','0','1', SP, CR, LF,'W','W','W',
				'-','A','u','t','h','e','n','t','i','c','a','t','e',':', SP,'B','e','a',
				'r','e','r', CR, LF, CR, LF},
			HTTP504 = new byte[] {
				'H','T','T','P','/','1','.','1', SP,'5','0','4', SP, CR, LF, CR, LF},
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

		static final class ShutdownCompletion {
			Connection connection;
			ByteBuffer buffer;
			boolean error;
		}

		static final class StreamClient {
			Connection connection;
			SSLEngine sslEngine;
			ByteBuffer buffer;
		}

		static final class DatagramClient {
			InetSocketAddress endpoint;
			DatagramHandler datagramHandler;
		}

		static final AtomicLong
			count = new AtomicLong();
		static final ConcurrentLinkedQueue<ConnectionHandler>
			handlers = new ConcurrentLinkedQueue<ConnectionHandler>();
		static final Executor
			executor = newSingleThreadExecutor();

		final long
			ID = count.getAndIncrement();
		final StateMachine
			stateMachine = new StateMachine();
		final String localHost;
		final String remoteHost;
		final int localPort;
		final int remotePort;
		Connection connection;
		SSLEngine sslEngine;
		boolean handshaking;
		volatile int state;
		volatile int context;
		volatile boolean marked;
		volatile boolean signaled;
		volatile Object domain;
		volatile byte[] hash;
		volatile int protocol;
		volatile int security;
		volatile Object client;
		volatile long inflow;
		volatile long outflow;

		static void mark (ConnectionHandler h) {
			assert !h.marked;
			h.marked = true;
		}

		static void signal (ConnectionHandler h) {
			assert !h.signaled;
			h.signaled = true;
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
						s.append("{\"begin\":\"");
						s.append(stamp());
						s.append("\",\"connections\":[");
					}
					Iterator<ConnectionHandler> i = handlers.iterator();
					while (i.hasNext()) {
						ConnectionHandler h = i.next();
						if (n == 0) {
							if (m != 0) {
								s.append(",");
							}
							s.append("{\"id\":");
							s.append(h.ID);
							s.append(",\"local\":\"");
							s.append(h.localHost);
							s.append(":");
							s.append(h.localPort);
							s.append("\",\"remote\":\"");
							s.append(h.remoteHost);
							s.append(":");
							s.append(h.remotePort);
							s.append("\",\"domain\":\"");
							s.append(h.domain);
							s.append("\",\"state\":");
							s.append(h.state);
							s.append(",\"context\":");
							s.append(h.context);
							s.append(",\"protocol\":");
							s.append(h.protocol);
							s.append(",\"security\":");
							s.append(h.security);
							s.append(",\"inflow\":");
							s.append(h.inflow);
							s.append(",\"outflow\":");
							s.append(h.outflow);
							s.append("}");
							if (h.state == STATE_CLOSED) {
								i.remove();
							} else if (!h.marked) {
								mark(h);
							} else if (!h.signaled) {
								signal(h);
							}
							m++;
						}
						if ((h.state == STATE_ACCEPTING) && !h.signaled) {
							Entry<byte[], String> e = ceilingRingEntry(h.hash);
							if ((e == null) || (e.getValue() != hostnames[0])) {
								signal(h);
							}
						}
					}
					if (n == 0) {
						s.append("],");
						s.append("\"end\":\"");
						s.append(stamp());
						s.append("\"}\n");
						log(s.toString());
					}
					n = (n + 1) % 6;
				}
			}, 0, 5, TimeUnit.SECONDS);
			return e;
		}

		static void connectDatagramClient (
			final Object domain,
			final InetSocketAddress endpoint, final DatagramHandler handler)
		{
			executor.execute(new Runnable() {
				public void run () {
					ConnectionHandler server = null;
					Iterator<ConnectionHandler> i = ConnectionHandler.handlers.iterator();
					while ((server == null) && i.hasNext()) {
						ConnectionHandler h = i.next();
						if ((h.state == STATE_ACCEPTING) && (h.protocol == PROTOCOL_DPTTH)
							&& !h.signaled && (h.security == TRANSPORT_PASSTHROUGH)
							&& h.domain.equals(domain))
						{
							server = h;
							assert h.client == null;
							DatagramClient c = new DatagramClient();
							c.endpoint = endpoint;
							c.datagramHandler = handler;
							h.client = c;
							signal(h);
						}
					}
					if (server == null) {
						handler.handleConnection(endpoint, null);
					}
				}
			});
		}

		ConnectionHandler (
			InetSocketAddress localEndpoint, InetSocketAddress remoteEndpoint,
			Connection connection, SSLEngine sslEngine)
		{
			this.localHost = localEndpoint.getAddress().getHostAddress();
			this.remoteHost = remoteEndpoint.getAddress().getHostAddress();
			this.localPort = localEndpoint.getPort();
			this.remotePort = remoteEndpoint.getPort();
			this.connection = connection;
			this.sslEngine = sslEngine;
			this.handshaking = true;
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

		final CompletionHandler shutdownCompleted = new CompletionHandler() {
			public void handle (Connection c, ByteBuffer b, boolean error) {
				ShutdownCompletion sc = new ShutdownCompletion();
				sc.connection = c;
				sc.buffer = b;
				sc.error = error;
				Dispatcher.dispatch(stateMachine, sc);
			}
		};

		void sendDatagram (ByteBuffer b) {
				Dispatcher.dispatch(stateMachine, b);
		}

		void enterState (int s) {
			state = s;
			if (marked) {
				marked = false;
			}
			if (signaled) {
				signaled = false;
			}
		}

		void close (Connection c) {
			capacity.release();
			c.close();
		}

		final State open = new State() {
			public void handle (StateMachine m, Object o) {
				if (o == SIGNAL) {
					if (signaled) {
						context = CONTEXT_SIGNALED;
						m.transitionTo(closed);
					}
				} else if (o == EXIT) {
					if (connection != null) {
						close(connection);
						connection = null;
					}
					if (client != null) {
						if (client instanceof StreamClient) {
							StreamClient c = (StreamClient) client;
							close(c.connection);
						} else {
							assert client instanceof DatagramClient;
							DatagramClient c = (DatagramClient) client;
							c.datagramHandler.handleDisconnection(
								c.endpoint, ConnectionHandler.this);
						}
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
				SECURITY_HEADER = 7, SECURITY_HEADER_LF = 8, HOST_HEADER = 9,
				DONE = 10;

			int parserState;
			int parserPosition;
			int targetPosition;
			int targetLength;
			int securityPosition;
			int securityLength;
			int hostPosition;
			int hostLength;

			void parseServerNameExtension (ByteBuffer b, int p , int q) {
				assert 0 <= p;
				assert p <= q;
				assert q <= b.position();
				if (p <= q - 2) {
					int serverNameListLength =
						((b.get(p) & 0xff) << 8) |
						(b.get(p + 1) & 0xff);
					p += 2;
					if (p <= q - serverNameListLength) {
						q = p + serverNameListLength;
						if (p <= q - 1) {
							int serverNameType =
								b.get(p) & 0xff;
							p++;
							if ((serverNameType == 0)
								&& (p <= q - 2))
							{
								int hostNameLength =
									((b.get(p) & 0xff) << 8) |
									(b.get(p + 1) & 0xff);
								p += 2;
								if (p <= q - hostNameLength) {
									hostPosition = p;
									hostLength = hostNameLength;
								}
							}
						}
					}
				}
			}

			void parseExtensions (ByteBuffer b, int p , int q) {
				assert 0 <= p;
				assert p <= q;
				assert q <= b.position();
				if (p <= q - 2) {
					int extensionListLength =
						((b.get(p) & 0xff) << 8)	|
						(b.get(p + 1) & 0xff);
					p += 2;
					if (p <= q - extensionListLength) {
						q = p + extensionListLength;
						while (p <= q - 4) {
							int extensionType =
								((b.get(p) & 0xff) << 8) |
								(b.get(p + 1) & 0xff);
							int extensionDataLength =
								((b.get(p + 2) & 0xff) << 8) |
								(b.get(p + 3) & 0xff);
							p += 4;
							if (p > q - extensionDataLength) {
								p = q;
							} else if (extensionType == 0) {
								q = p + extensionDataLength;
								parseServerNameExtension(b, p, q);
								p = q;
							} else {
								p += extensionDataLength;
							}
						}
					}
				}
			}

			void parseClientHello (ByteBuffer b, int p, int q) {
				assert 0 <= p;
				assert p <= q;
				assert q <= b.position();
				if (p <= q - 35) {
					int sessionIdLength =
						b.get(p + 34) & 0xff;
					p += 35;
					if (p <= q - sessionIdLength) {
						p += sessionIdLength;
						if (p <= q - 2) {
							int cipherSuitesLength =
								((b.get(p) & 0xff) << 8)	|
								(b.get(p + 1) & 0xff);
							p += 2;
							if (p <= q - cipherSuitesLength) {
								p += cipherSuitesLength;
								if (p <= q - 1) {
									int compressionMethodsLength =
										b.get(p) & 0xff;
									p++;
									if (p <= q - compressionMethodsLength) {
										p += compressionMethodsLength;
										parseExtensions(b, p, q);
									}
								}
							}
						}
					}
				}
			}

			void parseHandshake (ByteBuffer b, int p, int q) {
				assert 0 <= p;
				assert p <= q;
				assert q <= b.position();
				if (p <= q - 4) {
					int handshakeType =
						b.get(p) & 0xff;
					int handshakeLength =
						((b.get(p + 1) & 0xff) << 16) |
						((b.get(p + 2) & 0xff) << 8)	|
						(b.get(p + 3) & 0xff);
					p += 4;
					if ((handshakeType == 1)
						&& (p <= q - handshakeLength))
					{
						q = p + handshakeLength;
						parseClientHello(b, p, q);
					}
				}
			}

			void parseHostName (ByteBuffer b) {
				assert parserState != DONE;
				int p = 0;
				int q = b.position();
				if (p <= q - 5) {
					int plaintextType =
						b.get(p) & 0xff;
					int protocolVersion0 =
						b.get(p + 1) & 0xff;
					int protocolVersion1 =
						b.get(p + 2) & 0xff;
					int plaintextLength =
						((b.get(p + 3) & 0xff) << 8) |
						(b.get(p + 4) & 0xff);
					p += 5;
					if ((plaintextType != 22)
						|| (protocolVersion0 < 3)
						|| (protocolVersion0 == 3) && (protocolVersion1 == 0))
					{
						parserState = DONE;
					} else if (p <= q - plaintextLength) {
						q = p + plaintextLength;
						parseHandshake(b, p, q);
						parserState = DONE;
					}
				}
			}

			void parseRequest (ByteBuffer b) {
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
							} else if ((p >= 17) && (b.get(p - 17) == LF)
								&& ((b.get(p - 16) == 'X') || (b.get(p - 16) == 'x'))
								&& (b.get(p - 15) == '-')
								&& ((b.get(p - 14) == 'R') || (b.get(p - 14) == 'r'))
								&& ((b.get(p - 13) == 'e') || (b.get(p - 13) == 'E'))
								&& ((b.get(p - 12) == 'l') || (b.get(p - 12) == 'L'))
								&& ((b.get(p - 11) == 'a') || (b.get(p - 11) == 'A'))
								&& ((b.get(p - 10) == 'y') || (b.get(p - 10) == 'Y'))
								&& (b.get(p - 9) == '-')
								&& ((b.get(p - 8) == 'S') || (b.get(p - 8) == 's'))
								&& ((b.get(p - 7) == 'e') || (b.get(p - 7) == 'E'))
								&& ((b.get(p - 6) == 'c') || (b.get(p - 6) == 'C'))
								&& ((b.get(p - 5) == 'u') || (b.get(p - 5) == 'U'))
								&& ((b.get(p - 4) == 'r') || (b.get(p - 4) == 'R'))
								&& ((b.get(p - 3) == 'i') || (b.get(p - 3) == 'I'))
								&& ((b.get(p - 2) == 't') || (b.get(p - 2) == 'T'))
								&& ((b.get(p - 1) == 'y') || (b.get(p - 1) == 'Y')))
							{
								if (securityLength == 0) {
									s = SECURITY_HEADER;
									securityPosition = p + 1;
								}
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
							if (p >= 10) {
								int y = b.get(p - 10);
								if (((y == ':') || (y == ',') || (y == SP) || (y == HT))
									&& (b.get(p - 9) == 'D') && (b.get(p - 8) == 'P')
									&& (b.get(p - 7) == 'T') && (b.get(p - 6) == 'T')
									&& (b.get(p - 5) == 'H') && (b.get(p - 4) == '/')
									&& (b.get(p - 3) == '1') && (b.get(p - 2) == '.')
									&& (b.get(p - 1) == '0'))
								{
									protocol = PROTOCOL_DPTTH;
								}
							}
							if (p >= 9) {
								int y = b.get(p - 9);
								if (((y == ':') || (y == ',') || (y == SP) || (y == HT))
									&& (b.get(p - 8) == 'P') && (b.get(p - 7) == 'T')
									&& (b.get(p - 6) == 'T') && (b.get(p - 5) == 'H')
									&& (b.get(p - 4) == '/') && (b.get(p - 3) == '1')
									&& (b.get(p - 2) == '.') && (b.get(p - 1) == '0'))
								{
									protocol = PROTOCOL_PTTH;
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
					} else if (s == SECURITY_HEADER) {
						if ((x == ',') || (x == SP) || (x == HT) || (x == LF) || (x == CR))
						{
							if (p >= 23) {
								int y = b.get(p - 23);
								if (((y == ':') || (y == ',') || (y == SP) || (y == HT))
									&& (b.get(p - 22) == 't') && (b.get(p - 21) == 'r')
									&& (b.get(p - 20) == 'a') && (b.get(p - 19) == 'n')
									&& (b.get(p - 18) == 's') && (b.get(p - 17) == 'p')
									&& (b.get(p - 16) == 'o') && (b.get(p - 15) == 'r')
									&& (b.get(p - 14) == 't') && (b.get(p - 13) == '/')
									&& (b.get(p - 12) == 'p') && (b.get(p - 11) == 'a')
									&& (b.get(p - 10) == 's') && (b.get(p - 9) == 's')
									&& (b.get(p - 8) == '-') && (b.get(p - 7) == 't')
									&& (b.get(p - 6) == 'h') && (b.get(p - 5) == 'r')
									&& (b.get(p - 4) == 'o') && (b.get(p - 3) == 'u')
									&& (b.get(p - 2) == 'g') && (b.get(p - 1) == 'h'))
								{
									security = TRANSPORT_PASSTHROUGH;
								}
							}
							if (x == LF) {
								s = SECURITY_HEADER_LF;
							}
						}
					} else if (s == SECURITY_HEADER_LF) {
						if ((x == SP) || (x == HT)) {
							s = SECURITY_HEADER;
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
					enterState(STATE_RECEIVING);
					domain = null;
					hash = null;
					protocol = 0;
					security = 0;
					parserState = BEFORE_TARGET;
					parserPosition = 0;
					targetPosition = 0;
					targetLength = 0;
					securityPosition = 0;
					securityLength = 0;
					hostPosition = 0;
					hostLength = 0;
					connection.receive(null, receiveCompleted);
				} else if (o instanceof ReceiveCompletion) {
					ReceiveCompletion rc = (ReceiveCompletion) o;
					if (!rc.error) {
						ByteBuffer b = rc.buffer;
						if (sslEngine != null) {
							parseHostName(b);
						} else {
							parseRequest(b);
						}
						if (parserState != DONE) {
							if (b.position() < 2048) {
								if (marked) {
									marked = false;
								}
								connection.receive(b, receiveCompleted);
							} else {
								context = CONTEXT_RECEIVING_REQUEST_TOO_LARGE;
								m.transitionTo(closed);
							}
						} else {
							if (protocol == PROTOCOL_CLIENT) {
								String d = getSubdomain(b, hostPosition, hostLength);
								if (d != null) {
									domain = d;
								}
							}
							if ((sslEngine != null) && (domain == null)) {
								connection.upgradeToSSL(sslEngine, b, null);
								sslEngine = null;
								m.transitionTo(receiving);
							} else {
								byte[] h = sha1().digest(bytes((String) domain));
								Entry<byte[], String> e = ceilingRingEntry(h);
								if (e != null) {
									if (e.getValue() == hostnames[0]) {
										if ((protocol == PROTOCOL_PTTH)
											|| (protocol == PROTOCOL_DPTTH))
										{
											hash = h;
											if (domain.equals("/") || domain.equals("/relay_domain")) {
												connection.send(ByteBuffer.wrap(HTTP401), sendCompleted);
												m.transitionTo(sending);
											} else {
												if (handshaking) {
													handshaking = false;
													m.transitionTo(counting);
												} else {
													m.transitionTo(accepting);
												}
											}
										} else {
											assert protocol == PROTOCOL_CLIENT;
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
												StreamClient c = new StreamClient();
												c.connection = connection;
												c.sslEngine = sslEngine;
												c.buffer = b;
												client = c;
												connection = null;
												sslEngine = null;
												m.transitionTo(connecting);
											}
										}
									} else if (sslEngine != null) {
										connection.upgradeToSSL(sslEngine, b, null);
										sslEngine = null;
										m.transitionTo(receiving);
									} else {
										byte[] location = bytes(
											(connection.isSecure()? "https://": "http://")
											+ e.getValue() + ":" + localPort);
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
									context = CONTEXT_RECEIVING_NODE_NOT_FOUND;
									m.transitionTo(closed);
								}
							}
						}
					} else {
						context = CONTEXT_RECEIVING_RECEIVE_COMPLETION_ERROR;
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
					enterState(STATE_CONNECTING);
					executor.execute(new Runnable() {
						public void run () {
							ConnectionHandler server = null;
							StreamClient c = (StreamClient) client;
							Iterator<ConnectionHandler> i = handlers.iterator();
							while ((server == null) && i.hasNext()) {
								ConnectionHandler h = i.next();
								if ((h.state == STATE_ACCEPTING)
									&& (h.protocol == PROTOCOL_PTTH)
									&& !h.signaled && (
										((c.sslEngine == null)
											&& !c.connection.isSecure())
										|| ((h.security != TRANSPORT_PASSTHROUGH)
											&& h.connection.isSecure())
										|| ((h.security == TRANSPORT_PASSTHROUGH)
											&& (c.sslEngine != null)))
									&& h.domain.equals(domain))
								{
									server = h;
									assert h.client == null;
									h.client = client;
									client = null;
									signal(h);
								}
							}
							Dispatcher.dispatch(stateMachine, server);
						}
					});
				} else if (o instanceof ConnectionHandler) {
					context = CONTEXT_CONNECTING;
					m.transitionTo(closed);
				} else if (o == null) {
					StreamClient c = (StreamClient) client;
					if (c.sslEngine != null) {
						c.buffer.position(c.buffer.limit());
						c.buffer.limit(c.buffer.capacity());
						c.connection.upgradeToSSL(c.sslEngine, c.buffer, null);
						c.sslEngine = null;
					}
					c.connection.send(ByteBuffer.wrap(HTTP504), sendCompleted);
					m.transitionTo(sending);
				} else if (o == SIGNAL) {
					if (signaled) {
						signaled = false;
					}
				} else {
					m.upwardTo(open);
				}
			}
		};

		final State counting = new State() {
			public void handle (StateMachine m, Object o) {
				if (o == ENTER) {
					enterState(STATE_COUNTING);
					executor.execute(new Runnable() {
						public void run () {
							int n = 0;
							Iterator<ConnectionHandler> i = handlers.iterator();
							while ((n <= 32) && i.hasNext()) {
								ConnectionHandler h = i.next();
								Object d = h.domain;
								if ((h.state != STATE_CLOSED) && (d != null) && d.equals(domain))
								{
									n++;
								}
							}
							if (n <= 32) {
								Dispatcher.dispatch(stateMachine, Boolean.TRUE);
							} else {
								Dispatcher.dispatch(stateMachine, Boolean.FALSE);
							}
						}
					});
				} else if (o == Boolean.TRUE) {
					m.transitionTo(renewing);
				} else if (o == Boolean.FALSE) {
					context = CONTEXT_COUNTING;
					m.transitionTo(closed);
				} else if (o == SIGNAL) {
					if (signaled) {
						signaled = false;
					}
				} else {
					m.upwardTo(open);
				}
			}
		};

		final State accepting = new State() {
			public void handle (StateMachine m, Object o) {
				if (o == ENTER) {
					enterState(STATE_ACCEPTING);
				} else if (o == SIGNAL) {
					if (signaled) {
						if (client == null) {
							m.transitionTo(renewing);
						} else {
							m.transitionTo(upgrading);
						}
					}
				} else {
					m.upwardTo(open);
				}
			}
		};

		final State renewing = new State() {
			public void handle (StateMachine m, Object o) {
				if (o == ENTER) {
					enterState(STATE_RENEWING);
					connection.send(ByteBuffer.wrap(HTTP204), sendCompleted);
				} else if (o instanceof SendCompletion) {
					SendCompletion sc = (SendCompletion) o;
					if (!sc.error) {
						m.transitionTo(receiving);
					} else {
						context = CONTEXT_RENEWING;
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
					enterState(STATE_UPGRADING);
					if (protocol == PROTOCOL_PTTH) {
						connection.send(ByteBuffer.wrap(HTTP101_PTTH), sendCompleted);
					} else {
						assert protocol == PROTOCOL_DPTTH;
						connection.send(ByteBuffer.wrap(HTTP101_DPTTH), sendCompleted);
					}
				} else if (o instanceof SendCompletion) {
					SendCompletion sc = (SendCompletion) o;
					if (!sc.error) {
						if (client instanceof StreamClient) {
							StreamClient c = (StreamClient) client;
							if (c.sslEngine != null) {
								if (security != TRANSPORT_PASSTHROUGH) {
									c.buffer.position(c.buffer.limit());
									c.buffer.limit(c.buffer.capacity());
									c.connection.upgradeToSSL(c.sslEngine, c.buffer, null);
								}
								c.sslEngine = null;
							}
							m.transitionTo(relayingStreams);
						} else {
							assert client instanceof DatagramClient;
							DatagramClient c = (DatagramClient) client;
							c.datagramHandler.handleConnection(
								c.endpoint, ConnectionHandler.this);
							m.transitionTo(relayingDatagrams);
						}
					} else {
						close(connection);
						connection = null;
						if (client instanceof StreamClient) {
							m.transitionTo(connecting);
						} else {
							assert client instanceof DatagramClient;
							DatagramClient c = (DatagramClient) client;
							connectDatagramClient(
								ConnectionHandler.this.domain, c.endpoint, c.datagramHandler);
							context = CONTEXT_UPGRADING;
							m.transitionTo(closed);
						}
					}
				} else {
					m.upwardTo(open);
				}
			}
		};

		final State relayingStreams = new State() {
			boolean error;

			Connection peer (Connection c) {
				Connection result;
				if (c == connection) {
					if (client != null) {
						result = ((StreamClient) client).connection;
					} else {
						result = null;
					}
				} else if (client != null) {
					if (c == ((StreamClient) client).connection) {
						result = connection;
					} else {
						result = null;
					}
				} else {
					result = null;
				}
				return result;
			}

			void closeEndpoint (Connection c) {
				assert c != null;
				close(c);
				if (c == connection) {
					connection = null;
				} else {
					assert client != null;
					assert c == ((StreamClient) client).connection;
					client = null;
				}
			}

			void transitionToClosed (Connection c, Connection p) {
				assert c != null;
				assert p != null;
				if (p.isSecure()) {
					closeEndpoint(c);
					p.shutdownOutput(shutdownCompleted);
					stateMachine.transitionTo(closing);
				} else {
					p.shutdownOutput(null);
					context = CONTEXT_RELAYING_STREAMS;
					stateMachine.transitionTo(closed);
				}
			}

			public void handle (StateMachine m, Object o) {
				if (o == ENTER) {
					enterState(STATE_RELAYING_STREAMS);
					StreamClient c = (StreamClient) client;
					inflow += c.buffer.remaining();
					connection.send(c.buffer, sendCompleted);
					connection.receive(null, receiveCompleted);
					c.buffer = null;
					error = false;
				} else if (o instanceof SendCompletion) {
					SendCompletion sc = (SendCompletion) o;
					Connection p = peer(sc.connection);
					if (!sc.error) {
						ByteBuffer b = sc.buffer;
						outflow += b.position();
						b.clear();
						if (p != null) {
							if (marked) {
								marked = false;
							}
							p.receive(b, receiveCompleted);
						} else if (sc.connection.isSecure()) {
							sc.connection.shutdownOutput(shutdownCompleted);
							m.transitionTo(closing);
						} else {
							sc.connection.shutdownOutput(null);
							context = CONTEXT_RELAYING_STREAMS_SENDING;
							m.transitionTo(closed);
						}
					} else if (!error) {
						error = true;
						assert p != null;
						if (sc.connection.isSecure() || p.isSecure()) {
							transitionToClosed(sc.connection, p);
						}
					} else if (p != null) {
						transitionToClosed(sc.connection, p);
					} else {
						context = CONTEXT_RELAYING_STREAMS_SEND_COMPLETION_ERROR;
						m.transitionTo(closed);
					}
				} else if (o instanceof ReceiveCompletion) {
					ReceiveCompletion rc = (ReceiveCompletion) o;
					Connection p = peer(rc.connection);
					if (!rc.error) {
						ByteBuffer b = rc.buffer;
						inflow += b.position();
						b.flip();
						assert p != null;
						if (marked) {
							marked = false;
						}
						p.send(b, sendCompleted);
					} else if (!error) {
						error = true;
						assert p != null;
						if (rc.connection.isSecure() || p.isSecure()) {
							transitionToClosed(rc.connection, p);
						} else {
							p.shutdownOutput(null);
						}
					} else if (p != null) {
						transitionToClosed(rc.connection, p);
					} else {
						context = CONTEXT_RELAYING_STREAMS_RECEIVE_COMPLETION_ERROR;
						m.transitionTo(closed);
					}
				} else {
					m.upwardTo(open);
				}
			}
		};

		final State relayingDatagrams = new State() {
			boolean sending, sendCompletionError, receiveCompletionError;
			LinkedList<ByteBuffer> incomingDatagrams =
				new LinkedList<ByteBuffer>();

			public void handle (StateMachine m, Object o) {
				if (o == ENTER) {
					enterState(STATE_RELAYING_DATAGRAMS);
					sending = false;
					sendCompletionError = false;
					receiveCompletionError = false;
					connection.receive(null, receiveCompleted);
				} else if (o instanceof SendCompletion) {
					SendCompletion sc = (SendCompletion) o;
					if (!sc.error) {
						ByteBuffer b = sc.buffer;
						assert b.position() >= 2;
						outflow += b.position() - 2;
						if (marked) {
							marked = false;
						}
						if (incomingDatagrams.isEmpty()) {
							sending = false;
						} else {
							connection.send(incomingDatagrams.poll(), sendCompleted);
						}
					} else {
						sending = false;
						sendCompletionError = true;
						if (sc.connection.isSecure() || receiveCompletionError) {
							context = CONTEXT_RELAYING_DATAGRAMS_SEND_COMPLETION_ERROR;
							stateMachine.transitionTo(closed);
						}
					}
				} else if (o instanceof ReceiveCompletion) {
					ReceiveCompletion rc = (ReceiveCompletion) o;
					if (!rc.error) {
						boolean done;
						ByteBuffer b = rc.buffer;
						do {
							done = true;
							if (b.position() >= 2) {
								int length = (b.get(0) & 0xff) | ((b.get(1) & 0xff) << 8);
								if (b.position() >= 2 + length) {
									inflow += length;
									ByteBuffer d = ByteBuffer.allocate(length);
									for (int i = 2; i != 2 + length; i++) {
										d.put(b.get(i));
									}
									d.flip();
									DatagramClient c = (DatagramClient) client;
									c.datagramHandler.handleOutgoingDatagram(d, c.endpoint);
									b.limit(b.position());
									b.position(2 + length);
									b.compact();
									done = false;
								}
							}
						} while (!done);
						if (marked) {
							marked = false;
						}
						rc.connection.receive(b, receiveCompleted);
					} else {
						receiveCompletionError = true;
						if (rc.connection.isSecure() || sendCompletionError) {
							context = CONTEXT_RELAYING_DATAGRAMS_RECEIVE_COMPLETION_ERROR;
							stateMachine.transitionTo(closed);
						}
					}
				} else if (o instanceof ByteBuffer) {
					ByteBuffer b = (ByteBuffer) o;
					if (!sendCompletionError && (b.capacity() - b.limit() >= 2)) {
						int length = b.limit();
						b.limit(length + 2);
						for (int i = length - 1; i >= 0; i--) {
							b.put(i + 2, b.get(i));
						}
						assert length <= 0xffff;
						b.put(0, (byte) (length & 0xff));
						b.put(1, (byte) ((length >> 8) & 0xff));
						if (marked) {
							marked = false;
						}
						if (sending) {
							incomingDatagrams.offer(b);
						} else {
							connection.send(b, sendCompleted);
							sending = true;
						}
					}
				} else if (o == EXIT) {
					incomingDatagrams.clear();
				} else {
					m.upwardTo(open);
				}
			}
		};

		final State sending = new State() {
			public void handle (StateMachine m, Object o) {
				if (o == ENTER) {
					enterState(STATE_SENDING);
				} else if (o instanceof SendCompletion) {
					SendCompletion sc = (SendCompletion) o;
					if (!sc.error) {
						if (sc.connection.isSecure()) {
							sc.connection.shutdownOutput(shutdownCompleted);
							m.transitionTo(closing);
						} else {
							sc.connection.shutdownOutput(null);
							context = CONTEXT_SENDING;
							m.transitionTo(closed);
						}
					} else {
						context = CONTEXT_SENDING_SEND_COMPLETION_ERROR;
						m.transitionTo(closed);
					}
				} else {
					m.upwardTo(open);
				}
			}
		};

		final State closing = new State() {
			public void handle (StateMachine m, Object o) {
				if (o == ENTER) {
					enterState(STATE_CLOSING);
				} else if (o instanceof ShutdownCompletion) {
					context = CONTEXT_CLOSING;
					m.transitionTo(closed);
				} else if (!(o instanceof SendCompletion)
					&& !(o instanceof ReceiveCompletion)
					&& !(o instanceof ByteBuffer))
				{
					m.upwardTo(open);
				}
			}
		};

		final State closed = new State() {
			public void handle (StateMachine m, Object o) {
				if (o == ENTER) {
					enterState(STATE_CLOSED);
				}
			}
		};
	}

	public static void openConnectionListener (
		final InetSocketAddress endpoint, final SSLContext sslContext)
	{
		assert endpoint != null;
		Tasks.newSingleThreadExecutor().execute(new Runnable() {
			public void run () {
				ServerSocketChannel sc;
				try {
					sc = ServerSocketChannel.open();
					sc.socket().setReuseAddress(true);
					sc.socket().bind(endpoint, 4095);
				} catch (Exception e) { throw new Error(e); }
				while (true) {
					SocketChannel c;
					Socket s;
					try {
						capacity.acquire();
						c = sc.accept();
						s = c.socket();
						c.configureBlocking(false);
						s.setTcpNoDelay(true);
					} catch (Exception e) { throw new Error(e); }
					SSLEngine e = null;
					if (sslContext != null) {
						e = sslContext.createSSLEngine();
						e.setUseClientMode(false);
					}
					new ConnectionHandler(
						endpoint, (InetSocketAddress) s.getRemoteSocketAddress(),
						new Connection(c, null), e);
				}
			}
		});
	}

	private static final class DatagramHandler {
		static final class ConnectionEvent {
			InetSocketAddress client;
			ConnectionHandler connectionHandler;
		}

		static final class DisconnectionEvent {
			InetSocketAddress client;
			ConnectionHandler connectionHandler;
		}

		static final class OutgoingDatagram {
			ByteBuffer buffer;
			InetSocketAddress destination;
		}

		static Selector newSelector () {
			try {
				return Selector.open();
			} catch (Exception e) { throw new Error(e); }
		}

		final Selector
			selector = newSelector();
		final ConcurrentLinkedQueue<Object>
			connectionEvents = new ConcurrentLinkedQueue<Object>();
		final ConcurrentLinkedQueue<OutgoingDatagram>
			outgoingDatagrams = new ConcurrentLinkedQueue<OutgoingDatagram>();

		final HashMap<InetSocketAddress, ConnectionHandler>
			connectionHandlers = new HashMap<InetSocketAddress, ConnectionHandler>();
		final HashMap<InetSocketAddress, LinkedList<ByteBuffer>>
			incomingDatagrams = new HashMap<InetSocketAddress, LinkedList<ByteBuffer>>();

		int serverNamePosition;
		int serverNameLength;

		void parseServerNameExtension (ByteBuffer b, int p , int q) {
			assert 0 <= p;
			assert p <= q;
			assert q <= b.limit();
			if (p <= q - 2) {
				int serverNameListLength =
					((b.get(p) & 0xff) << 8) |
					(b.get(p + 1) & 0xff);
				p += 2;
				if (p <= q - serverNameListLength) {
					q = p + serverNameListLength;
					if (p <= q - 1) {
						int serverNameType =
							b.get(p) & 0xff;
						p++;
						if ((serverNameType == 0)
							&& (p <= q - 2))
						{
							int hostNameLength =
								((b.get(p) & 0xff) << 8) |
								(b.get(p + 1) & 0xff);
							p += 2;
							if (p <= q - hostNameLength) {
								serverNamePosition = p;
								serverNameLength = hostNameLength;
							}
						}
					}
				}
			}
		}

		void parseExtensions (ByteBuffer b, int p , int q) {
			assert 0 <= p;
			assert p <= q;
			assert q <= b.limit();
			if (p <= q - 2) {
				int extensionListLength =
					((b.get(p) & 0xff) << 8)	|
					(b.get(p + 1) & 0xff);
				p += 2;
				if (p <= q - extensionListLength) {
					q = p + extensionListLength;
					while (p <= q - 4) {
						int extensionType =
							((b.get(p) & 0xff) << 8) |
							(b.get(p + 1) & 0xff);
						int extensionDataLength =
							((b.get(p + 2) & 0xff) << 8) |
							(b.get(p + 3) & 0xff);
						p += 4;
						if (p > q - extensionDataLength) {
							p = q;
						} else if (extensionType == 0) {
							q = p + extensionDataLength;
							parseServerNameExtension(b, p, q);
							p = q;
						} else {
							p += extensionDataLength;
						}
					}
				}
			}
		}

		void parseClientHello (ByteBuffer b, int p, int q) {
			assert 0 <= p;
			assert p <= q;
			assert q <= b.limit();
			if (p <= q - 35) {
				int sessionIdLength =
					b.get(p + 34) & 0xff;
				p += 35;
				if (p <= q - sessionIdLength) {
					p += sessionIdLength;
					if (p <= q - 3) {
						int cipherSuitesLength =
							((b.get(p + 1) & 0xff) << 8)	|
							(b.get(p + 2) & 0xff);
						p += 3;
						if (p <= q - cipherSuitesLength) {
							p += cipherSuitesLength;
							if (p <= q - 1) {
								int compressionMethodsLength =
									b.get(p) & 0xff;
								p++;
								if (p <= q - compressionMethodsLength) {
									p += compressionMethodsLength;
									parseExtensions(b, p, q);
								}
							}
						}
					}
				}
			}
		}

		void parseHandshake (ByteBuffer b, int p, int q) {
			assert 0 <= p;
			assert p <= q;
			assert q <= b.limit();
			if (p <= q - 12) {
				int handshakeType =
					b.get(p) & 0xff;
				int handshakeLength =
					((b.get(p + 1) & 0xff) << 16) |
					((b.get(p + 2) & 0xff) << 8)	|
					(b.get(p + 3) & 0xff);
				p += 12;
				if ((handshakeType == 1)
					&& (p <= q - handshakeLength))
				{
					q = p + handshakeLength;
					parseClientHello(b, p, q);
				}
			}
		}

		void parseServerName (ByteBuffer b) {
			int p = 0;
			int q = b.limit();
			if (p <= q - 13) {
				int plaintextType =
					b.get(p) & 0xff;
				int protocolVersion0 =
					b.get(p + 1) & 0xff;
				int protocolVersion1 =
					b.get(p + 2) & 0xff;
				int plaintextLength =
					((b.get(p + 11) & 0xff) << 8) |
					(b.get(p + 12) & 0xff);
				p += 13;
				if ((plaintextType == 22)
					&& (protocolVersion0 == 254)
					&& ((protocolVersion1 == 255) || (protocolVersion1 == 253))
					&& (p <= q - plaintextLength))
				{
						q = p + plaintextLength;
						parseHandshake(b, p, q);
				}
			}
		}

		void handleConnection (InetSocketAddress client, ConnectionHandler h) {
			assert client != null;
			ConnectionEvent e = new ConnectionEvent();
			e.client = client;
			e.connectionHandler = h;
			connectionEvents.offer(e);
			selector.wakeup();
		}

		void handleDisconnection (InetSocketAddress client, ConnectionHandler h) {
			assert client != null;
			assert h != null;
			DisconnectionEvent e = new DisconnectionEvent();
			e.client = client;
			e.connectionHandler = h;
			connectionEvents.offer(e);
			selector.wakeup();
		}

		void handleConnectionEvents () {
			while (!connectionEvents.isEmpty()) {
				Object o = connectionEvents.poll();
				if (o instanceof ConnectionEvent) {
					ConnectionEvent e = (ConnectionEvent) o;
					LinkedList<ByteBuffer> q = incomingDatagrams.remove(e.client);
					if (e.connectionHandler != null) {
						connectionHandlers.put(e.client, e.connectionHandler);
						while (!q.isEmpty()) {
							e.connectionHandler.sendDatagram(q.poll());
						}
					}
				} else {
					assert o instanceof DisconnectionEvent;
					DisconnectionEvent e = (DisconnectionEvent) o;
					connectionHandlers.remove(e.client);
				}
			}
		}

		void handleIncomingDatagram (ByteBuffer b, InetSocketAddress source) {
			assert b != null;
			assert source != null;
			ConnectionHandler h = connectionHandlers.get(source);
			if (h != null) {
				h.sendDatagram(b);
			} else {
				LinkedList<ByteBuffer> q = incomingDatagrams.get(source);
				if (q != null) {
					q.offer(b);
				} else {
					serverNamePosition = 0;
					serverNameLength = 0;
					parseServerName(b);
					if (serverNameLength > 0) {
						String domain = getSubdomain(b, serverNamePosition, serverNameLength);
						if (domain != null) {
							q = new LinkedList<ByteBuffer>();
							incomingDatagrams.put(source, q);
							q.offer(b);
							ConnectionHandler.connectDatagramClient(
								domain, source, DatagramHandler.this);
						}
					}
				}
			}
		}

		void handleOutgoingDatagram (ByteBuffer b, InetSocketAddress destination) {
			assert b != null;
			assert destination != null;
			OutgoingDatagram d = new OutgoingDatagram();
			d.buffer = b;
			d.destination = destination;
			outgoingDatagrams.offer(d);
			selector.wakeup();
		}

		static void openListener (final InetSocketAddress endpoint) {
			Tasks.newSingleThreadExecutor().execute(new Runnable() {
				public void run () {
					DatagramChannel c;
					try {
						c = DatagramChannel.open();
						c.configureBlocking(false);
						c.socket().setReuseAddress(true);
						c.socket().bind(endpoint);
					} catch (Exception e) { throw new Error(e); }
					DatagramHandler h = new DatagramHandler();
					while (true) {
						try {
							c.register(h.selector, h.outgoingDatagrams.isEmpty()?
								SelectionKey.OP_READ:
								SelectionKey.OP_READ | SelectionKey.OP_WRITE);
							h.selector.select();
						} catch (Exception e) { throw new Error(e); }
						h.handleConnectionEvents();
						for (SelectionKey k: h.selector.selectedKeys()) {
							if (k.isValid()) {
								int readyOps = k.readyOps();
								if ((readyOps & SelectionKey.OP_READ) != 0) {
									Object source = null;
									ByteBuffer b = ByteBuffer.allocate(DATAGRAM_BUFFER_SIZE);
									try {
										source = c.receive(b);
									} catch (IOException e) {}
									if (source != null) {
										b.flip();
										h.handleIncomingDatagram(b, (InetSocketAddress) source);
									}
								}
								if ((readyOps & SelectionKey.OP_WRITE) != 0) {
									OutgoingDatagram d = h.outgoingDatagrams.poll();
									try {
										c.send(d.buffer, d.destination);
									} catch (IOException e) {}
								}
							}
						}
						h.selector.selectedKeys().clear();
					}
				}
			});
		}
	}

	public static void openDatagramListener (final InetSocketAddress endpoint) {
		assert endpoint != null;
		DatagramHandler.openListener(endpoint);
	}

	public static void init (
		String[] hostnames, String root, int capacity, int tokencount)
	{
		assert capacity >= 0;
		if ((hostnames == null) || (hostnames.length == 0)) {
			hostnames = new String[] {""};
		}
		Relay.hostnames = hostnames;
		Relay.root = root;
		Relay.capacity = new Semaphore(capacity, true);
		MessageDigest d = sha1();
		for (int i = 0; i < tokencount; i++) {
			d.reset();
			ring.put(d.digest(bytes(hostnames[0] + "." + i)), hostnames[0]);
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
