// Copyright (c) 2010 - 2018, Yaler Gmbh, Switzerland. All rights reserved.

package org.yaler.core;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;

import org.yaler.core.Dispatcher;
import org.yaler.core.Dispatcher.Selection;
import org.yaler.core.StateMachines.State;
import org.yaler.core.StateMachines.StateMachine;
import org.yaler.core.Tasks;
import org.yaler.core.Tasks.Executor;

public final class Connections {
	private Connections () {}

	private static final String[]
		DEFAULT_PROTOCOLS = new String[] {
			"TLSv1.2",
			"TLSv1.1",
			"TLSv1"},
		DEFAULT_CIPHER_SUITES = new String[] {
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
			"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
			"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
			"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
			"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
			"SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
			"SSL_RSA_WITH_3DES_EDE_CBC_SHA"};

	static {
		System.setProperty("jdk.tls.ephemeralDHKeySize", "2048");
	}

	public static interface CompletionHandler {
		public void handle (Connection c, ByteBuffer b, boolean error);
	}

	private static final class Upgrade {
		SSLEngine sslEngine;
		ByteBuffer buffer;
		CompletionHandler completionHandler;
	}

	private static final class Send {
		ByteBuffer buffer;
		CompletionHandler completionHandler;
	}

	private static final class Receive {
		ByteBuffer buffer;
		CompletionHandler completionHandler;
	}

	private static final class Shutdown {
		CompletionHandler completionHandler;
	}

	public static final class Connection {
		private static final boolean
			ERROR = true;
		private static final Object
			CLOSE = new Object(),
			TASK_COMPLETION = new Object();
		private static final ByteBuffer
			NULL = ByteBuffer.allocate(0);

		private static final Executor
			executor = Tasks.newSingleThreadExecutor();

		private final StateMachine stateMachine = new StateMachine();
		private final SocketChannel channel;

		private volatile SSLEngine sslEngine;

		private CompletionHandler
			sendCompletionHandler,
			receiveCompletionHandler,
			shutdownCompletionHandler;
		private ByteBuffer
			inboundBuffer,
			outboundBuffer,
			readBuffer,
			writeBuffer;
		private int interestOps;
		private HandshakeStatus handshakeStatus;
		private int handshakeCount;

		private static String[] intersection (String[] x, String[] y) {
			String[] z = new String[Math.min(x.length, y.length)];
			int k = 0, i = 0, n = x.length;
			while (i != n) {
				String t = x[i];
				int j = 0, m = y.length;
				while ((j != m) && !t.equals(y[j])) {
					j++;
				}
				if (j != m) {
					z[k] = t;
					k++;
				}
				i++;
			}
			if (k != z.length) {
				String[] t = new String[k];
				System.arraycopy(z, 0, t, 0, k);
				z = t;
			}
			return z;
		}

		public Connection (SocketChannel c, SSLEngine e) {
			assert c != null;
			assert !c.isBlocking();
			channel = c;
			sslEngine = e;
			inboundBuffer = NULL;
			outboundBuffer = NULL;
			if (sslEngine != null) {
				initSSL(null);
			}
			Dispatcher.start(stateMachine, normal);
		}

		private void initSSL (ByteBuffer b) {
			sslEngine.setEnabledProtocols(intersection(
				DEFAULT_PROTOCOLS, sslEngine.getSupportedProtocols()));
			sslEngine.setEnabledCipherSuites(intersection(
				DEFAULT_CIPHER_SUITES, sslEngine.getSupportedCipherSuites()));
			try {
				SSLParameters sslParameters = sslEngine.getSSLParameters();
				sslParameters.getClass()
					.getMethod("setUseCipherSuitesOrder", Boolean.TYPE)
					.invoke(sslParameters, Boolean.TRUE);
				sslEngine.setSSLParameters(sslParameters);
			} catch (NoSuchMethodException x) {
			} catch (Exception x) {
				throw new Error(x);
			}
			int n = sslEngine.getSession().getPacketBufferSize();
			if (b == null) {
				readBuffer = ByteBuffer.allocate(n);
			} else {
				b.flip();
				if (n > b.remaining()) {
					readBuffer = ByteBuffer.allocate(n).put(b);
				} else {
					readBuffer = ByteBuffer.allocate(b.remaining()).put(b);
				}
			}
			writeBuffer = ByteBuffer.allocate(n);
			writeBuffer.flip();
			handshakeStatus = HandshakeStatus.NOT_HANDSHAKING;
			handshakeCount = 0;
		}

		private void bounceUpgrade (Upgrade u) {
			if (u.completionHandler != null) {
				u.completionHandler.handle(this, u.buffer, ERROR);
			}
		}

		private void bounceSend (Send s) {
			s.completionHandler.handle(this, s.buffer, ERROR);
		}

		private void bounceReceive (Receive r) {
			r.completionHandler.handle(this, r.buffer, ERROR);
		}

		private void bounceShutdown (Shutdown s) {
			if (s.completionHandler != null) {
				s.completionHandler.handle(this, null, ERROR);
			}
		}

		private void signalSendCompletion (boolean error) {
			if (sendCompletionHandler != null) {
				sendCompletionHandler.handle(this, outboundBuffer, error);
				outboundBuffer = NULL;
				sendCompletionHandler = null;
			}
		}

		private void signalReceiveCompletion (boolean error) {
			if (receiveCompletionHandler != null) {
				receiveCompletionHandler.handle(this, inboundBuffer, error);
				inboundBuffer = NULL;
				receiveCompletionHandler = null;
			}
		}

		private void signalShutdownCompletion (boolean error) {
			if (shutdownCompletionHandler != null) {
				shutdownCompletionHandler.handle(this, null, error);
				shutdownCompletionHandler = null;
			}
		}

		private void register (int ops) {
			if ((interestOps & ops) != ops) {
				interestOps |= ops;
				Dispatcher.register(channel, interestOps, stateMachine);
			}
		}

		private void cancel (int ops) {
			if ((interestOps & ops) != 0) {
				interestOps &= ~ops;
				Dispatcher.register(channel, interestOps, stateMachine);
			}
		}

		private Status unwrap () {
			Status s;
			readBuffer.flip();
			try {
				s = sslEngine.unwrap(readBuffer, inboundBuffer).getStatus();
				if (s == Status.BUFFER_OVERFLOW ) {
					int n = inboundBuffer.position()
						+ sslEngine.getSession().getApplicationBufferSize();
					inboundBuffer.flip();
					inboundBuffer = ByteBuffer.allocate(n).put(inboundBuffer);
					s = sslEngine.unwrap(readBuffer, inboundBuffer).getStatus();
				}
				if (s == Status.BUFFER_UNDERFLOW) {
					int n = sslEngine.getSession().getPacketBufferSize();
					if (n > readBuffer.capacity()) {
						readBuffer = ByteBuffer.allocate(n).put(readBuffer);
						readBuffer.flip();
					}
				}
			} catch (SSLException e) {
				s = null;
			}
			readBuffer.compact();
			assert (s == null) || (s == Status.OK) || (s == Status.CLOSED)
				|| (s == Status.BUFFER_UNDERFLOW);
			return s;
		}

		private Status wrap () {
			Status s;
			writeBuffer.compact();
			try {
				s = sslEngine.wrap(outboundBuffer, writeBuffer).getStatus();
				if (s == Status.BUFFER_OVERFLOW) {
					int n = sslEngine.getSession().getPacketBufferSize();
					if (n > writeBuffer.capacity()) {
						writeBuffer.flip();
						writeBuffer = ByteBuffer.allocate(n).put(writeBuffer);
						s = sslEngine.wrap(outboundBuffer, writeBuffer).getStatus();
					}
				}
			} catch (SSLException e) {
				s = null;
			}
			writeBuffer.flip();
			assert (s == null) || (s == Status.OK) || (s == Status.CLOSED)
				|| (s == Status.BUFFER_OVERFLOW);
			return s;
		}

		private void submitTask () {
			final Runnable r = sslEngine.getDelegatedTask();
			if (r != null) {
				executor.execute(new Runnable() {
					public void run () {
						r.run();
						Dispatcher.dispatch(stateMachine, TASK_COMPLETION);
					}
				});
			}
		}

		private final State open = new State() {
			public void handle (StateMachine m, Object o) {
				if (o == EXIT) {
					try {
						channel.close();
					} catch (IOException e) {}
				} else {
					m.upwardTo(TOP);
				}
			}
		};

		private final State normal = new State() {
			State next;

			void transitionToClosed () {
				if (next == null) {
					signalSendCompletion(ERROR);
					signalReceiveCompletion(ERROR);
					signalShutdownCompletion(ERROR);
					next = closed;
					stateMachine.transitionTo(next);
				}
			}

			void transitionToClosure () {
				if (next == null) {
					signalSendCompletion(outboundBuffer.hasRemaining());
					signalReceiveCompletion(ERROR);
					sslEngine.closeOutbound();
					Status s = wrap();
					if (s == null) {
						signalShutdownCompletion(ERROR);
						next = closed;
					} else {
						register(SelectionKey.OP_WRITE);
						next = closure;
					}
					stateMachine.transitionTo(next);
				}
			}

			void handleSSLStatus () {
				Status s;
				int p = inboundBuffer.position();
				if (!outboundBuffer.hasRemaining() && !writeBuffer.hasRemaining()) {
					signalSendCompletion(!ERROR);
				}
				do {
					s = null;
					HandshakeStatus hs = sslEngine.getHandshakeStatus();
					if (((hs == HandshakeStatus.NEED_UNWRAP)
						|| (hs == HandshakeStatus.NEED_WRAP)
						|| (hs == HandshakeStatus.NEED_TASK))
						&& (handshakeStatus != HandshakeStatus.NEED_UNWRAP)
						&& (handshakeStatus != HandshakeStatus.NEED_WRAP)
						&& (handshakeStatus != HandshakeStatus.NEED_TASK)
						&& (handshakeCount != Integer.MAX_VALUE))
					{
						handshakeCount++;
					}
					handshakeStatus = hs;
					if (handshakeCount > 1) {
						transitionToClosed();
					} else if (hs == HandshakeStatus.NEED_TASK) {
						submitTask();
					} else {
						if ((hs == HandshakeStatus.NEED_UNWRAP)
							|| (hs == HandshakeStatus.NOT_HANDSHAKING)
								&& (receiveCompletionHandler != null)
								&& (inboundBuffer.position() == p))
						{
							s = unwrap();
							if (s == null) {
								transitionToClosed();
							} else if (s == Status.CLOSED) {
								transitionToClosure();
							} else if (s == Status.BUFFER_UNDERFLOW) {
								register(SelectionKey.OP_READ);
							}
						}
						if ((hs == HandshakeStatus.NEED_WRAP)
							|| (hs == HandshakeStatus.NOT_HANDSHAKING)
								&& (sendCompletionHandler != null)
								&& outboundBuffer.hasRemaining())
						{
							s = wrap();
							if (s == null) {
								transitionToClosed();
							} else {
								register(SelectionKey.OP_WRITE);
							}
						}
					}
				} while (s == Status.OK);
				if (inboundBuffer.position() != p) {
					signalReceiveCompletion(!ERROR);
				}
			}

			void upgrade (SSLEngine e, ByteBuffer b, CompletionHandler h) {
				assert sslEngine == null;
				sslEngine = e;
				inboundBuffer = NULL;
				outboundBuffer = NULL;
				initSSL(b);
				boolean error = false;
				try {
					sslEngine.beginHandshake();
				} catch (SSLException x) {
					error = true;
				}
				if (h != null) {
					h.handle(Connection.this, null, error);
				}
			}

			void send (ByteBuffer b, CompletionHandler h) {
				assert sendCompletionHandler == null;
				sendCompletionHandler = h;
				outboundBuffer = b;
				if (sslEngine == null) {
					writeBuffer = outboundBuffer;
					register(SelectionKey.OP_WRITE);
				} else {
					handleSSLStatus();
				}
			}

			void receive (ByteBuffer b, CompletionHandler h) {
				assert receiveCompletionHandler == null;
				receiveCompletionHandler = h;
				if (inboundBuffer.position() == 0) {
					if (b != null) {
						if (b.hasRemaining() || (b.limit() >= inboundBuffer.limit())) {
							inboundBuffer = b;
						} else {
							b.flip();
							inboundBuffer.put(b);
						}
					}
					if (sslEngine == null) {
						if (!inboundBuffer.hasRemaining()) {
							int n = inboundBuffer.limit();
							try {
								n += channel.socket().getReceiveBufferSize();
							} catch (IOException e) { throw new Error(e); }
							inboundBuffer.flip();
							inboundBuffer = ByteBuffer.allocate(n).put(inboundBuffer);
						}
						readBuffer = inboundBuffer;
						register(SelectionKey.OP_READ);
					} else {
						handleSSLStatus();
					}
				} else {
					if (b != null) {
						inboundBuffer.flip();
						if (b.remaining() >= inboundBuffer.limit()) {
							inboundBuffer = b.put(inboundBuffer);
						} else {
							b.flip();
							int n = b.limit() + inboundBuffer.limit();
							inboundBuffer = ByteBuffer.allocate(n).put(b).put(inboundBuffer);
						}
					}
					signalReceiveCompletion(!ERROR);
				}
			}

			void shutdownOutput (CompletionHandler h) {
				assert shutdownCompletionHandler == null;
				shutdownCompletionHandler = h;
				if (sslEngine == null) {
					signalSendCompletion(ERROR);
					boolean error = false;
					try {
						channel.socket().shutdownOutput();
					} catch (IOException e) {
						error = true;
					}
					signalShutdownCompletion(error);
				} else {
					transitionToClosure();
				}
			}

			void read () {
				int n = -1;
				try {
					n = channel.read(readBuffer);
				} catch (IOException e) {}
				if (n > 0) {
					cancel(SelectionKey.OP_READ);
					if (sslEngine == null) {
						signalReceiveCompletion(!ERROR);
					} else {
						handleSSLStatus();
					}
				} else if (n == -1) {
					if (sslEngine == null) {
						cancel(SelectionKey.OP_READ);
						signalReceiveCompletion(ERROR);
					} else {
						transitionToClosed();
					}
				}
			}

			void write () {
				int n = -1;
				try {
					n = channel.write(writeBuffer);
				} catch (IOException e) {}
				if (!writeBuffer.hasRemaining()) {
					cancel(SelectionKey.OP_WRITE);
					if (sslEngine == null) {
						signalSendCompletion(!ERROR);
					} else {
						handleSSLStatus();
					}
				} else if (n == -1) {
					if (sslEngine == null) {
						cancel(SelectionKey.OP_WRITE);
						signalSendCompletion(ERROR);
					} else {
						transitionToClosed();
					}
				}
			}

			public void handle (StateMachine m, Object o) {
				if (o instanceof Upgrade) {
					Upgrade u = (Upgrade) o;
					upgrade(u.sslEngine, u.buffer, u.completionHandler);
				} else if (o instanceof Send) {
					Send s = (Send) o;
					send(s.buffer, s.completionHandler);
				} else if (o instanceof Receive) {
					Receive r = (Receive) o;
					receive(r.buffer, r.completionHandler);
				} else if (o instanceof Shutdown) {
					Shutdown s = (Shutdown) o;
					shutdownOutput(s.completionHandler);
				} else if (o instanceof Selection) {
					int readyOps = ((Selection) o).readyOps;
					if ((readyOps & SelectionKey.OP_READ) == SelectionKey.OP_READ) {
						read();
					}
					if ((readyOps & SelectionKey.OP_WRITE) == SelectionKey.OP_WRITE) {
						write();
					}
				} else if (o == TASK_COMPLETION) {
					handleSSLStatus();
				} else if (o == CLOSE) {
					transitionToClosed();
				} else {
					m.upwardTo(open);
				}
			}
		};

		private final State closure = new State() {
			public void handle (StateMachine m, Object o) {
				if (o instanceof Upgrade) {
					bounceUpgrade((Upgrade) o);
				} else if (o instanceof Send) {
					bounceSend((Send) o);
				} else if (o instanceof Receive) {
					bounceReceive((Receive) o);
				} else if (o instanceof Shutdown) {
					bounceShutdown((Shutdown) o);
				} else if (o instanceof Selection) {
					int readyOps = ((Selection) o).readyOps;
					if ((readyOps & SelectionKey.OP_WRITE) == SelectionKey.OP_WRITE) {
						int n = -1;
						try {
							n = channel.write(writeBuffer);
						} catch (IOException e) {}
						if (!writeBuffer.hasRemaining()) {
							Status s = wrap();
							if (s == null) {
								signalShutdownCompletion(ERROR);
								m.transitionTo(closed);
							} else if (s == Status.CLOSED) {
								signalShutdownCompletion(!ERROR);
								m.transitionTo(closed);
							}
						} else if (n == -1) {
							signalShutdownCompletion(ERROR);
							m.transitionTo(closed);
						}
					}
				} else if (o == CLOSE) {
					signalShutdownCompletion(ERROR);
					m.transitionTo(closed);
				} else if (o != TASK_COMPLETION) {
					m.upwardTo(open);
				}
			}
		};

		private final State closed = new State() {
			public void handle (StateMachine m, Object o) {
				if (o instanceof Upgrade) {
					bounceUpgrade((Upgrade) o);
				} else if (o instanceof Send) {
					bounceSend((Send) o);
				} else if (o instanceof Receive) {
					bounceReceive((Receive) o);
				} else if (o instanceof Shutdown) {
					bounceShutdown((Shutdown) o);
				}
			}
		};

		public boolean isSecure () {
			return sslEngine != null;
		}

		public void upgradeToSSL (SSLEngine e, ByteBuffer b, CompletionHandler h) {
			assert e != null;
			Upgrade u = new Upgrade();
			u.sslEngine = e;
			u.buffer = b;
			u.completionHandler = h;
			Dispatcher.dispatch(stateMachine, u);
		}

		public void send (ByteBuffer b, CompletionHandler h) {
			assert b != null;
			assert h != null;
			Send s = new Send();
			s.buffer = b;
			s.completionHandler = h;
			Dispatcher.dispatch(stateMachine, s);
		}

		public void receive (ByteBuffer b, CompletionHandler h) {
			assert h != null;
			Receive r = new Receive();
			r.buffer = b;
			r.completionHandler = h;
			Dispatcher.dispatch(stateMachine, r);
		}

		public void shutdownOutput (CompletionHandler h) {
			Shutdown s = new Shutdown();
			s.completionHandler = h;
			Dispatcher.dispatch(stateMachine, s);
		}

		public void close () {
			Dispatcher.dispatch(stateMachine, CLOSE);
		}
	}
}
