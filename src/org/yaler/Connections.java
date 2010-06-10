// Copyright (c) 2010, Oberon microsystems AG, Switzerland
// All rights reserved

package org.yaler;

import java.io.IOError;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;

import org.yaler.Assertions;
import org.yaler.Dispatcher;
import org.yaler.Dispatcher.Selection;
import org.yaler.StateMachines.State;
import org.yaler.StateMachines.StateMachine;

public final class Connections {
	private Connections () {}

	public static interface CompletionHandler {
		public void handle (Connection c, ByteBuffer b, boolean error);
	}

	private static final class Send {
		ByteBuffer buffer;
		CompletionHandler completionHandler;
	}

	private static final class Receive {
		ByteBuffer buffer;
		CompletionHandler completionHandler;
	}

	public static final class Connection {
		private static final boolean
			ERROR = true;
		private static final Object
			CLOSE = new Object(),
			SHUTDOWN_OUTPUT = new Object(),
			TASK_COMPLETION = new Object();
		private static final ByteBuffer
			NULL = ByteBuffer.allocate(0);
		private static final ExecutorService
			executor = Executors.newSingleThreadExecutor();

		private final StateMachine stateMachine = new StateMachine();
		private final SocketChannel channel;
		private final SSLEngine sslEngine;
		private CompletionHandler sendCompletionHandler, receiveCompletionHandler;
		private ByteBuffer inboundBuffer, outboundBuffer, readBuffer, writeBuffer;
		private int interestOps;

		static { Assertions.enable(); }

		public Connection (SocketChannel c, SSLEngine e) {
			assert c != null;
			assert !c.isBlocking();
			channel = c;
			sslEngine = e;
			inboundBuffer = NULL;
			outboundBuffer = NULL;
			if (sslEngine != null) {
				int n = sslEngine.getSession().getPacketBufferSize();
				readBuffer = ByteBuffer.allocateDirect(n);
				writeBuffer = ByteBuffer.allocateDirect(n);
				writeBuffer.flip();
			}
			stateMachine.start(normal);
		}

		private void bounceSend (Send s) {
			s.completionHandler.handle(this, s.buffer, ERROR);
		}

		private void bounceReceive (Receive r) {
			r.completionHandler.handle(this, r.buffer, ERROR);
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
						readBuffer = ByteBuffer.allocateDirect(n).put(readBuffer);
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
						writeBuffer = ByteBuffer.allocateDirect(n).put(writeBuffer);
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
				executor.submit(new Runnable() {
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
					if (hs == HandshakeStatus.NEED_TASK) {
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
				if (inboundBuffer == NULL) {
					if (b != null) {
						inboundBuffer = b;
					}
					if (sslEngine == null) {
						if (!inboundBuffer.hasRemaining()) {
							int n = inboundBuffer.limit();
							try {
								n += channel.socket().getReceiveBufferSize();
							} catch (IOException e) { throw new IOError(e); }
							inboundBuffer.flip();
							inboundBuffer = ByteBuffer.allocateDirect(n).put(inboundBuffer);
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
							ByteBuffer x;
							int n = b.limit() + inboundBuffer.limit();
							if (b.isDirect()) {
								x = ByteBuffer.allocateDirect(n);
							} else {
								x = ByteBuffer.allocate(n);
							}
							inboundBuffer = x.put(b).put(inboundBuffer);
						}
					}
					signalReceiveCompletion(!ERROR);
				}
			}

			void read () {
				try {
					int n = channel.read(readBuffer);
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
				} catch (IOException e) {
					if (sslEngine == null) {
						cancel(SelectionKey.OP_READ);
						signalReceiveCompletion(ERROR);
					} else {
						transitionToClosed();
					}
				}
			}

			void write () {
				try {
					channel.write(writeBuffer);
					if (!writeBuffer.hasRemaining()) {
						cancel(SelectionKey.OP_WRITE);
						if (sslEngine == null) {
							signalSendCompletion(!ERROR);
						} else {
							handleSSLStatus();
						}
					}
				} catch (IOException e) {
					if (sslEngine == null) {
						cancel(SelectionKey.OP_WRITE);
						signalSendCompletion(ERROR);
					} else {
						transitionToClosed();
					}
				}
			}

			void shutdownOutput () {
				if (sslEngine == null) {
					signalSendCompletion(ERROR);
					try {
						channel.socket().shutdownOutput();
					} catch (IOException e) {}
				} else {
					transitionToClosure();
				}
			}

			void close () {
				if (sslEngine == null) {
					transitionToClosed();
				} else {
					transitionToClosure();
				}
			}

			public void handle (StateMachine m, Object o) {
				if (o instanceof Send) {
					Send s = (Send) o;
					send(s.buffer, s.completionHandler);
				} else if (o instanceof Receive) {
					Receive r = (Receive) o;
					receive(r.buffer, r.completionHandler);
				} else if (o instanceof Selection) {
					int readyOps = ((Selection) o).readyOps;
					if ((readyOps & SelectionKey.OP_READ) != 0) {
						read();
					}
					if ((readyOps & SelectionKey.OP_WRITE) != 0) {
						write();
					}
				} else if (o == TASK_COMPLETION) {
					handleSSLStatus();
				} else if (o == SHUTDOWN_OUTPUT) {
					shutdownOutput();
				} else if (o == CLOSE) {
					close();
				} else {
					m.upwardTo(open);
				}
			}
		};

		private final State closure = new State() {
			public void handle (StateMachine m, Object o) {
				if (o instanceof Send) {
					bounceSend((Send) o);
				} else if (o instanceof Receive) {
					bounceReceive((Receive) o);
				} else if (o instanceof Selection) {
					if ((((Selection) o).readyOps & SelectionKey.OP_WRITE) != 0) {
						try {
							channel.write(writeBuffer);
							if (!writeBuffer.hasRemaining()) {
								Status s = wrap();
								if ((s == null) || (s == Status.CLOSED)) {
									m.transitionTo(closed);
								}
							}
						} catch (IOException e) {
							m.transitionTo(closed);
						}
					}
				} else if
					((o != TASK_COMPLETION) && (o != SHUTDOWN_OUTPUT) && (o != CLOSE))
				{
					m.upwardTo(open);
				}
			}
		};

		private final State closed = new State() {
			public void handle (StateMachine m, Object o) {
				if (o instanceof Send) {
					bounceSend((Send) o);
				} else if (o instanceof Receive) {
					bounceReceive((Receive) o);
				}
			}
		};

		public boolean isSecure () {
			return sslEngine != null;
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

		public void shutdownOutput () {
			Dispatcher.dispatch(stateMachine, SHUTDOWN_OUTPUT);
		}

		public void close () {
			Dispatcher.dispatch(stateMachine, CLOSE);
		}
	}
}