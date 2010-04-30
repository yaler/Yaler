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

	public static enum Error {
		NONE,
		CLOSED,
		INBOUND_CLOSED,
		OPERATION_PENDING
	}

	public static interface CompletionHandler {
		public void handle (Connection c, ByteBuffer b, Error e);
	}

	private static final class SendMessage {
		ByteBuffer buffer;
		CompletionHandler completionHandler;
	}

	private static final class ReceiveMessage {
		ByteBuffer buffer;
		CompletionHandler completionHandler;
	}

	public static final class Connection {
		private static final Object
			CLOSE_MESSAGE = new Object(),
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
			stateMachine.start(open);
		}

		private void bounceSendMessage (SendMessage m, Error e) {
			m.completionHandler.handle(this, m.buffer, e);
		}

		private void bounceReceiveMessage (ReceiveMessage m, Error e) {
			m.completionHandler.handle(this, m.buffer, e);
		}

		private void signalSendCompletion (Error e) {
			if (sendCompletionHandler != null) {
				sendCompletionHandler.handle(this, outboundBuffer, e);
				outboundBuffer = NULL;
				sendCompletionHandler = null;
			}
		}

		private void signalReceiveCompletion (Error e) {
			if (receiveCompletionHandler != null) {
				receiveCompletionHandler.handle(this, inboundBuffer, e);
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

		private void enterClosure () {
			try {
				sslEngine.closeInbound();
			} catch (SSLException e) {}
			sslEngine.closeOutbound();
		}

		private final State open = new State() {
			void handleSSLStatus () {
				int p = inboundBuffer.position();
				Status s;
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
								stateMachine.transitionTo(closed);
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
								stateMachine.transitionTo(closed);
							} else {
								register(SelectionKey.OP_WRITE);
							}
						}
					}
				} while (s == Status.OK);
				if (inboundBuffer.position() != p) {
					signalReceiveCompletion(Error.NONE);
				} else if (sslEngine.isInboundDone()) {
					signalReceiveCompletion(Error.INBOUND_CLOSED);
				}
				if (!outboundBuffer.hasRemaining()) {
					signalSendCompletion(Error.NONE);
				}
				if (sslEngine.isOutboundDone()) {
					stateMachine.transitionTo(closed);
				}
			}

			void handleSendMessage (SendMessage m) {
				sendCompletionHandler = m.completionHandler;
				outboundBuffer = m.buffer;
				if (sslEngine == null) {
					writeBuffer = outboundBuffer;
					register(SelectionKey.OP_WRITE);
				} else {
					handleSSLStatus();
				}
			}

			void handleReceiveMessage (ReceiveMessage m) {
				receiveCompletionHandler = m.completionHandler;
				ByteBuffer b = m.buffer;
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
					signalReceiveCompletion(Error.NONE);
				}
			}

			private void handleSelection (int readyOps) {
				try {
					if ((readyOps & SelectionKey.OP_READ) != 0) {
						int n = channel.read(readBuffer);
						if (n > 0) {
							cancel(SelectionKey.OP_READ);
							if (sslEngine == null) {
								signalReceiveCompletion(Error.NONE);
							} else {
								handleSSLStatus();
							}
						} else if (n == -1) {
							cancel(SelectionKey.OP_READ);
							if (sslEngine == null) {
								signalReceiveCompletion(Error.INBOUND_CLOSED);
							} else {
								enterClosure();
								handleSSLStatus();
							}
						}
					}
					if ((readyOps & SelectionKey.OP_WRITE) != 0) {
						channel.write(writeBuffer);
						if (!writeBuffer.hasRemaining()) {
							cancel(SelectionKey.OP_WRITE);
							if (sslEngine == null) {
								signalSendCompletion(Error.NONE);
							} else {
								handleSSLStatus();
							}
						}
					}
				} catch (IOException e) {
					stateMachine.transitionTo(closed);
				}
			}

			public void handle (StateMachine m, Object o) {
				if (o instanceof SendMessage) {
					if (sendCompletionHandler != null) {
						bounceSendMessage((SendMessage) o, Error.OPERATION_PENDING);
					} else {
						handleSendMessage((SendMessage) o);
					}
				} else if (o instanceof ReceiveMessage) {
					if (receiveCompletionHandler != null) {
						bounceReceiveMessage((ReceiveMessage) o, Error.OPERATION_PENDING);
					} else {
						handleReceiveMessage((ReceiveMessage) o);
					}
				} else if (o == CLOSE_MESSAGE) {
					if (sslEngine == null) {
						m.transitionTo(closed);
					} else {
						enterClosure();
						handleSSLStatus();
					}
				} else if (o instanceof Selection) {
					handleSelection(((Selection) o).readyOps);
				} else if (o == TASK_COMPLETION) {
					handleSSLStatus();
				} else if (o == EXIT) {
					try {
						channel.close();
					} catch (IOException e) {}
					signalSendCompletion(Error.CLOSED);
					signalReceiveCompletion(Error.CLOSED);
				} else {
					m.upwardTo(TOP);
				}
			}
		};

		private final State closed = new State() {
			public void handle (StateMachine m, Object o) {
				if (o instanceof SendMessage) {
					bounceSendMessage((SendMessage) o, Error.CLOSED);
				} else if (o instanceof ReceiveMessage) {
					bounceReceiveMessage((ReceiveMessage) o, Error.CLOSED);
				}
			}
		};

		public boolean isSecure () {
			return sslEngine != null;
		}

		public void send (ByteBuffer b, CompletionHandler h) {
			assert b != null;
			assert h != null;
			SendMessage m = new SendMessage();
			m.buffer = b;
			m.completionHandler = h;
			Dispatcher.dispatch(stateMachine, m);
		}

		public void receive (ByteBuffer b, CompletionHandler h) {
			assert h != null;
			ReceiveMessage m = new ReceiveMessage();
			m.buffer = b;
			m.completionHandler = h;
			Dispatcher.dispatch(stateMachine, m);
		}

		public void close () {
			Dispatcher.dispatch(stateMachine, CLOSE_MESSAGE);
		}
	}
}