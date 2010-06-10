// Copyright (c) 2010, Oberon microsystems AG, Switzerland
// All rights reserved

package org.yaler;

import java.io.IOError;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.nio.channels.ServerSocketChannel;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import org.yaler.Assertions;
import org.yaler.Connections.CompletionHandler;
import org.yaler.Connections.Connection;
import org.yaler.Dispatcher;
import org.yaler.Dispatcher.Selection;
import org.yaler.StateMachines.State;
import org.yaler.StateMachines.StateMachine;

public final class Relay {
	private Relay () {}

	static { Assertions.enable(); }

	private static final class SendCompletion {
		Connection connection;
		ByteBuffer buffer;
		boolean error;
	}

	private static final class ReceiveCompletion {
		Connection connection;
		ByteBuffer buffer;
		boolean error;
	}

	private static final class Client {
		Connection connection;
		ByteBuffer buffer;
	}

	private static final class ConnectionHandler {
		static final ConcurrentLinkedQueue<ConnectionHandler>
			connectionHandlers = new ConcurrentLinkedQueue<ConnectionHandler>();
		static final ScheduledExecutorService
			executor = Executors.newSingleThreadScheduledExecutor();
		static final Object TIMEOUT = new Object();
		static final byte HT = 9, LF = 10, CR = 13, SP = 32, QUOTE = 39;
		static final ByteBuffer
			switchingProtocols = ByteBuffer.wrap(new byte[] {
				'H','T','T','P','/','1','.','1', SP,'1','0','1', SP,'S','w','i','t','c',
				'h','i','n','g', SP,'P','r','o','t','o','c','o','l','s', CR, LF,'U','p',
				'g','r','a','d','e',':', SP,'P','T','T','H','/','1','.','0', CR, LF,'C',
				'o','n','n','e','c','t','i','o','n',':', SP,'U','p','g','r','a','d','e',
				 CR, LF, CR, LF}),
			noConnection = ByteBuffer.wrap(new byte[] {
				'H','T','T','P','/','1','.','1', SP,'2','0','4', SP,'N','o', SP,'C','o',
				'n','n','e','c','t','i','o','n', CR, LF, CR, LF}),
			gatewayTimeout = ByteBuffer.wrap(new byte[] {
				'H','T','T','P','/','1','.','1', SP,'5','0','4', SP,'G','a','t','e','w',
				'a','y', SP,'T','i','m','e','o','u','t', CR, LF,'C','o','n','t','e','n',
				't','-','L','e','n','g','t','h',':', SP,'1','5', CR, LF, CR, LF,'G','a',
				't','e','w','a','y', SP,'T','i','m','e','o','u','t'});

		static {
			final ConnectionHandler sentinel = new ConnectionHandler(null);
			executor.scheduleWithFixedDelay(new Runnable() {
				public void run() {
					connectionHandlers.offer(sentinel);
					ConnectionHandler h = connectionHandlers.poll();
					while (h != sentinel) {
						if (h.alive) {
							h.alive = false;
							connectionHandlers.offer(h);
						} else {
							Dispatcher.dispatch(h.stateMachine, TIMEOUT);
						}
						h = connectionHandlers.poll();
					}
				}
			}, 30, 30, TimeUnit.SECONDS);
		}

		final StateMachine stateMachine = new StateMachine();
		volatile boolean alive = true, readyToAccept = false;
		Connection connection;
		Object domain;
		Client client;

		ConnectionHandler (Connection c) {
			if (c != null) {
				connection = c;
				stateMachine.start(receivingRequest);
				connectionHandlers.offer(this);
			}
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
			public void handle (StateMachine m, Object o) {
				if (o == TIMEOUT) {
					m.transitionTo(closed);
				} else if (o == EXIT) {
					if (connection != null) {
						connection.shutdownOutput();
						connection.close();
					}
					if (client != null) {
						client.connection.shutdownOutput();
						client.connection.close();
					}
				} else {
					m.upwardTo(TOP);
				}
			}
		};

		final State receivingRequest = new State() {
			static final int // parser states
				BEFORE_DOMAIN = 0, DOMAIN = 1, AFTER_DOMAIN = 2,
				UPGRADE_HEADER = 3, UPGRADE_HEADER_LF = 4, DONE = 5;
			int parserState, parserPosition;
			boolean upgradeToPTTH;

			void parse (ByteBuffer b) {
				assert b != null;
				assert parserState != DONE;
				int s = parserState;
				int p = parserPosition;
				int q = b.position();
				do {
					byte x = b.get(p);
					if (s == BEFORE_DOMAIN) {
						if (x == SP) {
							domain = new StringBuilder();
							s = DOMAIN;
						}
					} else if (s == DOMAIN) {
						StringBuilder d = (StringBuilder) domain;
						if (('a' <= x) && (x <= 'z') || ('0' <= x) && (x <= '9')
							|| (x == '-') || (x == '.') || (x == '_') || (x == '~')
							|| (x == '%') || (x == '!') || (x == '$') || (x == '&')
							|| (x == '(') || (x == ')') || (x == '*') || (x == '+')
							|| (x == ',') || (x == ';') || (x == '=') || (x == QUOTE))
						{
							d.append((char) x);
						} else if (('A' <= x) && (x <= 'Z')) {
							d.append((char) (x + 32));
						} else {
							if (d.length() == 0) {
								if (x == '/') {
									d.append('/');
								} else if ((x != SP) && (x != HT)) {
									domain = "/";
									s = AFTER_DOMAIN;
								}
							} else {
								domain = d.toString();
								s = AFTER_DOMAIN;
							}
						}
					} else if (s == AFTER_DOMAIN) {
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
							}
						}
					} else if (s == UPGRADE_HEADER) {
						if ((x == ',') || (x == SP) || (x == HT) || (x == LF) || (x == CR))
						{
							if (p >= 9) {
								byte y = b.get(p - 9);
								if (((y == ':') || (y == ',') || (y == SP) || (y == HT))
									&& (b.get(p - 8) == 'P') && (b.get(p - 7) == 'T')
									&& (b.get(p - 6) == 'T') && (b.get(p - 5) == 'H')
									&& (b.get(p - 4) == '/') && (b.get(p - 3) == '1')
									&& (b.get(p - 2) == '.') && (b.get(p - 1) == '0'))
								{
									upgradeToPTTH = true;
								}
							}
							if (x == LF) {
								s = UPGRADE_HEADER_LF;
							}
						}
					} else {
						assert s == UPGRADE_HEADER_LF;
						if ((x == SP) || (x == HT)) {
							s = UPGRADE_HEADER;
						} else if (x == LF) {
							s = DONE;
						} else {
							s = AFTER_DOMAIN;
						}
					}
					p++;
				} while ((p != q) && (s != DONE));
				parserPosition = p;
				parserState = s;
			}

			public void handle (StateMachine m, Object o) {
				if (o == ENTER) {
					alive = true;
					parserState = 0;
					parserPosition = 0;
					upgradeToPTTH = false;
					connection.receive(null, receiveCompleted);
				} else if (o instanceof ReceiveCompletion) {
					ReceiveCompletion rc = (ReceiveCompletion) o;
					if (!rc.error) {
						ByteBuffer b = rc.buffer;
						parse(b);
						if (parserState != DONE) {
							if (b.position() < 2048) {
								alive = true;
								connection.receive(b, receiveCompleted);
							} else {
								m.transitionTo(closed);
							}
						} else {
							if (upgradeToPTTH) {
								m.transitionTo(accepting);
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
					alive = true;
					final Object d = domain;
					executor.execute(new Runnable() {
						public void run () {
							ConnectionHandler server = null;
							for (ConnectionHandler h: connectionHandlers) {
								if (h.readyToAccept && h.domain.equals(d)) {
									h.readyToAccept = false;
									server = h;
									break;
								}
							}
							Dispatcher.dispatch(stateMachine, server);
						}
					});
				} else if (o instanceof ConnectionHandler) {
					ConnectionHandler server = (ConnectionHandler) o;
					Dispatcher.dispatch(server.stateMachine, client);
					client = null;
					m.transitionTo(closed);
				} else if (o == null) {
					client.connection.send(gatewayTimeout.duplicate(), sendCompleted);
					m.transitionTo(sendingResponse);
				} else if (o == TIMEOUT) {
					alive = true;
					connectionHandlers.offer(ConnectionHandler.this);
				} else {
					m.upwardTo(open);
				}
			}
		};

		final State accepting = new State() {
			public void handle (StateMachine m, Object o) {
				if (o == ENTER) {
					alive = true;
					readyToAccept = true;
				} else if (o instanceof Client) {
					client = (Client) o;
					m.transitionTo(upgrading);
				} else if (o == TIMEOUT) {
					if (readyToAccept) {
						readyToAccept = false;
						m.transitionTo(renewing);
					}
					alive = true;
					connectionHandlers.offer(ConnectionHandler.this);
				} else {
					m.upwardTo(open);
				}
			}
		};

		final State renewing = new State() {
			public void handle (StateMachine m, Object o) {
				if (o == ENTER) {
					alive = true;
					connection.send(noConnection.duplicate(), sendCompleted);
				} else if (o instanceof SendCompletion) {
					SendCompletion sc = (SendCompletion) o;
					if (!sc.error) {
						m.transitionTo(receivingRequest);
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
					alive = true;
					connection.send(switchingProtocols.duplicate(), sendCompleted);
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
					alive = true;
					error = false;
					connection.send(client.buffer, sendCompleted);
					connection.receive(null, receiveCompleted);
					client.buffer = null;
				} else if (o instanceof SendCompletion) {
					SendCompletion sc = (SendCompletion) o;
					if (!sc.error) {
						ByteBuffer b = sc.buffer;
						b.clear();
						alive = true;
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
						b.flip();
						alive = true;
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

		final State sendingResponse = new State() {
			public void handle (StateMachine m, Object o) {
				if (o == ENTER) {
					alive = true;
				} else if (o instanceof SendCompletion) {
					m.transitionTo(closed);
				} else {
					m.upwardTo(open);
				}
			}
		};

		final State closed = new State() {
			public void handle (StateMachine m, Object o) {}
		};
	}

	public static void start (final ServerSocketChannel s, final SSLContext c) {
		assert s != null;
		assert !s.isBlocking();
		new StateMachine().start(new State() {
			public void handle (StateMachine m, Object o) {
				if (o == ENTER) {
					Dispatcher.register(s, SelectionKey.OP_ACCEPT, m);
				} else if (o instanceof Selection) {
					try {
						SocketChannel x = s.accept();
						x.socket().setTcpNoDelay(true);
						x.configureBlocking(false);
						SSLEngine e;
						if (c != null) {
							e = c.createSSLEngine();
							e.setUseClientMode(false);
						} else {
							e = null;
						}
						new ConnectionHandler(new Connection(x, e));
					} catch (IOException e) { throw new IOError(e); }
				} else {
					m.upwardTo(TOP);
				}
			}
		});
	}
}
