// Copyright (c) 2011, Yaler GmbH, Switzerland
// All rights reserved

package org.yaler.relay;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.concurrent.Semaphore;

import org.yaler.core.Connections.CompletionHandler;
import org.yaler.core.Connections.Connection;
import org.yaler.core.Tasks;

public final class Policies {
	private Policies () {}

	private static final byte[]
		SILVERLIGHT_POLICY = new byte[] {
			'<','a','c','c','e','s','s','-','p','o','l','i','c','y','>','<','c','r',
			'o','s','s','-','d','o','m','a','i','n','-','a','c','c','e','s','s','>',
			'<','p','o','l','i','c','y','>','<','a','l','l','o','w','-','f','r','o',
			'm','>','<','d','o','m','a','i','n',' ','u','r','i','=','"','*','"','/',
			'>','<','/','a','l','l','o','w','-','f','r','o','m','>','<','g','r','a',
			'n','t','-','t','o','>','<','s','o','c','k','e','t','-','r','e','s','o',
			'u','r','c','e',' ','p','o','r','t','=','"','4','5','0','2','-','4','5',
			'3','4','"',' ','p','r','o','t','o','c','o','l','=','"','t','c','p','"',
			'/','>','<','/','g','r','a','n','t','-','t','o','>','<','/','p','o','l',
			'i','c','y','>','<','/','c','r','o','s','s','-','d','o','m','a','i','n',
			'-','a','c','c','e','s','s','>','<','/','a','c','c','e','s','s','-','p',
			'o','l','i','c','y','>'};

	private static void enable (
		final String hostname, final int port, final byte[] policy)
	{
		Tasks.newSingleThreadExecutor().execute(new Runnable() {
			public void run () {
				final Semaphore s = new Semaphore(512, true);
				ServerSocketChannel sc;
				try {
					sc = ServerSocketChannel.open();
					sc.socket().setReuseAddress(true);
					sc.socket().bind(new InetSocketAddress(hostname, port), 64);
				} catch (Exception e) { throw new Error(e); }
				while (true) {
					SocketChannel c;
					try {
						s.acquire();
						c = sc.accept();
						c.configureBlocking(false);
						c.socket().setTcpNoDelay(true);
					} catch (Exception e) { throw new Error(e); }
					new Connection(c, null).send(
						ByteBuffer.wrap(policy),
						new CompletionHandler() {
							public void handle (Connection c, ByteBuffer b, boolean error) {
								s.release();
								c.shutdownOutput();
								c.close();
							}
						});
				}
			}
		});
	}

	public static void enable (String hostname) {
		enable(hostname, 943, SILVERLIGHT_POLICY);
	}
}
