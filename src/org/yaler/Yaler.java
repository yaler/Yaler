// Copyright (c) 2010, Oberon microsystems AG, Switzerland
// All rights reserved

package org.yaler;

import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.channels.ServerSocketChannel;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.yaler.Dispatcher;
import org.yaler.Relay;

class Yaler {
	private static final String VERSION = "1.0";

	public static void main (String[] args) throws Exception {
		boolean error = false, secure = false;
		InetSocketAddress endpoint = null;
		for (String s: args) {
			if (s.toLowerCase().equals("-secure")) {
				secure = true;
			} else if (endpoint == null) {
				String[] t = s.split(":");
				if (t.length == 2) {
					try {
						endpoint = new InetSocketAddress(t[0], Integer.parseInt(t[1]));
					} catch (IllegalArgumentException e) {
						error = true;
					}
				} else {
					error = true;
				}
			} else {
				error = true;
			}
		}
		if (error || (endpoint == null)) {
			System.err.println("Yaler " + VERSION);
			System.err.println("Usage: org.yaler.Yaler [-secure] <endpoint>:<port>");
		} else {
			SSLContext sslc = null;
			if (secure) {
				char[] password = "org.yaler".toCharArray();
				KeyStore ks = KeyStore.getInstance("jks");
				ks.load(new FileInputStream("yalerkeys"), password);
				KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
				kmf.init(ks, password);
				TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
				tmf.init(ks);
				sslc = SSLContext.getInstance("TLS");
				sslc.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			}
			ServerSocketChannel c = ServerSocketChannel.open();
			c.configureBlocking(false);
			ServerSocket s = c.socket();
			s.setReuseAddress(true);
			s.bind(endpoint, 64);
			Relay.start(c, sslc);
			Dispatcher.run();
		}
	}
}