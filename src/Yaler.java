// Copyright (c) 2011, Yaler GmbH, Switzerland
// All rights reserved

import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.security.Key;
import java.security.KeyStore;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import org.yaler.core.Cluster;
import org.yaler.core.Dispatcher;
import org.yaler.relay.Policies;
import org.yaler.relay.Relay;
import org.yaler.core.Tasks;

class Yaler {
	private static final char[] PASSWORD = "yaler.org".toCharArray();

	private static Mac mac (KeyStore s) {
		try {
			Mac m = Mac.getInstance("HmacSHA1");
			Key k = s.getKey("yalerkey", PASSWORD);
			m.init(new SecretKeySpec(k.getEncoded(), "HmacSHA1"));
			return m;
		} catch (Exception e) { throw new Error(e); }
	}

	private static SSLContext sslContext (KeyStore s) {
		try {
			SSLContext c = SSLContext.getInstance("TLS");
			KeyManagerFactory f = KeyManagerFactory.getInstance("SunX509");
			f.init(s, PASSWORD);
			c.init(f.getKeyManagers(), null, null);
			return c;
		} catch (Exception e) { throw new Error(e); }
	}

	private static KeyStore keystore () {
		try {
			KeyStore s = KeyStore.getInstance("JKS");
			s.load(new FileInputStream("yalerkeys"), PASSWORD);
			return s;
		} catch (Exception e) { throw new Error(e); }
	}

	private static InetSocketAddress endpoint (String s) {
		InetSocketAddress a = null;
		String[] t = s.split(":");
		if (t.length == 2) {
			try {
				a = new InetSocketAddress(t[0], Integer.parseInt(t[1]));
			} catch (IllegalArgumentException e) {}
		}
		return a;
	}

	public static void main (String[] args) {
		boolean enabled = false;
		assert enabled = true;
		if (!enabled) {
			throw new AssertionError("assertions must be enabled");
		} else {
			Tasks.setupExceptionHandling();
			InetSocketAddress[] relayEndpoints = new InetSocketAddress[1024];
			InetSocketAddress clusterEndpoint = null;
			InetSocketAddress[] seeds = null;
			boolean secure = false, enablePolicies = false;
			String hostname = null, root = null;
			int capacity = Integer.MAX_VALUE, tokencount = 1;
			int i = 0, j = args.length;
			boolean error = i == j;
			if (!error) {
				relayEndpoints[i] = endpoint(args[i]);
				error = relayEndpoints[i] == null;
				i++;
			}
			while (!error && (i != j) && (args[i].charAt(0) != '-')) {
				try {
					relayEndpoints[i] = new InetSocketAddress(
						relayEndpoints[0].getAddress().getHostAddress(),
						Integer.parseInt(args[i]));
				} catch (IllegalArgumentException e) { error = true; }
				i++;
			}
			if (!error && (i < j - 1) && args[i].equals("-hostname")) {
				hostname = args[i + 1];
				i += 2;
			}
			if (!error && (i < j - 1) && args[i].equals("-capacity")) {
				try {
					capacity = Integer.parseInt(args[i + 1]);
				} catch (IllegalArgumentException e) { error = true; }
				i += 2;
			}
			if (!error && (i != j) && args[i].equals("-secure")) {
				secure = true;
				i++;
			}
			if (!error && (i != j) && args[i].equals("-enablepolicies")) {
				enablePolicies = true;
				i++;
			}
			if (!error && (i < j - 1) && args[i].equals("-root")) {
				root = args[i + 1];
				i += 2;
			}
			if (!error && (i < j - 1) && args[i].equals("-cluster")) {
				clusterEndpoint = endpoint(args[i + 1]);
				error = clusterEndpoint == null;
				i += 2;
				if (!error && (i < j - 1) && args[j - 2].equals("-tokencount")) {
					try {
						tokencount = Integer.parseInt(args[j - 1]);
					} catch (IllegalArgumentException e) { error = true; }
					j -= 2;
				}
				seeds = new InetSocketAddress[j - i];
				while (!error && (i != j)) {
					j--;
					seeds[j - i] = endpoint(args[j]);
					error = seeds[j - i] == null;
				}
			}
			if (error || (i != j)) {
				System.err.print("Yaler 2.0\n"
					+ "Usage: Yaler <host>:<port> [port ...] "
					+ "[-hostname <hostname>] [-capacity <capacity>] "
					+ "[-secure] [-enablepolicies] [-root <uri>] "
					+ "[-cluster <host>:<port> ... [-tokencount <tokencount>]]\n");
			} else {
				if ((clusterEndpoint != null) && (hostname == null)) {
					hostname = relayEndpoints[0].getAddress().getHostAddress();
				}
				Relay.init(hostname, root, capacity, tokencount);
				for (InetSocketAddress relayEndpoint: relayEndpoints) {
					if (relayEndpoint != null) {
						SSLContext sslContext = secure? sslContext(keystore()): null;
						Relay.open(relayEndpoint, sslContext);
					}
				}
				if (clusterEndpoint != null) {
					Mac mac = mac(keystore());
					Cluster.join(clusterEndpoint, hostname, tokencount, seeds, mac);
				}
				if (enablePolicies) {
					Policies.enable(relayEndpoints[0].getAddress().getHostAddress());
				}
				Dispatcher.run();
			}
		}
	}
}