// Copyright (c) 2010 - 2018, Yaler Gmbh, Switzerland. All rights reserved.

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
import org.yaler.core.Tasks;
import org.yaler.relay.Relay;

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

	private static InetSocketAddress endpoint (String host, String port) {
		InetSocketAddress a;
		try {
			a = new InetSocketAddress(host, Integer.parseInt(port));
		} catch (IllegalArgumentException e) {
			a = null;
		}
		return a;
	}

	public static void main (String[] args) {
		boolean enabled = false;
		assert enabled = true;
		if (!enabled) {
			throw new AssertionError("assertions must be enabled");
		} else {
			final int NONE = 0, TLS = 1, DTLS = 2;
			Tasks.setupExceptionHandling();
			InetSocketAddress[] relayEndpoints = new InetSocketAddress[1024];
			int[] relayEndpointSecurity = new int[1024];
			InetSocketAddress clusterEndpoint = null;
			InetSocketAddress[] seeds = null;
			String[] hostnames = null;
			String root = null;
			int capacity = Integer.MAX_VALUE;
			int tokencount = 1;
			int i = 0;
			int j = args.length;
			boolean error = i == j;
			if (!error) {
				String s = args[i];
				int k = s.lastIndexOf(':');
				if (k >= 0) {
					if ((k >= 4) && (s.startsWith("tls:") || s.startsWith("ssl:"))) {
						relayEndpointSecurity[i] = TLS;
						relayEndpoints[i] = endpoint(s.substring(4, k), s.substring(k + 1));
					} else if ((k >= 5) && s.startsWith("dtls:")) {
						relayEndpointSecurity[i] = DTLS;
						relayEndpoints[i] = endpoint(s.substring(5, k), s.substring(k + 1));
					} else {
						relayEndpoints[i] = endpoint(s.substring(0, k), s.substring(k + 1));
					}
				}
				error = relayEndpoints[i] == null;
				i++;
			}
			if (!error && (i != j) && (args[i].charAt(0) != '-')) {
				String s = relayEndpoints[0].getAddress().getHostAddress();
				do {
					String t = args[i];
					if (t.startsWith("tls:") || t.startsWith("ssl:")) {
						relayEndpointSecurity[i] = TLS;
						relayEndpoints[i] = endpoint(s, t.substring(4));
					} else if (t.startsWith("dtls:")) {
						relayEndpointSecurity[i] = DTLS;
						relayEndpoints[i] = endpoint(s, t.substring(5));
					} else {
						relayEndpoints[i] = endpoint(s, t);
					}
					error = relayEndpoints[i] == null;
					i++;
				} while (!error && (i != j) && (args[i].charAt(0) != '-'));
			}
			if (!error && (i < j - 1) && args[i].equals("-hostnames")) {
				i++;
				int k = i;
				while ((k != j) && (args[k].charAt(0) != '-')) {
					k++;
				}
				error = k == i;
				if (!error) {
					hostnames = new String[k - i];
					System.arraycopy(args, i, hostnames, 0, k - i);
					i = k;
				}
			}
			if (!error && (i < j - 1) && args[i].equals("-capacity")) {
				try {
					capacity = Integer.parseInt(args[i + 1]);
				} catch (IllegalArgumentException e) {
					error = true;
				}
				i += 2;
			}
			if (!error && (i < j - 1) && args[i].equals("-root")) {
				root = args[i + 1];
				i += 2;
			}
			if (!error && (i < j - 1) && args[i].equals("-cluster")) {
				String s = args[i + 1];
				int k = s.lastIndexOf(':');
				if (k >= 0) {
					clusterEndpoint = endpoint(s.substring(0, k), s.substring(k + 1));
				}
				error = clusterEndpoint == null;
				i += 2;
				if (!error && (i < j - 1) && args[j - 2].equals("-tokencount")) {
					try {
						tokencount = Integer.parseInt(args[j - 1]);
					} catch (IllegalArgumentException e) {
						error = true;
					}
					j -= 2;
				}
				seeds = new InetSocketAddress[j - i];
				while (!error && (i != j)) {
					j--;
					s = args[j];
					k = s.lastIndexOf(':');
					if (k >= 0) {
						seeds[j - i] = endpoint(s.substring(0, k), s.substring(k + 1));
					}
					error = seeds[j - i] == null;
				}
			}
			if (error || (i != j)) {
				System.err.println("Yaler v2.1.0\n"
					+ "Usage: Yaler [ssl:]<host>:<port> [[ssl:]port ...] "
					+ "[-hostnames <hostname> ...] [-capacity <capacity>] [-root <uri>] "
					+ "[-cluster <host>:<port> ... [-tokencount <tokencount>]]");
			} else {
				if ((clusterEndpoint != null) && (hostnames == null)) {
					hostnames = new String[] {
						relayEndpoints[0].getAddress().getHostAddress()};
				}
				Relay.init(hostnames, root, capacity, tokencount);
				i = 0; j = relayEndpoints.length;
				while ((i != j) && (relayEndpoints[i] != null)) {
					if (relayEndpointSecurity[i] == NONE) {
						Relay.openConnectionListener(
							relayEndpoints[i], null);
					} else if (relayEndpointSecurity[i] == TLS) {
						Relay.openConnectionListener(
							relayEndpoints[i], sslContext(keystore()));
					} else {
						assert relayEndpointSecurity[i] == DTLS;
						Relay.openDatagramListener(relayEndpoints[i]);
					}
					i++;
				}
				if (clusterEndpoint != null) {
					Mac mac = mac(keystore());
					Cluster.join(clusterEndpoint, hostnames[0], tokencount, seeds, mac);
				}
				Dispatcher.run();
			}
		}
	}
}
