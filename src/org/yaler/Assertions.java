// Copyright (c) 2010, Oberon microsystems AG, Switzerland
// All rights reserved

package org.yaler;

public final class Assertions {
	private Assertions () {}

	public static void enable () {
		boolean enabled = false;
		assert enabled = true;
		if (!enabled) {
			throw new AssertionError("assertions must be enabled");
		}
	}
}