// Copyright (c) 2010, Oberon microsystems AG, Switzerland
// All rights reserved

// This module is based on Miro Samek's QEP event processor published in the
// book "Practical UML Statecharts in C/C++, Second Edition".

package org.yaler;

import org.yaler.Assertions;

public final class StateMachines {
	private StateMachines () {}

	public static interface State {
		public void handle (StateMachine m, Object o);

		public static final State TOP = new State() {
			public void handle (StateMachine m, Object o) {
				assert false;
			}
		};

		public static final Object
			ENTER = new Object(),
			EXIT = new Object(),
			INIT = new Object(),
			UPWARD = new Object();
	}

	public static final class StateMachine {
		private final State[] path = new State[8];
		private State state, transitionTo, upwardTo;
		private boolean barrier;

		static { Assertions.enable(); }

		public void transitionTo (State s) {
			assert barrier;
			assert transitionTo == null;
			assert upwardTo == null;
			assert s != null;
			assert s != State.TOP;
			transitionTo = s;
		}

		public void upwardTo (State s) {
			assert barrier;
			assert transitionTo == null;
			assert upwardTo == null;
			assert s != null;
			upwardTo = s;
		}

		private State superState (State s) {
			State result;
			transitionTo = null;
			upwardTo = null;
			s.handle(this, State.UPWARD);
			assert transitionTo == null;
			if (upwardTo == null) {
				result = State.TOP;
			} else {
				assert upwardTo != s;
				result = upwardTo;
			}
			return result;
		}

		private void dispatchEnter (State s, State superState) {
			assert s != superState;
			transitionTo = null;
			upwardTo = null;
			s.handle(this, State.ENTER);
			assert transitionTo == null;
			assert (upwardTo == null) || (upwardTo == superState)
				|| (superState == null) && (upwardTo != s);
		}

		private void dispatchExit (State s, State superState) {
			assert s != superState;
			transitionTo = null;
			upwardTo = null;
			s.handle(this, State.EXIT);
			assert transitionTo == null;
			assert (upwardTo == null) || (upwardTo == superState)
				|| (superState == null) && (upwardTo != s);
		}

		private State dispatchInit (State s, State superState) {
			assert s != superState;
			State result;
			transitionTo = null;
			upwardTo = null;
			s.handle(this, State.INIT);
			if (transitionTo != null) {
				assert (transitionTo != s) && (transitionTo != superState);
				result = transitionTo;
			} else {
				assert (upwardTo == null) || (upwardTo == superState)
					|| (superState == null) && (upwardTo != s);
				result = s;
			}
			return result;
		}

		private State enterState (State s, State ancestor) {
			assert s != ancestor;
			int i = path.length - 1;
			do {
				assert i > 0;
				i--;
				int j = 0;
				path[0] = s;
				do {
					j++;
					path[j] = superState(path[j - 1]);
				} while (path[j] != ancestor);
				do {
					j--;
					dispatchEnter(path[j], path[j + 1]);
				} while (j != 0);
				s = dispatchInit(path[0], path[1]);
				ancestor = path[0];
			} while (s != ancestor);
			return s;
		}

		private State processTransition (State s, State target) {
			// see StateMachines.StateMachine.processTransition.png
			State result;
			if (s == target) { // (a)
				dispatchExit(s, null);
				dispatchEnter(target, null);
				result = dispatchInit(target, null);
			} else { // (b), (c), (d), (e), (f), (g)
				int e; // number of states to enter
				path[0] = target;
				path[1] = superState(target);
				if (s == path[1]) { // (b)
					e = 1;
				} else { // (c), (d), (e), (f), (g)
					State s1 = superState(s);
					if (s1 == path[1]) { // (c)
						dispatchExit(s, s1);
						e = 1;
					} else if (s1 == target) { // (d)
						dispatchExit(s, s1);
						e = 0;
					} else { // (e), (f), (g)
						e = 1;
						if (path[1] != State.TOP) {
							do {
								e++;
								path[e] = superState(path[e - 1]);
							} while ((path[e] != s) && (path[e] != s1)
								&& (path[e] != State.TOP));
						}
						if (path[e] != s) { // (f), (g)
							dispatchExit(s, s1);
							if (path[e] != s1) { // (g)
								int n = e, i = path.length - 2;
								do {
									assert i > 0;
									i--;
									transitionTo = null;
									upwardTo = null;
									s1.handle(this, State.EXIT);
									assert transitionTo == null;
									if (upwardTo == null) {
										s1 = superState(s1);
									} else {
										assert upwardTo != s1;
										s1 = upwardTo;
									}
									e = n;
									while ((e != -1) && (path[e] != s1)) {
										e--;
									}
								} while (e == -1);
							}
						}
					}
				}
				while (e != 0) {
					e--;
					dispatchEnter(path[e], path[e + 1]);
				}
				result = dispatchInit(target, path[1]);
			}
			if (result != target) {
				result = enterState(result, target);
			}
			return result;
		}

		public void dispatch (Object o) {
			assert !barrier;
			assert state != null;
			barrier = true;
			int i = 0;
			path[0] = state;
			do {
				transitionTo = null;
				upwardTo = null;
				path[i].handle(this, o);
				if (upwardTo != null) {
					assert upwardTo != path[i];
					i++;
					path[i] = upwardTo;
				}
			} while ((upwardTo != null) && (upwardTo != State.TOP));
			if (transitionTo != null) {
				State target = transitionTo;
				int j = 0;
				while (j != i) {
					dispatchExit(path[j], path[j + 1]);
					j++;
				}
				state = processTransition(path[i], target);
			} else {
				assert upwardTo == null;
			}
			barrier = false;
		}

		public void start (State initialState) {
			assert !barrier;
			assert state == null;
			assert initialState != null;
			assert initialState != State.TOP;
			barrier = true;
			state = enterState(initialState, State.TOP);
			barrier = false;
		}
	}
}
