// Copyright (c) 2011, Yaler GmbH, Switzerland
// All rights reserved

// This module is based on Miro Samek's QEP event processor published in the
// book "Practical UML Statecharts in C/C++, Second Edition".

import org.yaler.core.StateMachines.State;
import org.yaler.core.StateMachines.StateMachine;

class StateMachinesTest {
	private static final StringBuilder log = new StringBuilder();
	private static boolean flag;

	private static final State s = new State() {
		public void handle (StateMachine m, Object o) {
			if (o == ENTER) {
				log.append("s-ENTER;");
			} else if (o == EXIT) {
				log.append("s-EXIT;");
			} else if (o == INIT) {
				log.append("s-INIT;");
				m.transitionTo(s11);
			} else if (o == "E") {
				log.append("s-E;");
				m.transitionTo(s11);
			} else if (o == "I") {
				if (flag) {
					log.append("s-I;");
					flag = false;
				} else {
					m.upwardTo(TOP);
				}
			} else {
				m.upwardTo(TOP);
			}
		}
	};

	private static final State s1 = new State() {
		public void handle (StateMachine m, Object o) {
			if (o == ENTER) {
				log.append("s1-ENTER;");
			} else if (o == EXIT) {
				log.append("s1-EXIT;");
			} else if (o == INIT) {
				log.append("s1-INIT;");
				m.transitionTo(s11);
			} else if (o == "A") {
				log.append("s1-A;");
				m.transitionTo(s1);
			} else if (o == "B") {
				log.append("s1-B;");
				m.transitionTo(s11);
			} else if (o == "C") {
				log.append("s1-C;");
				m.transitionTo(s2);
			} else if (o == "D") {
				if (!flag) {
					log.append("s1-D;");
					flag = true;
					m.transitionTo(s);
				} else {
					m.upwardTo(s);
				}
			} else if (o == "F") {
				log.append("s1-F;");
				m.transitionTo(s211);
			} else if (o == "I") {
				log.append("s1-I;");
			} else {
				m.upwardTo(s);
			}
		}
	};

	private static final State s11 = new State() {
		public void handle (StateMachine m, Object o) {
			if (o == ENTER) {
				log.append("s11-ENTER;");
			} else if (o == EXIT) {
				log.append("s11-EXIT;");
			} else if (o == "D") {
				if (flag) {
					log.append("s11-D;");
					flag = false;
					m.transitionTo(s1);
				} else {
					m.upwardTo(s1);
				}
			} else if (o == "G") {
				log.append("s11-G;");
				m.transitionTo(s211);
			} else if (o == "H") {
				log.append("s11-H;");
				m.transitionTo(s);
			} else {
				m.upwardTo(s1);
			}
		}
	};

	private static final State s2 = new State() {
		public void handle (StateMachine m, Object o) {
			if (o == ENTER) {
				log.append("s2-ENTER;");
			} else if (o == EXIT) {
				log.append("s2-EXIT;");
			} else if (o == INIT) {
				log.append("s2-INIT;");
				m.transitionTo(s211);
			} else if (o == "C") {
				log.append("s2-C;");
				m.transitionTo(s1);
			} else if (o == "F") {
				log.append("s2-F;");
				m.transitionTo(s11);
			} else if (o == "I") {
				if (!flag) {
					log.append("s2-I;");
					flag = true;
				} else {
					m.upwardTo(s);
				}
			} else {
				m.upwardTo(s);
			}
		}
	};

	private static final State s21 = new State() {
		public void handle (StateMachine m, Object o) {
			if (o == ENTER) {
				log.append("s21-ENTER;");
			} else if (o == EXIT) {
				log.append("s21-EXIT;");
			} else if (o == INIT) {
				log.append("s21-INIT;");
				m.transitionTo(s211);
			} else if (o == "A") {
				log.append("s21-A;");
				m.transitionTo(s21);
			} else if (o == "B") {
				log.append("s21-B;");
				m.transitionTo(s211);
			} else if (o == "G") {
				log.append("s21-G;");
				m.transitionTo(s1);
			} else {
				m.upwardTo(s2);
			}
		}
	};

	private static final State s211 = new State() {
		public void handle (StateMachine m, Object o) {
			if (o == ENTER) {
				log.append("s211-ENTER;");
			} else if (o == EXIT) {
				log.append("s211-EXIT;");
			} else if (o == "D") {
				log.append("s211-D;");
				m.transitionTo(s21);
			} else if (o == "H") {
				log.append("s211-H;");
				m.transitionTo(s);
			} else {
				m.upwardTo(s21);
			}
		}
	};

	public static void main (String[] args) {
		System.out.print("StateMachinesTest: ");
		long t = System.nanoTime();
		StateMachine m = new StateMachine();
		log.append("top-INIT;");
		m.start(s2);
		for (char c: "ABDEIFIIFABDDEGHHCGCC".toCharArray()) {
			log.append("\n" + c + ":");
			m.dispatch(Character.toString(c).intern());
		}
		if (log.toString().equals(
			"top-INIT;s-ENTER;s2-ENTER;s2-INIT;s21-ENTER;s211-ENTER;"
			+ "\n" + "A:s21-A;s211-EXIT;s21-EXIT;s21-ENTER;s21-INIT;s211-ENTER;"
			+ "\n" + "B:s21-B;s211-EXIT;s211-ENTER;"
			+ "\n" + "D:s211-D;s211-EXIT;s21-INIT;s211-ENTER;"
			+ "\n" + "E:s-E;s211-EXIT;s21-EXIT;s2-EXIT;s1-ENTER;s11-ENTER;"
			+ "\n" + "I:s1-I;"
			+ "\n" + "F:s1-F;s11-EXIT;s1-EXIT;s2-ENTER;s21-ENTER;s211-ENTER;"
			+ "\n" + "I:s2-I;"
			+ "\n" + "I:s-I;"
			+ "\n" + "F:s2-F;s211-EXIT;s21-EXIT;s2-EXIT;s1-ENTER;s11-ENTER;"
			+ "\n" + "A:s1-A;s11-EXIT;s1-EXIT;s1-ENTER;s1-INIT;s11-ENTER;"
			+ "\n" + "B:s1-B;s11-EXIT;s11-ENTER;"
			+ "\n" + "D:s1-D;s11-EXIT;s1-EXIT;s-INIT;s1-ENTER;s11-ENTER;"
			+ "\n" + "D:s11-D;s11-EXIT;s1-INIT;s11-ENTER;"
			+ "\n" + "E:s-E;s11-EXIT;s1-EXIT;s1-ENTER;s11-ENTER;"
			+ "\n" + "G:s11-G;s11-EXIT;s1-EXIT;s2-ENTER;s21-ENTER;s211-ENTER;"
			+ "\n" + "H:s211-H;s211-EXIT;s21-EXIT;s2-EXIT;s-INIT;s1-ENTER;s11-ENTER;"
			+ "\n" + "H:s11-H;s11-EXIT;s1-EXIT;s-INIT;s1-ENTER;s11-ENTER;"
			+ "\n" + "C:s1-C;s11-EXIT;s1-EXIT;s2-ENTER;s2-INIT;s21-ENTER;s211-ENTER;"
			+ "\n" + "G:s21-G;s211-EXIT;s21-EXIT;s2-EXIT;s1-ENTER;s1-INIT;s11-ENTER;"
			+ "\n" + "C:s1-C;s11-EXIT;s1-EXIT;s2-ENTER;s2-INIT;s21-ENTER;s211-ENTER;"
			+ "\n" + "C:s2-C;s211-EXIT;s21-EXIT;s2-EXIT;s1-ENTER;s1-INIT;s11-ENTER;"))
		{
			System.out.println("done (" + (System.nanoTime() - t) / 1000000 + "ms)");
		} else {
			throw new AssertionError();
		}
	}
}