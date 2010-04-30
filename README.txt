Yaler 1.0

Copyright (c) 2010, Oberon microsystems AG, Switzerland. All rights reserved.

Yaler is a simple, open and scalable relay infrastructure for the Web of Things.


To build and run the project, first make sure that you have JDK6 installed and
that your PATH environment variable includes the JDK's bin directory.

To do a complete build on Linux, execute:

    ./build.sh

And on Windows:

    build.bat

To start Yaler, type:

    java -ea -cp yaler.jar org.yaler.Yaler 127.0.0.1:80

If you now open the following URI in a browser, you should get "Gateway
Timeout":

    http://127.0.0.1/ping


To use SSL, you first need to create a keystore. On Linux, execute:

    ./genkey.sh

And on Windows:

    genkey.bat

You will be asked for a password. Please enter:

    org.yaler

To start Yaler in secure mode, type:

    java -ea -cp yaler.jar org.yaler.Yaler -secure 127.0.0.1:443

If you now open the following URI in a browser, you should get "Gateway
Timeout":

    https://127.0.0.1/ping


CREDITS: The module org.yaler.StateMachines is based on Miro Samek's QEP event
processor published in the book "Practical UML Statecharts in C/C++, Second
Edition". Miro has generously agreed to let us release it under the same license
that applies to all parts of Yaler: the Sleepycat license with the additional
clause "FOR NON-COMMERCIAL PURPOSES" to protect the interests of our paying
customers.

Thanks, and please join us at http://yaler.org/

Cuno (pfister@oberon.ch), Marc (frei@oberon.ch), Thomas (amberg@oberon.ch)