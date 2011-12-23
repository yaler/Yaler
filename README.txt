Yaler - a simple, open and scalable relay infrastructure

Copyright (c) 2011, Yaler Gmbh, Switzerland. All rights reserved.

The Yaler relay infrastructure enables secure Web access to embedded systems
behind a firewall, a NAT or a mobile network gateway. All you need on your
device is a TCP socket. A simple HTTP handshake makes your Web service running
on the device accessible from any Web browser, cURL or other HTTP client,
allowing you to remotely monitor and control your device.


To build and run the project, first make sure that you have JDK6 installed and
that your PATH environment variable includes the JDK's bin directory.

To do a complete build on Linux, execute:

    ./build.sh

And on Windows:

    build.bat

To start Yaler, type:

    java -ea -cp yaler.jar Yaler localhost:80

To use SSL, you first need to create a keystore. On Linux, execute:

    ./genkey.sh

And on Windows:

    genkey.bat

To start Yaler in secure mode, type:

    java -ea -cp yaler.jar Yaler localhost:443 -secure


CREDITS: The module org.yaler.StateMachines is based on Miro Samek's QEP event
processor published in the book "Practical UML Statecharts in C/C++, Second
Edition". Miro has generously agreed to let us release it under the same license
that applies to all parts of Yaler: the Sleepycat license with the additional
clause "FOR NON-COMMERCIAL PURPOSES". For other algorithms used in Yaler please
refer to doc/References.txt.


Thanks, and please join us at http://yaler.org/

Marc (frei@yaler.net), Thomas (tamberg@yaler.net)