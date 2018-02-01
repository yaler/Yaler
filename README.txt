Yaler - a simple, open and scalable relay infrastructure


The Yaler relay infrastructure enables secure Web access to embedded systems
behind a firewall, NAT or mobile network gateway. All you need on your device is
a TCP socket. A simple HTTP handshake makes your Web service running on the
device accessible from any Web browser, cURL or other HTTP client, allowing you
to remotely monitor and control your device.


To build and run the project, first make sure that you have JDK 8 installed and
that your PATH environment variable includes the JDK's bin directory.

To do a complete build, execute:

    ./build.sh

To start Yaler, type:

    java -ea -cp yaler.jar Yaler localhost:80

To use TLS, you first need to create a keystore:

    ./genkey.sh

To start Yaler in TLS mode, type:

    java -ea -cp yaler.jar Yaler tls:localhost:443


CREDITS: The module org.yaler.core.StateMachines is based on Miro Samek's QEP
event processor published in the book "Practical UML Statecharts in C/C++,
Second Edition". Miro has generously agreed to let us release it under the same
license that applies to all parts of Yaler: the GNU AGPLv3. For other algorithms
used in Yaler, please refer to doc/References.txt.


Thanks, and please join us at https://yaler.net/

Marc (frei@yaler.net), Thomas (tamberg@yaler.net)