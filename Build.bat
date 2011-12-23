@echo off
javac -cp src src/org/yaler/core/*.java
javac -cp src src/org/yaler/relay/*.java
javac -cp src src/*.java
javac -cp src test/*.java
cd src && (jar cf ../yaler.jar *.class org/yaler/core/*.class org/yaler/relay/*.class & cd ..)
