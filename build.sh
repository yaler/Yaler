#!/bin/sh
javac src/org/yaler/*.java
javac -cp src test/org/yaler/*.java
cd src && (jar cf ../yaler.jar org/yaler/*.class; cd ..)
