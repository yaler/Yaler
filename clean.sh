#!/bin/sh
find . -type f -name *.class -exec rm -f {} \;
test -f yaler.jar && rm -f yaler.jar
test -f yalerkeys && rm -f yalerkeys
