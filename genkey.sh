#!/bin/sh

keytool -genkey -keystore yalerkeys -storetype pkcs12 -alias yalerkey -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -validity 365 -storepass yaler.org -keypass yaler.org -dname "CN=n/a"
