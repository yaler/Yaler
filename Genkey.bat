@echo off
keytool -genkey -keyalg rsa -keystore yalerkeys -alias yalerkey -storepass yaler.org -keypass yaler.org -dname "cn="
