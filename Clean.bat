@echo off
for /f "delims=" %%i in ('dir /ad/s/b') do (
	if exist "%%i\*.class" (
		del /q "%%i\*.class"
	)
)
if exist yaler.jar (
	del /q yaler.jar
)
if exist yalerkeys (
	del /q yalerkeys
)
