@echo off

REM 编译 Linux
SET GOOS=linux
SET GOARCH=amd64
go build -o DnsScan_amd64

REM 编译 Linux
SET GOOS=linux
SET GOARCH=386
go build -o DnsScan_x86


REM 编译 Windows
SET GOOS=windows
SET GOARCH=amd64
go build -o DnsScan.exe
