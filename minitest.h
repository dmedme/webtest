/*
 * minitest.h - headers for minitest and webmenu
 */
#ifndef MINITEST_H
#define MINITEST_H
#ifdef UNIX
#ifndef ANDROID
#ifdef LINUX
#define signal sysv_signal
#endif
#endif
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/time.h>
#define closesocket close
#ifndef SD_RECEIVE
#define SD_RECEIVE 0
#endif
#ifndef SD_SEND
#define	SD_SEND 1
#endif
#ifndef SD_BOTH
#define SD_BOTH 2
#endif
#ifndef SOLAR
#define fifo_connect(x,y) open(x,O_WRONLY)
#define fifo_accept(x,y) open(x,O_RDONLY)
#endif
#else
#define strncasecmp strnicmp
typedef unsigned long in_addr_t;
#include <winsock2.h>
#include <windows.h>
#ifdef IMPROVE_TIMER_RESOLUTION
#include <intrinsics.h>
#endif
#include <process.h>
#include <io.h>
#include <fcntl.h>
#define sleep Sleep
#define dup2 _dup2
#ifndef O_NOINHERIT
#define O_NOINHERIT 0x80
#endif
#endif
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef UNIX
#ifdef fileno
#undef fileno
#endif
#ifdef WIN95
#define COMMAND_PROCESSOR "C:\\E2NETTST\\BASH.EXE"
#else
/* #define COMMAND_PROCESSOR "C:\\WINNT\\SYSTEM32\\CMD.EXE" */
#define COMMAND_PROCESSOR "C:\\WINDOWS\\SYSTEM32\\CMD.EXE"
#endif
#define SLEEP_FACTOR 1000
#else
#ifndef O_BINARY
#define O_BINARY 0
#endif
#define COMMAND_PROCESSOR "/bin/sh"
#define SLEEP_FACTOR 1
#endif

#define BUFLEN      1400
#define FIRST_PRIV  803
#ifndef TCP_KEEPALIVE
#define TCP_KEEPALIVE 8
#endif
#ifdef OSF
char * inet_ntoa();
#endif
#ifdef ANDROID
#define in_addr_t unsigned int
#endif
long int launch_pipeline();
char * attempt_request();
void do_asynch();
void zapall();
void websend();
#ifndef UNIX
#ifdef errno
#undef errno
#endif
#define errno WSAGetLastError()
void _invalid_parameter();
#endif
#endif
