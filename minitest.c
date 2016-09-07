/*
 * Copyright (c) E2 System 1985. All rights reserved.
 *
 * This program is written to run on generic *nix and Windows with no
 * dependencies on other sources or libraries beyond the minimum needed
 * by any OS that supports IP V.4 networking.
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems Limited 1985, 2009";
#include "minitest.h"
#if __LCCOPTIMLEVEL > 0
char * _stdcall strcpy(char *x1_ptr, const char *x2_ptr)
{
char * x3_ptr = x1_ptr;

    for(;;)
    {
        *x3_ptr = *x2_ptr;
        if (*x2_ptr == '\0')
            return x1_ptr;
        x3_ptr++;
        x2_ptr++;
    }
}
/* Assembly Language to implement ftol
 * ************************************
VC++ generates a call to function ftol, which saves current processor's
rounding mode, sets it to floor, executes instruction fistp, then pops
everything back. So instead of one instruction (fistp), you get a function
call plus this (ghastly Intel Syntax):

 * push ebp
 * mov ebp,esp
 * add esp,0F4h
 * wait
 * fnstcw word ptr [ebp-2]
 * wait
 * mov ax,word ptr [ebp-2]
 * or ah,0Ch
 * mov word ptr [ebp-4],ax
 * fldcw word ptr [ebp-4]
 * fistp qword ptr [ebp-0Ch]
 * fldcw word ptr [ebp-2]
 * mov eax,dword ptr [ebp-0Ch]
 * mov edx,dword ptr [ebp-8]
 * leave
 * ret

The following function can be used to achieve a great efficiency gain:

inline int Round(float a) {
#ifdef WIN32
	int i;
	__asm {
		fld   a
		fistp i
	}
	return i;
#else
	return rint(a); // just hope it's an intrinsic.
#endif
}

To get truncation, the function below can be used:

inline int Trunc(float f) {
#ifdef WIN32
	int magic = 0x3efffffe | (int&)f & 0x80000000;
	return Round(f - *(float*)&magic);
#else
	return int(f);
#endif
}

Function Trunc does the following for positive numbers: return Round(f - magic), where "magic" is the largest number less than 1. For negative numbers, additional two instructions are required negate this "magic" number. Note that this function is only suitable for computer graphics. It's no good for other kinds of computation, because it doesn't handle special cases at all.

It would be more efficient to modify the default rounding mode before a series of truncations, then restore it back This can be done with the _controlfp function.

unsigned int saved = _statusfp();
_controlfp(_MCW_RC,_RC_CHOP);   
// RC == Rounding Control, CHOP == Truncate
// use Round() to truncate many numbers
_controlfp(_MCW_RC,saved);

 *
 * fnstcw -2(%ebp)   ; store FPU control word
 * movw -2(%ebp),%di ; move FPU control word to di register
 * orw $3072,%di     ; modify di
 * movw %di,-4(%ebp) ; move di to the stack
 * fldcw -4(%ebp)    ; load same value from stack into FPU control word
 * fistl -8(%ebp)  ; store floating point value as an integer on the stack
 * movl -8(%ebp),%eax      ; move the integer value from stack to eax
 * fldcw -2(%ebp)          ; restore FPU control word
 * *************************************************************************
 * In this file, there is never any decimal component, so the current rounding
 * mode is irrelevant. So we proceed as follows.
 */
long _ftol(double d)
{
long l;
    _asm(" fldl 4(%esp)");
    _asm(" fistpl -4(%ebp)");
    return l;
}
#endif
#define LISTEN_SERV argv[1]
#define CALL_HOST   argv[1]
#define CALL_PORT   argv[2]
static void do_scen();
static void e2spawn();
static int child_cnt;
static long children[1024];
static int thread_cnt;
static in_addr_t sec_host[30];
static int sec_host_cnt;
#ifndef UNIX
static HANDLE threads[1024];
#endif
/*
 * The Win32 inet_ntoa is incredibly expensive, hence these
 */
char * e2inet_ntoa_r(l, ret_buf)
struct in_addr l;
char * ret_buf;
{
union {
unsigned char c[4];
struct in_addr l;
} test;

    test.l = l;
    sprintf(ret_buf, "%u.%u.%u.%u", test.c[0], test.c[1], test.c[2], test.c[3]);
    return ret_buf;
}
char * e2inet_ntoa(l)
struct in_addr l;
{
static char ret_buf[16];

    return e2inet_ntoa_r(l, ret_buf);
}

static void sigterm()
{
    puts("User Terminated");
#ifndef UNIX
    WSACleanup();
#endif
    zapall(0);
    exit(0);
}
#ifdef UNIX
static void sigchild()
{
int pid;
int i;
#ifdef POSIX
int
#else
union wait
#endif
    wait_status;
#ifndef SIGCLD
#define SIGCLD SIGCHLD
#endif

    (void) sigset(SIGCLD,SIG_DFL); /* Avoid nasties with the chld_sig/wait3()
                                       interaction */
    while ((pid=wait3(&wait_status, WNOHANG, 0)) > 0)
    {
        for (i = 0; i < child_cnt; i++)
        {
            if (children[i] == pid)
            {
                child_cnt--;
                while (i < child_cnt)
                {
                    children[i] = children[i+1];
                    i++;
                }
            }
        }
    }
    (void) sigset(SIGCLD,sigchild); /* re-install */
    return;
}
#endif
/*
 * Function to get known incoming
 */
static int smart_read(f,buf,len)
int f;
char * buf;
int len;
{
int so_far = 0;
int r;
int loop_detect = 0;

    do
    {
        r = recvfrom(f, buf, len, 0,0,0);
        if (r == 0)
            return so_far;
        else
        if (r < 0)
        {
            loop_detect++;
#ifdef UNIX
            if (errno == EINTR && loop_detect < 100)
                continue;
#endif
            if (so_far)
                return so_far;
            return r;
        }
        else
            loop_detect = 0;
        so_far += r;
        len -= r;
        buf += r;
    }
    while (len > 0);
    return so_far;
}
/*
 * Lock down minitest (which usually provides a password-free method of
 * executing commands as root on a target machine).
 */
static void set_sec_host(host_ip)
char * host_ip;
{
char * x;
/*
 * Generate a vector of valid hosts
 */
    for (sec_host_cnt = 0;
             sec_host_cnt < 30 && (x=strtok(host_ip," \n")) != (char *) NULL;)
    {
        fprintf(stderr, "SECURE %s", x);
        if ((sec_host[sec_host_cnt] = inet_addr(x)) == -1)
        {
            fprintf(stderr,
                        " but %s is not a valid IP Address so we ignore it\n",
                                          x);
        }
        else
        {
            fputs(" - applied\n", stderr);
            sec_host_cnt++;
        }
        host_ip = NULL;
    }
    fflush(stderr);
    return;
}
/*
 * Lock down minitest (which usually provides a password-free method of
 * executing commands as root on a target machine).
 */
static int check_sec_host(host_ip)
char * host_ip;
{
int i;
/*
 * Compare with the vector of valid hosts
 */
    for (i = 0; i < sec_host_cnt; i++)
        if (!memcmp(host_ip, 
               (char *) &sec_host[i], sizeof(sec_host[0])))
            return 1;
    return 0;
}
#ifndef UNIX
/******************************************************************************
 * Entry point - Main Program Start Here
 * VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV
 */
int main();
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, INT nCmdShow)
{
char * fifo_args[30];                           /* Dummy arguments to process */
short int i;

#if __MSVCRT_VERSION__ >= 0x800
    (void) _set_invalid_parameter_handler(_invalid_parameter);
#endif
/*
 * Process the arguments in the string that has been read
 */
    if ((fifo_args[0]=strtok(lpCmdLine,"  \n"))==NULL)
         return 0;
/*
 * Generate an argument vector
 */
    for (i=1;
             i < 29 && (fifo_args[i]=strtok(NULL," \n")) != (char *) NULL;
                 i++);
    fifo_args[i] = (char *) NULL; 
    return main(i,fifo_args);
}
#endif
void do_copy(accept_socket_fd, fname)
int accept_socket_fd;
char * fname;
{
unsigned char transfer_buf[BUFLEN];
int loop_detect;
int read_count;
char *x;
FILE * ofp = fopen(fname, "wb");

    fprintf(stderr, "COPY %s\n", fname);
    fflush(stderr);
    if (ofp == (FILE *) NULL)
    {
        fprintf(stderr, "fopen() error: %d", errno);
        fprintf(stderr, "Failed to open %s\n", fname);
        return;
    }
    for (loop_detect = 0;;)
    {
        read_count = recvfrom(accept_socket_fd,
                         transfer_buf,sizeof(transfer_buf),
                                  0,0,0);
#ifdef DEBUG
        fprintf(stderr, "recvfrom() returned %d errno %d\n", read_count,errno);
#endif
        if (read_count <= 0)
        {
            loop_detect++;
/*
 * What can legitimately cause EINTR here?
 */
#ifdef UNIX
            if (errno == EINTR && loop_detect < 100)
                continue;
#endif
            shutdown(accept_socket_fd, SD_BOTH);
            closesocket(accept_socket_fd);
            fclose(ofp);
            return;
        }
        else
            loop_detect = 0;
        (void) fwrite(transfer_buf,sizeof(char),read_count,ofp);
    }
    return;
}
void do_exec(accept_socket_fd, fname)
int accept_socket_fd;
char * fname;
{
char *x;

    fprintf(stderr, "EXEC %s\n", fname);
    fflush(stderr);
#ifdef UNIX
    if (accept_socket_fd != 0)
        dup2(accept_socket_fd, 0);
    if (accept_socket_fd != 1)
        dup2(accept_socket_fd, 1);
    if (accept_socket_fd != 2)
        dup2(accept_socket_fd, 2);
    if (accept_socket_fd != 0
      && accept_socket_fd != 1
      && accept_socket_fd != 2)
        close(accept_socket_fd);
    if (fname == NULL || strlen(fname) == 0)
        execlp("sh","sh",NULL);
    else
        execlp("sh","sh", "-c", fname, NULL);
    perror("execlp() failed");
#else
/*
 * With windows, have to hook up a pipe, and spawn, because sockets
 * are not files.
 */
    if (strlen(fname) == 0)
    {
        if ((x = getenv("COMSPEC")) == (char *) NULL)
        {
            if ( _osver & 0x8000 )
                x = "C:\\WINDOWS\\COMMAND.COM";
            else
                x = "C:\\WINDOWS\\SYSTEM32\\CMD.EXE";
/* Windows NT or 2000 would be ->   x = "C:\\WINNT\\SYSTEM32\\CMD.EXE"; */
        }
        e2spawn(accept_socket_fd, NULL, x);
    }
    else
        e2spawn(accept_socket_fd, NULL, fname);
#endif
    return;
}
void do_perf(accept_socket_fd, fname)
int accept_socket_fd;
char * fname;
{
int i;
char * pid;
char *x;
#ifndef UNIX
HANDLE my_thread;

    my_thread = threads[thread_cnt - 1]; 
#endif

    fprintf(stderr, "SCENARIO %s\n", fname);
    fflush(stderr);
    pid = strtok(fname, " \n\r");
    if (pid != (char *) NULL
      && (x = strtok(NULL, " \n\r")) != (char *) NULL)
    {
        i = atoi(x);
        do_scen(pid,i);
    }
    closesocket(accept_socket_fd);
#ifdef UNIX
    zapall(getpid());
#else
    zapall((long int) my_thread);   /* Get rid of all the child processes */
#endif
    return;
}
#ifndef UNIX
struct  arg_block {
void (*fun)();
int int_arg;
char * ptr;
};
void do_fun(abp)
struct arg_block * abp;
{
#ifndef UNIX
HANDLE my_thread;

    my_thread = threads[thread_cnt - 1]; 
#endif
    abp->fun(abp->int_arg, abp->ptr);
    free(abp);
#ifndef UNIX
    CloseHandle(my_thread);
#endif
    return;
}
void do_asynch(fun, int_arg, ptr_arg)
void (*fun)();
int int_arg;
char * ptr_arg;
{
int child_pid;
struct arg_block * abp = (struct arg_block *) malloc(9 +
                 sizeof(struct arg_block) +
     ((ptr_arg == NULL) ? 0 : strlen(ptr_arg)));

    abp->fun = fun;
    abp->int_arg = int_arg;
    abp->ptr = (char *) (abp + 1);
    if (ptr_arg != NULL)
        strcpy(abp->ptr, ptr_arg);
    else
        abp->ptr[0] = '\0';
    threads[thread_cnt++] =
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) do_fun,
                              (LPVOID) abp, 0, &child_pid);
    return;
}
#else
void do_asynch(fun, int_arg, ptr_arg)
void (*fun)();
int int_arg;
char * ptr_arg;
{
int child_pid;

    if ((child_pid=fork())==0)
    {
        fun(int_arg, ptr_arg);
        exit(0);
    }
    children[child_cnt++] = child_pid;
    return;
}
#endif
void do_command(accept_socket_fd)
int accept_socket_fd;
{
struct timeval t;
unsigned char transfer_buf[BUFLEN];
int read_count;
char *x;

    if (smart_read(accept_socket_fd,transfer_buf,2) != 2)
    {
        fprintf(stderr, "command length read() failed error:%d\n", errno);
        shutdown(accept_socket_fd, SD_BOTH);
        closesocket(accept_socket_fd);
        return;
    }
/*
 * This appears to be an HTTP request; get some more of it and pass it to
 * the request handler.
 */
    if  ((transfer_buf[0] == 'G' && transfer_buf[1] == 'E')
      || ( transfer_buf[0] == 'P'
      && (transfer_buf[1] == 'O' || transfer_buf[1] == 'O')))
    {
    int loop_detect = 0;

        for(;;)
        {
            read_count = recvfrom(accept_socket_fd, &transfer_buf[2], 
                        BUFLEN - 2, 0,0,0);
            if (read_count <= 0)
            {
#ifdef UNIX
                if (read_count < 0)
                {
                    loop_detect++;
                    if (errno == EINTR && loop_detect < 100)
                        continue;
                }
#endif
                fprintf(stderr, "HTTP read() failed error:%d\n", errno);
                shutdown(accept_socket_fd, SD_BOTH);
                closesocket(accept_socket_fd);
                return;
            }
            else
                break;
        }
        read_count += 2;
        if ((x = memchr(&transfer_buf[5],' ', read_count - 5)) == NULL)
        {
            fputs("Weird HTTP read() failed error:%d\n", stderr);
            shutdown(accept_socket_fd, SD_BOTH);
            closesocket(accept_socket_fd);
            return;
        }
        if ((x = attempt_request(accept_socket_fd, 
                 &transfer_buf[0], x,
                     read_count)) != NULL)
            web_send(accept_socket_fd, 43,
"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n"); 
        shutdown(accept_socket_fd, SD_BOTH);
        closesocket(accept_socket_fd);
        return;
    }
#ifdef DEBUG
    fputs("Command Length Read Succeeded\n", stderr);
    fflush(stderr);
#endif
    read_count = transfer_buf[0] * 256 + transfer_buf[1];
    if (read_count > sizeof(transfer_buf))
    {
        fputs("Command length > valid maximum\n", stderr);
        shutdown(accept_socket_fd, SD_BOTH);
        closesocket(accept_socket_fd);
        return;
    }
    if (read_count != smart_read(accept_socket_fd,transfer_buf,read_count))
    {
        fputs("Failed to read command\n", stderr);
        shutdown(accept_socket_fd, SD_BOTH);
        closesocket(accept_socket_fd);
        return;
    }
#ifdef DEBUG
    fputs("Command Read Succeeded\n", stderr);
    fflush(stderr);
#endif
/*
 * The commands are either COPY (in which case, what follows is the
 * name of the output file; do not bother with file modes or size) or EXEC
 * (in which case, what follows is an arbitrary shell command) or SLEW
 * (which finds out what the difference in time stamps should be).
 * or SCENE (which means, execute a scenario for a given time) or OVER,
 * (which means, overlay the existing process; used to update the software)
 * or ABORT (kill off all currently executing child processes) or SECURE
 * (only allow one of a number of IP address to issue commands).
 * or an HTTP GET, PUT or POST.
 */
    if (!strncmp("COPY", &transfer_buf[0],4))
        do_asynch(do_copy, accept_socket_fd, &transfer_buf[4]);
    else
    if (!strcmp(&transfer_buf[0], "SLEW"))
    {
        fputs("Command SLEW seen\n", stderr);
        fflush(stderr);
/*
 * Make sure that no 'first packet' costs intervene
 */
        sendto(accept_socket_fd, &transfer_buf[0], 2, 0,0,0);
        if (smart_read(accept_socket_fd,transfer_buf,2) != 2)
        {
            fprintf(stderr, "Clock length read() failed error: %d", errno);
            shutdown(accept_socket_fd, SD_BOTH);
            closesocket(accept_socket_fd);
            return;
        }
        gettimeofday(&t, NULL);
        sprintf(&transfer_buf[2],"%u.%06u",t.tv_sec, t.tv_usec);
        read_count = strlen(&transfer_buf[2]) +1;
        transfer_buf[0] = read_count/256;
        transfer_buf[1] = read_count % 256;
        sendto(accept_socket_fd, &transfer_buf[0], read_count+2,0,0,0);
        shutdown(accept_socket_fd, SD_BOTH);
    }
    else
    if (!strncmp("EXEC", &transfer_buf[0],4))
        do_asynch(do_exec, accept_socket_fd, &transfer_buf[4]);
    else
    if (!strncmp("OVER", &transfer_buf[0],4))
    {
        fprintf(stderr, "OVER %s\n", &transfer_buf[4]);
        fflush(stderr);
/*
 * Overwrite this process or just exit; used to update the binaries.
 */
        shutdown(accept_socket_fd, SD_BOTH);
#ifndef UNIX
        WSACleanup();
#endif
        if (!strcmp(&transfer_buf[4], "exit"))
            sigterm();                                  /* Scarper */  
        execlp(&transfer_buf[4],&transfer_buf[4],NULL); /* Does not return */
    }
    else
    if (!strncmp("ABORT", &transfer_buf[0],5))
    {
        fputs("ABORT\n", stderr);
        fflush(stderr);
/*
 * Kill all child processes. Should cascade.
 */
        shutdown(accept_socket_fd, SD_BOTH);
        zapall(0);
    }
    else
    if (!strncmp("SECURE", &transfer_buf[0],6))
    {
        set_sec_host( &transfer_buf[6]);
        shutdown(accept_socket_fd, SD_BOTH);
    }
    else
    if (!strncmp("SCENE", &transfer_buf[0],5))
        do_asynch(do_perf, accept_socket_fd, &transfer_buf[5]);
    else
        fprintf(stderr, "Unrecognised command:\n%s\n", &transfer_buf[0]);
#ifdef UNIX
    closesocket(accept_socket_fd);
#endif
    return;
}
struct sock_file_pair {
#ifndef UNIX
    LONG life;
#endif
    int sock_fd;
    int file_fd;
};
/*
 * Socket to File progression. These routines kill off the sockets always,
 * but not the files (which might be shared with other threads).
 */
void  sock_file_forward(sfp)
struct sock_file_pair * sfp;
{
unsigned char transfer_buf[BUFLEN];
int read_count;

#ifndef UNIX
    InterlockedIncrement(&sfp->life);
#endif
    for (;;)
    {
        if ((read_count=recvfrom(sfp->sock_fd, transfer_buf,BUFLEN,
                                            0,0,0)) <= 0)
        {
#ifdef DEBUG
            fprintf(stderr, "sock_file_forward() input:read_count: %d errno: %d\n",
                             read_count, errno);
#endif
            if (sfp->file_fd > 2)
                close(sfp->file_fd);
            break;
        }
        if (write(sfp->file_fd, transfer_buf,read_count) != read_count)
        {
#ifdef DEBUG
            fprintf(stderr, "sock_file_forward() output:read_count: %d errno: %d\n",
                             read_count, errno);
#endif
            break;
        }
    }
    shutdown(sfp->sock_fd, SD_RECEIVE);
#ifndef UNIX
    if (InterlockedIncrement(&sfp->life) >= 4)
#endif
    free((char *) sfp);
    return;
}
void file_sock_forward(sfp)
struct sock_file_pair * sfp;
{
unsigned char transfer_buf[BUFLEN];
int read_count;
int write_count;
char * x;
#ifndef UNIX
    InterlockedIncrement(&sfp->life);
#endif
    for (;;)
    {
        if ((read_count=read(sfp->file_fd, transfer_buf,BUFLEN)) <= 0)
        {
#ifdef DEBUG
            fprintf(stderr, "file_sock_forward() input:read_count: %d errno: %d\n",
                             read_count, errno);
#endif
            break;
        }
        x = transfer_buf;
        do
        {
            write_count = sendto(sfp->sock_fd, x,read_count, 0,0,0);
            if (write_count <= 0)
            {
                fprintf(stderr, "file_sock_forward() output: read_count: %d write_count: %d errno: %d\n",
                             read_count, write_count,errno);
                break;
            }
            else
            {
                read_count -= write_count;
                x += write_count;
            }
       }
       while ( read_count > 0);
    }
    shutdown(sfp->sock_fd, SD_SEND);
#ifndef UNIX
    if (InterlockedIncrement(&sfp->life) >= 4)
#endif
    free((char *) sfp);
    return;
}
#ifdef UNIX
long int launch_pipeline(int in_fd[2], int out_fd[2], char *in_command_line)
{
int child_pid;

    pipe(&in_fd[0]);
    pipe(&out_fd[0]);
    if ((child_pid = fork()) == 0)
    {     /* Child pid */
        if (in_fd[0] != 0)
        {
            dup2(in_fd[0], 0);
            close(in_fd[0]);
        }
        if (out_fd[1] != 1)
        {
            dup2(out_fd[1], 1);
            close(out_fd[1]);
        }
        close(out_fd[0]);
        close(in_fd[1]);
        if (in_command_line == NULL || strlen(in_command_line) == 0)
            execlp("sh","sh",NULL);
        else
            execlp("sh","sh", "-c", in_command_line, NULL);
        perror("execlp() failed");
        exit(1);
    }
    else
    {
        close(in_fd[0]);
        close(out_fd[1]);
        children[child_cnt++] = child_pid;
    }
    return child_pid;
}
#else
/*
 * Parent sends on in_fd[1], receives on out_fd[0]
 * Pipeline sends on out_fd[1], receives on in_fd[0]
 */
long int launch_pipeline(int in_fd[2], int out_fd[2], char *in_command_line)
{
char * command_line;

int h0;
int h1;
int h2;
int len;
DWORD dwCreationFlags = CREATE_NEW_PROCESS_GROUP;
BOOL bInheritHandles = TRUE;
STARTUPINFO si;
PROCESS_INFORMATION pi;
static char * prog_name;
/*
 * Check that we actually have a command to execute
 */
    if (in_command_line == NULL)
        return 0;
/*
 * Find the command interpreter
 */
    if (prog_name == (char *) NULL
     && (prog_name = getenv("COMSPEC")) == (char *) NULL)
    {
        if ( _osver & 0x8000 )
            prog_name = "C:\\WINDOWS\\COMMAND.COM";
        else
            prog_name = "C:\\WINDOWS\\SYSTEM32\\CMD.EXE";
/*            prog_name = "C:\\WINNT\\SYSTEM32\\CMD.EXE"; */
    }
    if ((command_line = (char *) malloc(strlen(prog_name) + 10
               + strlen(in_command_line)  + 1))
                  == (char *) NULL)
        return 0;
    sprintf(command_line, "%s /d /q /c %s", prog_name, in_command_line);
    fprintf(stderr, "Launch Command: %s\n", command_line);
/*
 * Default setup information for the spawned process
 */
    si.cb = sizeof(si);
    si.lpReserved = NULL;
    si.lpDesktop = NULL;
    si.lpTitle = NULL;
    si.dwX = 0;
    si.dwY = 0;
    si.dwXSize = 0;
    si.dwYSize= 0;
    si.dwXCountChars = 0;
    si.dwYCountChars= 0;
    si.dwFillAttribute= 0;
    si.dwFlags = STARTF_USESTDHANDLES /* | STARTF_USESHOWWINDOW */ ;
    si.wShowWindow = 0;
    si.cbReserved2 = 0;
    si.lpReserved2 = NULL;
/*
 * Create the read pipe
 */
    if (_pipe(&in_fd[0],4096,O_BINARY|O_NOINHERIT))
    {
        fprintf(stderr,"pipe(in_fd...) failed error:%d\n", errno);
        free(command_line);
        return 0;
    }
#ifdef DEBUG
    else
        fprintf(stderr,"pipe(in_fd...) gives files:(%d,%d)\n", in_fd[0],
                   in_fd[1]);
#endif
    if (_pipe(&out_fd[0],4096,O_BINARY|O_NOINHERIT))
    {
        fprintf(stderr,"pipe(out_fd...) failed error:%d\n", errno);
        _close(in_fd[0]);
        _close(in_fd[1]);
        free(command_line);
        return 0;
    }
#ifdef DEBUG
    else
        fprintf(stderr,"pipe(out_fd...) gives files:(%d,%d)\n", out_fd[0],
                   out_fd[1]);
#endif
    if ((h0 = _dup(in_fd[0])) < 0)
    {
        fprintf(stderr,"dup(in_fd[0]) failed error:%d\n", errno);
        _close(in_fd[0]);
        _close(out_fd[0]);
        _close(in_fd[1]);
        _close(out_fd[1]);
        free(command_line);
        return 0;
    }
    _close(in_fd[0]);
    SetHandleInformation((HANDLE) _get_osfhandle(in_fd[1]),
                  HANDLE_FLAG_INHERIT, 0);
/*
 * Set up the pipe handles for inheritance
 */
    if ((h1 = _dup(out_fd[1])) < 0)
    {
        fprintf(stderr,"dup(out_fd[1]) failed error:%d\n", errno);
        _close(out_fd[0]);
        _close(out_fd[1]);
        _close(in_fd[1]);
        _close(h0);
        free(command_line);
        return 0;
    }
    if ((h2 = _dup(2)) < 0)
    {
        fprintf(stderr,"dup(2) failed error:%d\n", errno);
        _close(h1);
        _close(out_fd[0]);
        _close(out_fd[1]);
        _close(in_fd[1]);
        _close(h0);
        free(command_line);
        return 0;
    }
    _close(out_fd[1]);
    SetHandleInformation((HANDLE) _get_osfhandle(out_fd[0]),
                     HANDLE_FLAG_INHERIT, 0);
/*
 * Execute the command
 */
    si.hStdInput = (HANDLE) _get_osfhandle(h0);
    si.hStdOutput = (HANDLE) _get_osfhandle(h1);
    si.hStdError = (HANDLE) _get_osfhandle(h2);
    if (!CreateProcess(prog_name, command_line, NULL, NULL, bInheritHandles,
                  dwCreationFlags, NULL, NULL, &si, &pi))
    {
        fprintf(stderr,"CreateProcess failed error:%d\n", errno);
        _close(out_fd[0]);
        _close(in_fd[1]);
        _close(h0);
        _close(h1);
        _close(h2);
        free(command_line);
        return 0;
    }
    _close(h0);
    _close(h1);
    _close(h2);
#ifdef DEBUG
    fprintf(stderr, "Handle: %x Process: %s\n", pi.hProcess, command_line);
    fflush(stderr);
#endif
    free(command_line);
    children[child_cnt++] = (long int) pi.hProcess;
    CloseHandle(pi.hThread);
    return (long int) pi.hProcess;
}
/*
 * Function to fire off a child process connected by pipes to a socket
 */
static void e2spawn(accept_socket_fd, prog_name, command_line)
int accept_socket_fd;
char * prog_name;
char * command_line;
{
int threadid;
HANDLE hthread;
struct sock_file_pair * sock_to_file;
struct sock_file_pair * file_to_sock;
int pwrite[2];
int pread[2];
/*
 * Duplicate the standard file handles
 */
    fprintf(stderr,"Executing command %s\n", command_line);
    fflush(stderr);
/*
 * Parent sends on pread[1], receives on pwrite[0]
 * (Pipeline sends on pwrite[1], receives on pread[0])
 */
    if (!launch_pipeline(pread, pwrite, command_line))
    {
        fprintf(stderr,"launch of '%s' failed error:%d\n", command_line);
        return;
    }
/*
 * Set up the socket/pipe forwarding
 */
    sock_to_file = (struct sock_file_pair *)
                        malloc(sizeof(struct sock_file_pair));
    
    memset((char *) sock_to_file, 0, sizeof(struct sock_file_pair));
    file_to_sock = (struct sock_file_pair *)
                        malloc(sizeof(struct sock_file_pair));
    memset((char *) file_to_sock, 0, sizeof(struct sock_file_pair));
    sock_to_file->file_fd = pread[1];
    file_to_sock->file_fd = pwrite[0];
    file_to_sock->sock_fd = accept_socket_fd;
    sock_to_file->sock_fd = accept_socket_fd;
    hthread = CreateThread(NULL, 0,
           (LPTHREAD_START_ROUTINE) sock_file_forward, (LPVOID) sock_to_file,
                      0, &threadid);
    file_sock_forward(file_to_sock);
    closesocket(accept_socket_fd);
    close(pwrite[0]);
    CloseHandle(hthread);
    return;
}
#endif
/*****************************************************************
 *   Start of Main Program
 */
int main(argc, argv)
int argc;
char* argv[];
{
struct sockaddr_in listen_sock,
connect_sock,
calling_sock;
int on=1;
struct linger optval;
int output_socket_fd,
accept_socket_fd,
listen_socket_fd;
in_addr_t num_host;
struct hostent num_ent;
long * phost; 
/*
 * Initialise - use input parameters to set up listen port or
 * address of port to connect to
 */
long int child_pid;
struct hostent *connect_host;
int    read_count, socket_flags=0, icount;
int calladdrlength=sizeof(listen_sock);
struct sock_file_pair * sock_to_file, * file_to_sock;
unsigned char transfer_buf[BUFLEN];
struct timeval t, t1, t2;
char *x;
/*
 * Construct the Socket Addresses
 */
#ifndef UNIX
WORD wVersionRequested;
WSADATA wsaData;
HANDLE child_handle = INVALID_HANDLE_VALUE;
wVersionRequested = 0x0101;
#endif
    child_pid = getpid();
#ifdef DEBUG
    fprintf(stderr, "argc: %d argv[0]: %s\n", argc, argv[0]);
    fflush(stderr);
#endif
#ifndef UNIX
    if ( WSAStartup( wVersionRequested, &wsaData ))
    {
        fprintf(stderr, "WSAStartup error: %d", WSAGetLastError());
        exit(1);
    }
#endif
    if (argc < 2)
    {
        fputs("Insufficient Arguments: try -h\n", stderr);
        exit(0);
    }
    else if (argv[1][0] == '-')
        webmenu_main(argc, argv);
    else
    if (argc > 2)
    {
/*
 * The socket to connect to
 */
        memset((char *) &connect_sock, 0, sizeof(connect_sock));
/*
 * Because NT4 gethostbyname is so useless
 */
        if ((num_host = inet_addr(CALL_HOST)) != -1)
        {
            memcpy(&connect_sock.sin_addr,&num_host, sizeof(num_host)); 
            num_ent.h_addrtype = AF_INET;
            num_ent.h_addr_list = &phost;
            num_ent.h_addr_list[0] = (char *) &num_host;
            num_ent.h_length = sizeof(num_host);
            connect_host = &num_ent;
        }
        else
        if ((connect_host=gethostbyname(CALL_HOST)) != (struct hostent *) NULL)
            memcpy(&connect_sock.sin_addr,connect_host->h_addr_list[0], 
                    (connect_host->h_length < sizeof(connect_sock.sin_addr)) ?
                        connect_host->h_length :sizeof(connect_sock.sin_addr));
        else
        {
            fprintf(stderr,"host %s not found\n",CALL_HOST);
#ifndef UNIX
            WSACleanup();
#endif
            exit(1);
        }
        connect_sock.sin_family = connect_host->h_addrtype;
        connect_sock.sin_port   =  htons(atoi(CALL_PORT));
/*
 * Now create the socket to output on
 */
        if ((output_socket_fd = socket(AF_INET,SOCK_STREAM,6)) < 0)
        {
            fprintf(stderr, "socket() failed error: %d", errno);
            fprintf(stderr,"PID %d Error %d Output create failed\n",
                    child_pid,errno);
#ifndef UNIX
            WSACleanup();
#endif
            exit(1);
        }
/*
 * Set the linger to ten seconds, so that close will linger a while before
 * closing connection
 */
        optval.l_onoff = 1;
        optval.l_linger = 10*SLEEP_FACTOR;  /* Factor should not be needed */
        if (setsockopt(output_socket_fd, SOL_SOCKET,
                  SO_LINGER, (char *) &optval, sizeof( optval )) < 0)
        {
            fprintf(stderr, "setsockopt() failed error: %d", errno);
#ifndef UNIX
            WSACleanup();
#endif
            exit(1);
        }
/*
 * Connect with the destination
 */
        if (connect(output_socket_fd,
                    (struct sockaddr *) &connect_sock,sizeof(connect_sock)))
        { 
            fprintf(stderr, "connect() failed error: %d", errno);
            fprintf(stderr,"PID %d Error %d Output connect failed\n",
                    child_pid,errno);
#ifndef UNIX
            WSACleanup();
#endif
            exit(1);
        }
#ifdef DEBUG
        else
            fputs("Connect succeeded\n", stderr);
#endif
#ifdef UNIX
        setsockopt(output_socket_fd, IPPROTO_TCP, TCP_KEEPALIVE, &on,
                        sizeof(on));
#else
        if (setsockopt(output_socket_fd, SOL_SOCKET, SO_KEEPALIVE, &on,
                        sizeof(on)) == SOCKET_ERROR)
            fprintf(stderr, "Failed to set TCP keepalive error: %d\n",
                         WSAGetLastError());
#endif
        if (argc > 4 && !strcmp(argv[3],"COPY"))
        {
            strcpy(&transfer_buf[2],argv[3]);
            strcat(&transfer_buf[2],argv[4]);
        }
        else
        if (argc > 5 && !strcmp(argv[3],"SCENE"))
        {
            strcpy(&transfer_buf[2],argv[3]);
            strcat(&transfer_buf[2],argv[4]);
            strcat(&transfer_buf[2]," ");
            strcat(&transfer_buf[2],argv[5]);
        }
        else
        if (argc > 4 && !strcmp(argv[3],"OVER"))
        {
            strcpy(&transfer_buf[2],"OVER");
            strcat(&transfer_buf[2], argv[4]);
        }
        else
        if (argc > 4 && !strcmp(argv[3],"SECURE"))
        {
            strcpy(&transfer_buf[2],"SECURE");
            strcat(&transfer_buf[2], argv[4]);
        }
        else
        if (argc > 3 && !strcmp(argv[3],"SLEW"))
            strcpy(&transfer_buf[2],"SLEW");
        else
        if (argc > 3 && !strcmp(argv[3],"ABORT"))
            strcpy(&transfer_buf[2],"ABORT");
        else
        {
            strcpy(&transfer_buf[2],"EXEC");
            if (argc > 3 && !strcmp(argv[3],"EXEC"))
                icount = 4;
            else
                icount = 3;
            while (icount < argc)
            {
                strcat(&transfer_buf[2], argv[icount]);
                strcat(&transfer_buf[2], " ");
                icount++;
            }
        }
        read_count = strlen(&transfer_buf[2]) + 1;
        transfer_buf[0] = read_count/256;
        transfer_buf[1] = read_count % 256;
        if (sendto(output_socket_fd, &transfer_buf[0], 2 + read_count,
                  0,0,0) != 2 + read_count)
        {
            fprintf(stderr, "Command sendto() error: %d", errno);
        }
#ifdef DEBUG
        else
            fputs("Command sendto succeeded\n", stderr);
#endif
        if (argc > 3 && !strcmp(argv[3],"SLEW"))
        {
/*
 * Make sure that no 'first packet' costs intervene
 */
            if (smart_read(output_socket_fd,transfer_buf,2) != 2)
            {
                fprintf(stderr, "Clock length read() failed error: %d", errno);
#ifndef UNIX
                WSACleanup();
#endif
                exit(1);
            }
            sendto(output_socket_fd, &transfer_buf[0], 2, 0,0,0);
            gettimeofday(&t, NULL);
            if (smart_read(output_socket_fd,transfer_buf,2) != 2)
            {
                fprintf(stderr, "Clock length read() failed error: %d", errno);
#ifndef UNIX
                WSACleanup();
#endif
                exit(1);
            }
            read_count = transfer_buf[0] * 256 + transfer_buf[1];
            if (read_count > sizeof(transfer_buf))
            {
                fputs("Clock length > valid maximum\n", stderr);
#ifndef UNIX
                WSACleanup();
#endif
                exit(1);
            }
            if (read_count != smart_read(output_socket_fd,
                                         transfer_buf,read_count))
            {
                fputs("Failed to read clock\n", stderr);
#ifndef UNIX
                WSACleanup();
#endif
                exit(1);
            }
            gettimeofday(&t2, NULL);
            t1.tv_sec = strtol(&transfer_buf[0], &x, 10);
            x++;            /* Skip the decimal point */
            t1.tv_usec = atoi(x);
#ifdef DEBUG
            printf("t: %u.%06u\n",t.tv_sec, t.tv_usec);
            printf("transfer_buf: %s\n",&transfer_buf[0]);
            printf("t1: %u.%06u\n",t1.tv_sec, t1.tv_usec);
            printf("t2: %u.%06u\n",t2.tv_sec, t2.tv_usec);
            printf("t2: %s", ctime(&t2.tv_sec));
#endif
            if (t.tv_sec == t2.tv_sec)
                t.tv_usec = (t.tv_usec + t2.tv_usec)/2;
            else
            {
                t.tv_usec = ((t2.tv_sec - t.tv_sec) * 1000000 +
                             t.tv_usec + t2.tv_usec)/2;
                t.tv_sec += t.tv_usec/1000000;
                t.tv_usec = t.tv_usec % 1000000;
            }
            if ((t.tv_sec > t1.tv_sec)
            ||  (t.tv_sec == t1.tv_sec && t.tv_usec > t1.tv_usec))
            {
                t2.tv_usec = t.tv_usec - t1.tv_usec;
                if (t2.tv_usec < 0)
                {
                    t2.tv_usec += 1000000;
                    t.tv_sec -= 1;
                }
                t2.tv_sec = t.tv_sec - t1.tv_sec;
                printf("%u.%06u\n",t2.tv_sec, t2.tv_usec);
            }
            else
            {
                t2.tv_usec = t1.tv_usec - t.tv_usec;
                if (t2.tv_usec < 0)
                {
                    t2.tv_usec += 1000000;
                    t1.tv_sec -= 1;
                }
                t2.tv_sec = t1.tv_sec - t.tv_sec;
                if (t2.tv_sec == 0 &&
                    t2.tv_usec == 0)
                    puts("0");
                else
                    printf("-%u.%06u\n",t2.tv_sec, t2.tv_usec);
            }
#ifndef UNIX
            WSACleanup();
#endif
            exit(0);
        }
/*
 * Get ready to do the forwarding.
 */
        sock_to_file = (struct sock_file_pair *)
                        malloc(sizeof(struct sock_file_pair));
        file_to_sock = (struct sock_file_pair *)
                        malloc(sizeof(struct sock_file_pair));
/*
 * COPY specifies an input file rather than stdin
 */
        if (argc > 5 && !strcmp(argv[3],"COPY"))
        {
            if ((file_to_sock->file_fd = open(argv[5],O_BINARY|O_RDONLY))
                     < 0)
            {
                fprintf(stderr,"COPY: open() of input file %s failed error %d\n",
                             argv[5], errno);
#ifndef UNIX
                WSACleanup();
#endif
                exit(1);
            }
            if (file_to_sock->file_fd != 0)
            {
                dup2(file_to_sock->file_fd,0);
                close(file_to_sock->file_fd);
            }
        }
#ifndef UNIX
        else
            _setmode(0,  O_BINARY);
        _setmode(1,  O_BINARY);
#endif
        file_to_sock->file_fd = 0;
        sock_to_file->file_fd = 1;
        file_to_sock->sock_fd = output_socket_fd;
        sock_to_file->sock_fd = output_socket_fd;
        if (!strcmp(argv[3],"SCENE"))
            sock_file_forward( sock_to_file);  /* Wait for the end */
        else
        if (strcmp(argv[3],"COPY"))
	{
#ifdef UNIX
            if (fork() == 0)
            {
                sock_file_forward( sock_to_file);
                exit(0);
            }
#else
            child_handle = CreateThread(NULL, 0,
                    (LPTHREAD_START_ROUTINE) sock_file_forward,
                    (LPVOID) sock_to_file, 0, &child_pid);
#endif
        }
        if (strcmp(argv[3],"SCENE"))
            file_sock_forward(file_to_sock);
#ifdef DONT_TRUST_LINGER
        sleep(300*SLEEP_FACTOR);
#endif
#ifdef UNIX
        while (wait(0) > 0);
#else
        if (child_handle != INVALID_HANDLE_VALUE)
        {
            if (WaitForSingleObject(child_handle, INFINITE) == WAIT_FAILED)
                fprintf(stderr, "WaitForSingleObject() failed error %d\n",
                          GetLastError());
            CloseHandle(child_handle);
        }
#endif
        shutdown(output_socket_fd, SD_BOTH);
        closesocket(output_socket_fd);
        close (0);
#ifndef UNIX
        WSACleanup();
#endif
        exit(0);
    }
    else
    if (argc == 2) 
    {
/*
 * The socket to listen on
 */
        memset((char *) &listen_sock, 0, sizeof(listen_sock));
        listen_sock.sin_family = AF_INET;
        listen_sock.sin_port   = htons((short) atoi(LISTEN_SERV));
/*
 * If E2_SECURE_HOST is set in the environment, restrict the hosts that
 * can send us commands to one of these.
 */
        if ((x = getenv("E2_SECURE_HOST")) != (char *) NULL)
            set_sec_host(x);
        if ((x = getenv("E2_BIND_HOST")) != (char *) NULL)
            num_host = inet_addr(x);
        else
            num_host = INADDR_ANY;
        listen_sock.sin_addr.s_addr = num_host;
/*
 * Initialise the signal catcher
 */
#ifdef UNIX
        signal(SIGCHLD,sigchild);
        signal(SIGTERM, sigterm);
#endif
        signal(SIGINT, sigterm);
        webini();       /* Initialise HTTP request handling */
/*
 * Now create the socket to listen on
 */
        if ((listen_socket_fd=socket(AF_INET,SOCK_STREAM,6))<0)
        { 
            puts("Listen create failed"); 
            fprintf(stderr, "socket() error: %d", errno); 
#ifndef UNIX
            WSACleanup();
#endif
            exit(1);
        }
#ifndef SO_REUSEADDR
#define SO_REUSEADDR 2
#endif
    if ((setsockopt(listen_socket_fd, SOL_SOCKET, SO_REUSEADDR, &on,
                        sizeof(on))) < 0)
        fprintf(stderr, "Failed to enable socket address re-use error: %d",
                errno);
/*
 * Bind its name to it
 */
        if (bind(listen_socket_fd,
                 (struct sockaddr *) &listen_sock,sizeof(listen_sock)))
        { 
            fprintf(stderr, "bind() error: %d", errno); 
            printf("Listen bind failed"); 
#ifndef UNIX
            WSACleanup();
#endif
            exit(1);
        }
/*
 * Declare it ready to accept calls
 */
        if (listen(listen_socket_fd,5))
        {
            printf("listen failed");
            fprintf(stderr, "  error: %d", errno); 
#ifndef UNIX
            WSACleanup();
#endif
            exit(1);
        }
#ifdef DEBUG
        fputs("Listen succeeded\n", stderr);
#endif
/*****************************************************************
 *   Start of Main Loop; wait for connexions and trace them, until
 *   terminate signal arrives; when a connexion arrives, spawn a handler.
 */
        for (;;)
        {
        char *x;
/*
 * Wait for calls
 */
            if ((accept_socket_fd = accept(listen_socket_fd,
                    (struct sockaddr *) &calling_sock, &calladdrlength)) < 0)
            {
                if (errno == EINTR)
                    continue;
                fprintf(stderr, "Accept failed error: %d\n", errno);
#ifndef UNIX
                WSACleanup();
#endif
                exit(1);
            }
            x = e2inet_ntoa(calling_sock.sin_addr);
            if (x != NULL)
                fprintf(stderr, "Accept from %s succeeded ... ", x);
            if (sec_host_cnt > 0)
            {
                if (!check_sec_host((char *) &(calling_sock.sin_addr)))
                {
                    x = e2inet_ntoa(calling_sock.sin_addr);
                    if (x != NULL)
                        fprintf(stderr,
                            "but %s is not our parent host so we ignore it\n",
                                 x);
                     closesocket(accept_socket_fd);
                     continue;
                }
                else
                    fputs("- security check passed - ", stderr);
            }
            else
                fputs("- no security check applied - ", stderr);
#ifdef UNIX
            setsockopt(accept_socket_fd, IPPROTO_TCP, TCP_KEEPALIVE, &on,
                        sizeof(on));
#else
            if (setsockopt(accept_socket_fd, SOL_SOCKET, SO_KEEPALIVE, &on,
                        sizeof(on)) == SOCKET_ERROR)
                fprintf(stderr, "Failed to set TCP keepalive error: %d\n",
                         WSAGetLastError());
#endif
            do_command(accept_socket_fd);
#ifdef DEBUG
            fflush(stderr);
#endif
        }    /*    End of infinite for */
    }
    exit(0);
}    /* End of Main */
/*
 * Run a command asynchronously, without a shell.
 */
static void kickoff(cmdline, errlog)
char * cmdline;
char * errlog;
{
#ifndef UNIX
DWORD dwCreationFlags = CREATE_NEW_PROCESS_GROUP;
BOOL bInheritHandles = TRUE;
STARTUPINFO si;
PROCESS_INFORMATION pi;
static char * prog_name;
char * command_line;
#endif
int i;
FILE *fp;
int h0;
int h1;
int h2;
char * args[256];                           /* Dummy arguments to process */
/*
 * Check that we actually have a command to execute
 */
    if (cmdline == NULL)
        return;
/*
 * Process the arguments in the string that has been read
 */
#ifdef UNIX
    if ((args[0]=strtok(cmdline,"  \n"))==NULL)
         return;
/*
 * Generate an argument vector
 */
    for (i=1;
             i < 255 && (args[i]=strtok(NULL," \n")) != (char *) NULL;
                 i++);
    args[i] = (char *) NULL;
    if ((children[child_cnt++] = fork()) == 0)
    {     /* Child pid */
        (void) close(0);
        (void) close(1);
        (void) close(2);
        fp = fopen(errlog, "wb");
        if (fileno(fp) != 1)
            (void) dup2(fileno(fp),1);
        if (fileno(fp) != 2)
            (void) dup2(fileno(fp),2);
        if (fileno(fp) != 1 && fileno(fp) != 2)
            close(fileno(fp));
        if (execvp(args[0],args) < 0)
        {
            perror("Exec failed");
            (void) fprintf(stderr,
                   "Could not execute program %s\n", args[0]);
            exit(1);
        }
    }
#else
/*
 * Find the command interpreter
 */
    if (prog_name == (char *) NULL
     && (prog_name = getenv("COMSPEC")) == (char *) NULL)
    {
        if ( _osver & 0x8000 )
            prog_name = "C:\\WINDOWS\\COMMAND.COM";
        else
            prog_name = "C:\\WINDOWS\\SYSTEM32\\CMD.EXE";
/*            prog_name = "C:\\WINNT\\SYSTEM32\\CMD.EXE"; */
    }
    if ((command_line = (char *) malloc(strlen(prog_name) + 10
               + strlen(cmdline) +strlen(errlog)  + 4))
                  == (char *) NULL)
        return;
    sprintf(command_line, "%s /d /q /c %s 2>%s", prog_name, cmdline, errlog);
    fprintf(stderr, "Launch Command: %s\n", command_line);
/*
 * Default setup information for the spawned process
 */
    si.cb = sizeof(si);
    si.lpReserved = NULL;
    si.lpDesktop = NULL;
    si.lpTitle = NULL;
    si.dwX = 0;
    si.dwY = 0;
    si.dwXSize = 0;
    si.dwYSize= 0;
    si.dwXCountChars = 0;
    si.dwYCountChars= 0;
    si.dwFillAttribute= 0;
    si.dwFlags = STARTF_USESTDHANDLES /* | STARTF_USESHOWWINDOW */ ;
    si.wShowWindow = 0;
    si.cbReserved2 = 0;
    si.lpReserved2 = NULL;
/*
 * Execute the command
 */
    si.hStdInput = (HANDLE) _get_osfhandle(0);
    si.hStdOutput = (HANDLE) _get_osfhandle(1);
    si.hStdError = (HANDLE) _get_osfhandle(2);
    if (!CreateProcess(prog_name, command_line, NULL, NULL, bInheritHandles,
                  dwCreationFlags, NULL, NULL, &si, &pi))
        fprintf(stderr,"CreateProcess failed error:%d\n", GetLastError());
    else
    {
        children[child_cnt++] = (long int) pi.hProcess;
        CloseHandle(pi.hThread);
    }
    free(command_line);
#endif
    return;
}
static char * replace_env(name, value, currp)
char * name;
char * value;
char * currp;
{
    if (currp != NULL)
        free(currp);
    currp = (char *) malloc(strlen(name) + strlen(value) + 2);
    sprintf(currp, "%s=%s", name, value);
    putenv(currp);
    return currp;
}
/*
 * Run a command asynchronously, without a shell.
 */
static void kickoff_sqldrive(pdr, pxarg0, pid, bundle, thread, path_con_args)
char * pdr;
char * pxarg0;
char * pid;
int bundle;
int thread;
char * path_con_args;
{
#ifndef UNIX
DWORD dwCreationFlags = CREATE_NEW_PROCESS_GROUP;
BOOL bInheritHandles = TRUE;
STARTUPINFO si;
PROCESS_INFORMATION pi;
static char * prog_name;
char * command_line;
#endif
int i;
FILE *fp;
int h0;
int h1;
int h2;
char bun_char[23];
char thread_char[23];
char log_file[23];
char echo_file[23];
char dump_file[23];
char * args[8];                           /* Dummy arguments to process */
/*
 * Process the arguments in the string that has been read
 */
    args[0] = pdr;
    i = 1;
    sprintf(echo_file, "echo%s.%d.%d", pid, bundle,thread); 
    sprintf(dump_file, "dump%s.%d.%d", pid, bundle,thread); 
    sprintf(log_file, "log%s.%d.%d", pid, bundle,thread); 
    sprintf(bun_char, "%d", bundle);
    sprintf(thread_char, "%d", thread);
#ifdef UNIX
    if (thread == 0)
        args[i++] = pxarg0;
    args[i++] = log_file;
    args[i++] = pid;
    args[i++] = bun_char;
    args[i++] = thread_char;
    args[i++] = path_con_args;
    args[i] = (char *) NULL;
    if ((children[child_cnt++] = fork()) == 0)
    {     /* Child pid */
        (void) close(0);
        (void) close(1);
        (void) close(2);
        fp = fopen(dump_file, "wb");
        if (fileno(fp) != 1)
            (void) dup2(fileno(fp),1);
        if (fileno(fp) != 2)
            (void) dup2(fileno(fp),2);
        if (fileno(fp) != 1 && fileno(fp) != 2)
            fclose(fp);
        fclose(fp);
        fp = fopen(echo_file, "rb");
        if (fileno(fp) != 0)
        {
            (void) dup2(fileno(fp),0);
            fclose(fp);
        }
        if (execvp(args[0],args) < 0)
        {
            perror("Exec failed");
            (void) fprintf(stderr,
                   "Could not execute program %s\n", args[0]);
            exit(1);
        }
    }
#else
/*
 * Find the command interpreter
 */
    if (prog_name == (char *) NULL
     && (prog_name = getenv("COMSPEC")) == (char *) NULL)
    {
        if ( _osver & 0x8000 )
            prog_name = "C:\\WINDOWS\\COMMAND.COM";
        else
            prog_name = "C:\\WINDOWS\\SYSTEM32\\CMD.EXE";
/*            prog_name = "C:\\WINNT\\SYSTEM32\\CMD.EXE"; */
    }
    if ((command_line = (char *) malloc(strlen(prog_name) + 20
            + strlen( pdr)
            + strlen( pxarg0)
            + strlen( echo_file)
            + strlen( dump_file)
            + strlen( log_file)
            + strlen( pid)
            + strlen( bun_char)
            + strlen( thread_char)
            + strlen( path_con_args)))
                  == (char *) NULL)
        return;
    if (thread == 0)
        sprintf(command_line,
              "%s /d /q /c %s %s %s %s %s %s <%s 2>%s", prog_name, 
                      pdr,
                      pxarg0,
                      log_file,
                      pid,
                      bun_char,
                      thread_char,
                      path_con_args,
                      echo_file,
                      dump_file);
    else
        sprintf(command_line,
              "%s /d /q /c %s %s %s %s %s <%s 2>%s", prog_name, 
                      pdr,
                      log_file,
                      pid,
                      bun_char,
                      thread_char,
                      path_con_args,
                      echo_file,
                      dump_file);
    fprintf(stderr, "Launch Command: %s\n", command_line);
/*
 * Default setup information for the spawned process
 */
    si.cb = sizeof(si);
    si.lpReserved = NULL;
    si.lpDesktop = NULL;
    si.lpTitle = NULL;
    si.dwX = 0;
    si.dwY = 0;
    si.dwXSize = 0;
    si.dwYSize= 0;
    si.dwXCountChars = 0;
    si.dwYCountChars= 0;
    si.dwFillAttribute= 0;
    si.dwFlags = STARTF_USESTDHANDLES /* | STARTF_USESHOWWINDOW */ ;
    si.wShowWindow = 0;
    si.cbReserved2 = 0;
    si.lpReserved2 = NULL;
/*
 * Execute the command
 */
    si.hStdInput = (HANDLE) _get_osfhandle(0);
    si.hStdOutput = (HANDLE) _get_osfhandle(1);
    si.hStdError = (HANDLE) _get_osfhandle(2);
    if (!CreateProcess(prog_name, command_line, NULL, NULL, bInheritHandles,
                  dwCreationFlags, NULL, NULL, &si, &pi))
        fprintf(stderr,"CreateProcess failed error:%d\n", GetLastError());
    else
    {
        children[child_cnt++] = (long int) pi.hProcess;
        CloseHandle(pi.hThread);
    }
    free(command_line);
#endif
    return;
}
/*
 * Terminate all the known child processes
 */
void zapall(me)
long int me;
{
int i;

    for (i = 0; i < child_cnt; i++)
    {
#ifdef UNIX
        kill(children[i], SIGTERM);
#else
        if (((HANDLE) children[i]) != INVALID_HANDLE_VALUE
        &&  ((HANDLE) children[i]) != (HANDLE) me)
        {
            TerminateProcess((HANDLE) children[i], SIGINT);
            CloseHandle((HANDLE) children[i]);
        }
#endif
    }
#ifdef UNIX
    while (wait(&i) > 0);
#else
    for (i = 0; i < thread_cnt; i++)
        if (threads[i] != INVALID_HANDLE_VALUE
         && threads[i] != (HANDLE) me)
        {
            TerminateThread(threads[i], SIGINT);
            CloseHandle(threads[i]);
        }
    thread_cnt = 0;
#endif
    child_cnt = 0;
    return;
}
/*
 * Process a runout file
 */
static int do_run(pid)
char * pid;
{
int nusers;
char tran[80];
int ntrans;
char para_1[80];
int think;
char para_2[80];
int actor;
char seed[80];
char errfl[80];
FILE * fp;
char buf[2048];
int bundle;
int i;
char *pdr;
char *pxarg0;
char *pxarg;
int degenerate_flag;
int single_thread_flag;
int stagger;
char * path_con_args;
char temp_1[128];
static char * e2_path_log = NULL;
static char * e2_path_tranche = NULL;
static char * e2_path_bundle = NULL;
static char * e2_path_rope = NULL;

    sprintf(buf,"runout%s",pid);
    if ((fp = fopen(buf,"rb")) == (FILE *) NULL)
    {
        fprintf(stderr,"Cannot open file %s\n",buf);
        return 0;
    }
/*
 * Find out which driver we are using, etc. etc.
 */
    if ((pdr = getenv("PATH_DEGENERATE")) != (char *) NULL)
        degenerate_flag = atoi(pdr);
    else
        degenerate_flag = 0;
    if ((pdr = getenv("PATH_SINGLE_THREAD")) != (char *) NULL)
        single_thread_flag = atoi(pdr);
    else
        single_thread_flag = 0;
    path_con_args = getenv("PATH_CON_ARGS");
    if ((pdr = getenv("PATH_STAGGER")) == (char *) NULL)
        stagger = 1;
    else
    if ((stagger = atoi(pdr)) < 0)
        stagger = 0;
    if ((pdr = getenv("PATH_DRIVER")) == (char *) NULL)
        pdr = "racdrive.exe";
    if ((pxarg0 = getenv("PATH_EXTRA_ARGS0")) == (char *) NULL)
        pxarg0 = "";
    if ((pxarg = getenv("PATH_EXTRA_ARGS")) == (char *) NULL)
        pxarg = "";
/*
 * Loop - pick up the details from the file
 */
    bundle = 1;
    (void) fgets(buf, sizeof(buf), fp);  /* Skip the 3 blank lines */
    (void) fgets(buf, sizeof(buf), fp);
    (void) fgets(buf, sizeof(buf), fp);
    e2_path_tranche = replace_env("E2_PATH_TRANCHE", pid, e2_path_tranche);
    while (fgets(buf,sizeof(buf),fp) != (char *) NULL)
    {
    int nf = sscanf(buf, "%d %s %d %d %d %s %s %s",
               &nusers, tran, &ntrans, &think, &actor, seed, para_1, para_2);
        if (nf < 6)
            continue;
        if (!strcmp(tran, "end_time"))
            continue;
        sprintf(temp_1, "%d", bundle);
        e2_path_bundle = replace_env("E2_PATH_BUNDLE", temp_1, e2_path_bundle);
        if (!strncasecmp(pdr, "sqldrive",8) && path_con_args != NULL)
        {
            for (i = 0; i < nusers; i++)
            {
                kickoff_sqldrive(pdr, pxarg0, pid, bundle, i, path_con_args);
                if (stagger)
                    sleep(stagger*SLEEP_FACTOR);
            }
        }
        else
/*
 * Actor must be zero for non-network benchmarks.
 *
 * Beware; only the first four arguments are identical for the different driver
 * programs.
 *
 * The code below works for ipdrive, webdrive, racdrive and t3drive (which
 * don't examine the actor parameter) and for any of the custom drivers that
 * take the standard 4 arguments and an input file name.
 *
 * The code below doesn't work for the drivers that take their input from
 * stdin; ptydrive, which only takes 4 parameters, and sqldrive, which wants a
 * DB sign-on as parameter 5. Furthermore, if the driver is ptydrive, the
 * actor parameter from the runout file will actually be the typing speed.
 */
        if (actor == 0)
        {
            if (single_thread_flag)
            {
                for (i = 0; i < nusers; i++)
                {
                    sprintf(temp_1, "%d", i);
                    e2_path_rope = replace_env("E2_PATH_ROPE",temp_1,
                                               e2_path_rope);
                    sprintf(temp_1, "log%s.%d.%d", pid, bundle, i);
                    e2_path_log = replace_env("E2_PATH_LOG",temp_1,e2_path_log);
                    if (i == 0)
                        sprintf(buf, 
                           "%s %s log%s.%d.%d %s %d %d echo%s.%d.%d 0",
                             pdr, pxarg0,
                             pid, bundle, i, pid, bundle, i, pid, bundle,
	        		 degenerate_flag ? 0: i);
                    else
                        sprintf(buf, 
                           "%s %s log%s.%d.%d %s %d %d echo%s.%d.%d 0",
                             pdr, pxarg,
                             pid, bundle, i, pid, bundle, i, pid, bundle,
        			 degenerate_flag ? 0: i);
                    sprintf(errfl, "dump%s.%d.%d", pid, bundle, i);
                    kickoff(buf, errfl);
                    if (stagger)
                        sleep(stagger*SLEEP_FACTOR);
                }
            }
            else
            {
            char * cmd_line = (char *) malloc(32 + strlen(pdr) + strlen(pxarg) +
                             +strlen(pxarg0) + (strlen(pid) + 27)*(2 + nusers));
            char *x = cmd_line + sprintf(cmd_line, 
                       "%s -m %d %s %s log%s.%d %s %d 0 echo%s.%d.0",pdr,nusers,
                         pxarg0, pxarg, pid, bundle, pid, bundle, pid, bundle);
                e2_path_rope = replace_env("E2_PATH_ROPE","0", e2_path_rope);
                sprintf(temp_1, "log%s.%d.0", pid, bundle);
                e2_path_log = replace_env("E2_PATH_LOG",temp_1, e2_path_log);
                for (i = 1; i < nusers; i++)
                    x += sprintf(x, " echo%s.%d.%d", pid, bundle, i);
                sprintf(errfl, "dump%s.%d.0", pid, bundle);
                kickoff(cmd_line, errfl);
                free(cmd_line);
                if (stagger)
                    sleep(nusers * stagger*SLEEP_FACTOR);
            }
        }
        else
        if (nusers)
        {
/*
 * Actor is a count of actors; can be 1 to 3. Only network benchmarks have
 * multiple actors, so the arguments must be a la ipdrive.
 */
            e2_path_rope = replace_env("E2_PATH_ROPE","0", e2_path_rope);
            sprintf(temp_1, "log%s.%d.0", pid, bundle);
            e2_path_log = replace_env("E2_PATH_LOG",temp_1, e2_path_log);
            sprintf(buf, 
                   "ipdrive log%s.%d.0 %s %d 0 echo%s.%d.0 %s",
                         pid, bundle, pid, bundle, pid, bundle, seed);
            sprintf(errfl, "dump%s.%d.0_%s", pid, bundle, seed);
            kickoff(buf, errfl);
            if (actor > 1)
            {
                sprintf(buf, 
                   "ipdrive log%s.%d.0 %s %d 0 echo%s.%d.0 %s",
                         pid, bundle, pid, bundle, pid, bundle, para_1);
                sprintf(errfl, "dump%s.%d.0_%s", pid, bundle, para_1);
                kickoff(buf, errfl);
            }
            if (actor > 2)
            {
                sprintf(buf, 
                   "ipdrive log%s.%d.0 %s %d 0 echo%s.%d.0 %s",
                         pid, bundle, pid, bundle, pid, bundle, para_2);
                sprintf(errfl, "dump%s.%d.0_%s", pid, bundle, para_2);
                kickoff(buf, errfl);
            }
            if (stagger)
                sleep(stagger*SLEEP_FACTOR);
        }
        bundle++;
    }
/*
 * No end of run specified; take everything
 */
    fclose(fp);
    return 1;
}
/*
 * Execute stepped scenarios
 */
static void do_scen(pid, tint)
char * pid;
int tint;
{
char *pr;
char mod_pid[256];
int i = 1;
int del;
/*
 * Loop - execute each step that makes up the overall run, waiting the
 * requisite interval between each step.
 */
    strcpy(mod_pid, pid);
    while (do_run(mod_pid))
    {
#ifdef UNIX
        for (del = tint; del > 0;)
            del = sleep(del);
#else
        sleep(tint*SLEEP_FACTOR);
#endif
        sprintf(mod_pid, "%s_%d", pid, i++);
        if ((pr = strtok(NULL, " \n\r")) != (char *) NULL)
            tint = atoi(pr);
    }
/*
 * If this is a remote agent, package up the results for download
 */
    if ((pr = getenv("PATH_REMOTE")) != (char *) NULL)
    {
        sprintf(mod_pid,"miniarc c res%s.tar runout%s* log%s*", pid, pid, pid);
        system(mod_pid);
        sprintf(mod_pid,"res%s.tar.bz2", pid);
        unlink(mod_pid);
        sprintf(mod_pid,"bzip2 res%s.tar", pid);
        system(mod_pid);
    }
    return;
}
