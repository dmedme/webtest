/*
 * Copy a named pipe to stdout forever.
 *
 * Needed for Windows and Solaris, because you cannot simply write to
 * Windows Named Pipes or Solaris UNIX Domain Sockets from the shell.
 */
#include "minitest.h"
int main(argc, argv)
int argc;
char ** argv;
{
int retcode = 0;
int fifo_fd = -1;
FILE * fifo;
char buf[BUFSIZ];
int i;
struct stat sbuf;
int len;

    if (argc < 2)
    {
        fputs("Provide the name of an input FIFO\n", stderr);
        exit(0);
    }
#ifndef MINGW32
    if ((stat(argv[1], &sbuf)) < 0)
    {
        perror("FIFO does not exist");
 (void) fprintf(stderr,"Error: %d; perhaps target isn't running?\n",errno);
        exit(1);
    }
#else
    _setmode(1, O_BINARY);
#if __MSVCRT_VERSION__ >= 0x800
    (void) _set_invalid_parameter_handler(_invalid_parameter);
#endif
#endif
/*
 * fifo_listen on Windows is really a no-op, since we achieve generalised
 * re-use by closing and re-opening the thing within the accept. Perhaps
 * we should do the disconnect thing instead.
 */
#ifdef SOLAR
    if ((fifo_fd = fifo_listen(argv[1])) < 0)
    {
        perror("FIFO listen failed");
        (void) fprintf(stderr,
             "Error: %d; perhaps source isn't running?\n",errno);
        exit(1);
    }
#else
#ifdef MINGW32
    if ((fifo_fd = fifo_listen(argv[1])) < 0)
    {
        perror("FIFO listen failed");
        (void) fprintf(stderr,
                 "Error: %d; does something else have it open already?\n",
                       GetLastError());
        exit(1);
    }
#endif
#endif
#ifdef SOLAR
    if ((fifo_fd = fifo_accept(fifo_fd, argv[1])) < 0
       || (fifo = fdopen(fifo_fd,"rb")) == (FILE *) NULL)
    {
        perror("FIFO accept failed");
        (void) fprintf(stderr,
                 "Error: %d; does something else have it open already?\n",
                    errno);
        if (fifo_fd != -1)
            close(fifo_fd);
        exit(1);
    }
#else
#ifdef MINGW32
    if ((fifo_fd = fifo_accept(argv[1], fifo_fd)) < 0
        || (fifo = fdopen(fifo_fd,"rb")) == (FILE *) NULL)
    {
        perror("FIFO accept failed");
        (void) fprintf(stderr,
                 "Error: %d; does something else have it open already?\n",
                    GetLastError());
        if (fifo_fd != -1)
            close(fifo_fd);
        exit(1);
    }
#else
    if ((fifo=fopen(argv[1],"rb")) == (FILE *) NULL)
    {
        perror("Cannot Open FIFO");
        exit(1);
    }
#endif
#endif
/*
 * Attempt to output fifo to stdout
 */
    while (fgets(buf, sizeof(buf), fifo) == buf)
    {
        if (fputs(buf, stdout) < 0)
            break;
        fflush(stdout);
    }
    fclose(fifo);
    exit(0);
}
