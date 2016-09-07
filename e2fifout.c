/*
 * Copy stdin to a named pipe forever.
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
        fputs("Provide the name of an output FIFO\n", stderr);
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
    _setmode(0, O_BINARY);
#if __MSVCRT_VERSION__ >= 0x800
    (void) _set_invalid_parameter_handler(_invalid_parameter);
#endif
#endif
#ifdef SOLAR
    if ((fifo_fd = fifo_connect(argv[1], argv[1])) < 0
       || (fifo = fdopen(fifo_fd,"wb")) == (FILE *) NULL)
    {
        perror("FIFO connect failed");
        (void) fprintf(stderr,"Error: %d; perhaps sink isn't running?\n",errno);
        if (fifo_fd != -1)
            close(fifo_fd);
        exit(1);
    }
#else
#ifdef MINGW32
    if ((fifo_fd = fifo_connect(argv[1], argv[1])) < 0
        || (fifo = fdopen(fifo_fd,"wb")) == (FILE *) NULL)
    {
        perror("FIFO connect failed");
     (void) fprintf(stderr,"Error: %d; perhaps sink isn't running?\n",
                    GetLastError());
        if (fifo_fd != -1)
            close(fifo_fd);
        exit(1);
    }
#else
    if ((fifo=fopen(argv[1],"wb")) == (FILE *) NULL)
    {
        perror("Cannot Open FIFO");
        exit(1);
    }
#endif
#endif
    setbuf(fifo,(char *) NULL);
/*
 * Attempt to output stdin to the FIFO
 */
    while(fgets(buf, sizeof(buf), stdin) == buf)
    {
        if (fputs(buf, fifo) < 0)
            break;
        fflush(fifo);
    }
    fclose(fifo);
    exit(0);
}
