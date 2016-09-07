/******************************************************************************
 * webmenu.c - a subset of the functionality required of a web-server, to
 * support a Web interface to PATH.
 ******************************************************************************
 * As originally conceived, the thing was entirely single threaded, and used
 * one TCP connection per HTTP request. It was designed to display web-forms,
 * and accept input, in the same manner as natmenu (dumb terminal) and dman
 * (Windows GUI).
 *
 * In addition, it fielded requests for static content, so that logos and
 * static material such as fdreport run results would be rendered without
 * disrupting the dialogues.
 *
 * Parsing of the incoming HTTP was rudimentary.
 *
 * Static URL handling was further enhanced to support file upload and file
 * editing.
 *
 * The main processing loop was as follows
 * -  If the request appeared to be a GET, PUT or POST of a static file,
 *    webmenu attempted to service it.
 * -  Otherwise the incoming URL line, minus the GET / and the status, was
 *    emitted on stdout.
 * -  The name of a file to return was read on stdin.
 *    -  If the file could be opened, it was returned
 *    -  If not, a 404 (Not Found) header was returned.  
 ******************************************************************************
 * This is actually very effective. It is good discipline to enforce that
 * someone is only doing one thing; the flow of control follows the chosen
 * procedures.
 *
 * However, it doesn't cater for a new requirement; periodic monitors.
 *
 * We want these to live in independent threads of control.
 *
 * We can't afford to allow these to block the main dialogue.
 *
 * Monitors are built with:
 * -  'Local sensors'; programs on remote machines that log Performance
 *    Indicators
 * -  logmon, a program that forwards data from files that has been added since
 *    it last checked.
 * -  minitest, that provides the remote invocation mechanisms and cross-machine
 *    data transfer.
 * -  various programs that render input as web pages, fdreport being one such.
 * -  gnuplot, which generates the graphs.
 *
 * minitest is TCP-aware but not HTTP aware.
 *
 * The simplest way of extending the design seems to be to allow webmenu to
 * service multiple send/receive pipe pairs, in a manner analogous to the
 * default. But we need to do this in a more parallel manner than at present.
 *
 * So we are going to:
 * -  Recognise 'monitor' URL's
 * -  Maintain a send/receive pipe for such, creating the pair if it does not
 *    already exist. We will have a fixed list of slots; say 64. We won't need
 *    as many as that, probably.
 * -  fork() a new process or kick off a thread to deal with the request,
 *    freeing the main thread for the dialogue.   
 ******************************************************************************
 * Security is rudimentary
 * -  You can't have .. in a file path
 * -  You can't have an absolute path
 * -  You can only update things under the scripts or data directory,
 *    or a few specific elements
 ******************************************************************************
 * Copyright (c) E2 System 2008
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (C) E2 Systems Limited 2008";
#include "minitest.h"
static int debug_level = 0;
static char ret_buf[16384];
#include "bmmatch.h"
#ifdef MINGW32
#include "matchlib.h"
static int pipe (int fd[2])
{
    return _pipe(fd, 4096, O_BINARY|O_NOINHERIT);
}
void setlinebuf(FILE * fp)
{
    setvbuf(fp, NULL, _IOLBF, 4096);
    return;
}
#else
/*
 * Non-standard Windows dup2() behaviour
 */
static int _dup2(int oldfd, int newfd)
{
    oldfd = dup2(oldfd, newfd);
    return ((oldfd == newfd) ? 0 : -1);
}
#endif
void timeout();
/*
 * Actual tables
 */
struct webmenu {
    struct bm_table * ncrp;
    struct bm_table * clp;
    struct bm_table * boundaryp;
    struct bm_table * traverse_u;
    struct bm_table * traverse_w;
    char * out_fifo;
} webmenu;
/****************************************************************************
 * Routine to check a file.
 * -   path mustn't start with /
 * -   path mustn't contain ../
 * -   if file exists, it must be a regular file
 * -   if file is being written, it must be below the scripts directory,
 *     must be below the data directory, or be pathenv.sh
 */
int sec_check(fname,  write_flag)
char * fname;
int write_flag;
{
struct stat sbuf;
int ret;
char * bound = fname +  strlen(fname);

    while (*fname =='/' || *fname =='\\' || *fname == ' ')
        fname++;
    if (bm_match(webmenu.traverse_u, fname, bound) != NULL
     || bm_match(webmenu.traverse_w, fname, bound) != NULL
     || (write_flag
        && strncmp(fname, "scripts/", 8)
        && strncmp(fname, "path_web/pathenv.sh", 19)
        && strncmp(fname, "web_path_web/pathenv.sh", 23)
        && strncmp(fname, "data/", 5)))
        return 403;
    if ((ret = stat(fname, &sbuf)) && !write_flag)
        return 404;
    if (!ret && (!S_ISREG(sbuf.st_mode)))
        return 403;
    return 0;
}
/****************************************************************************
 * Routine to set up a socket address
 */
static void sock_ready(host, port, out_sock)
char * host;
int port;
struct sockaddr_in * out_sock;
{
struct hostent  *connect_host;
in_addr_t addr;

    connect_host=gethostbyname(host);
    if (connect_host == (struct hostent *) NULL)
        addr = inet_addr(host); /* Assume numeric arguments */
    else
        memcpy((char *) &addr, (char *) connect_host->h_addr_list[0], 
                    (connect_host->h_length < sizeof(addr)) ?
                        connect_host->h_length :sizeof(addr));
/*
 * Set up the socket address
 */
     memset(out_sock,0,sizeof(*out_sock));
#ifdef OSF
     out_sock->sin_len = connect_host->h_length + sizeof(out_sock->sin_port);
#endif
     out_sock->sin_family = AF_INET;
     out_sock->sin_port   = htons((unsigned short) port);
     memcpy((char *) &(out_sock->sin_addr.s_addr),
            (char *) &addr,(sizeof(out_sock->sin_addr.s_addr) < sizeof(addr)) ?
                                 sizeof(out_sock->sin_addr.s_addr) :
                                 sizeof(addr));
    return;
}
void log_sock_bind(fd)
int fd;
{
struct sockaddr_in check;
int len = sizeof(check);

    if (!getsockname(fd,(struct sockaddr *) (&check),&len))
    {
        (void) fprintf(stderr,"Socket %d bound as %x:%d\n",
                                fd, check.sin_addr.s_addr, check.sin_port);
        (void) fflush(stderr);
    }
    else
    { 
        perror("getsockname() failed"); 
    }
    return;
}
/************************************************************************
 * Listen set up 
 */
int listen_setup(host, port, sockp)
char * host;
int port;
struct sockaddr_in *sockp;
{
struct protoent *web_prot;
/*
 * This will never ever change ...
 */
static int webprot = 6;
unsigned int flag = 1;
int listen_fd;

    if (debug_level > 1)
        (void) fprintf(stderr,"listen_setup(%s,%d)\n", host,port);
    if (webprot == -1)
    {
        web_prot=getprotobyname("tcp");
        if ( web_prot == (struct protoent *) NULL)
        { 
            fputs( "Logic Error; no tcp protocol!\n", stderr);
            return;
        }
        webprot = web_prot->p_proto;
    }
/*
 *    Construct the Socket Address
 */
    sock_ready(host, port, sockp);
    sockp->sin_addr.s_addr = INADDR_ANY;
/*
 *    Now create the socket to listen on
 */
    if ((listen_fd=
         socket(AF_INET,SOCK_STREAM,webprot))<0)
    { 
        fputs( "Listen socket create failed\n", stderr);
        perror("Listen socket create failed"); 
    }
/*
 * Bind its name to it
 */
    if (bind(listen_fd,(struct sockaddr *) (sockp),sizeof(*sockp)))
    { 
        fputs( "Listen socket bin failed\n", stderr);
        perror("Listen bind failed"); 
    }
    else
    if (debug_level > 1)
        log_sock_bind(listen_fd);
/*
 * Make sure we can reuse the address
 */
    if (setsockopt(listen_fd,SOL_SOCKET,SO_REUSEADDR,
                       (char *) &flag, sizeof(int)) < 0)
    {
        fprintf(stderr, "Set Address Re-use Error:%d\n", errno);
        perror("setsockopt()");
    }
/*
 *    Declare it ready to accept calls
 */
    if (listen(listen_fd, 512))
    { 
        fputs("Listen() failed\n", stderr); 
        perror("listen() failed"); 
        fflush(stderr);
    }
    return listen_fd;
}
/*
 * Send our returned data on the designated port
 */
void web_send(web_out, mess_len, buf)
int web_out;
int mess_len;
char * buf;
{
int so_far = 0;
int r;
int loop_detect;

    if (mess_len <= 0)
    {
	shutdown(web_out, SD_BOTH);
        closesocket(web_out);
        return;
    }
    so_far = 0;
    loop_detect = 0;
    if (debug_level > 1)
        (void) fprintf(stderr,"web_out(%d)\n", mess_len);
    do
    {
        signal(SIGPIPE, timeout);
        r = sendto(web_out, buf, mess_len, 0,0,0);
        if (r <= 0)
        {
            loop_detect++;
#ifndef MINGW32
            if (errno == EINTR && loop_detect < 100)
                continue;
#endif
            break;
        }
        else
            loop_detect = 0;
        so_far += r;
        mess_len -= r;
        buf += r;
    }
    while (mess_len > 0);
    return;
}
static void cont_type_lookup(fext, outp)
char * fext;
char * outp;
{
    if (!strcasecmp(fext, "html")
     || !strcasecmp(fext, "htm"))
        strcpy(outp, "text/html");
    else
    if (!strcasecmp(fext, "png"))
        strcpy(outp, "image/png");
    else
    if (!strcasecmp(fext, "gif"))
        strcpy(outp, "image/gif");
    else
    if (!strcasecmp(fext, "jpg")
     || !strcasecmp(fext, "jpeg"))
        strcpy(outp, "image/jpeg");
    else
    if (!strcasecmp(fext, "svg"))
        strcpy(outp, "image/svg+xml");
    else
    if (!strcasecmp(fext, "css"))
        strcpy(outp, "text/css");
    else
    if (!strcasecmp(fext, "js"))
        strcpy(outp, "text/javascript");
    else
    if (!strcasecmp(fext, "txt"))
        strcpy(outp, "text/plain");
    else
    if (!strcasecmp(fext, "msg"))   /* A PATH script */
        strcpy(outp, "text/plain");
    else
    if (!strcasecmp(fext, "pdf"))
        strcpy(outp, "application/pdf");
    else
    if (!strcasecmp(fext, "jar"))
        strcpy(outp, "application/x-java-archive");
    else
    if (!strcasecmp(fext, "doc"))
        strcpy(outp, "application/msword");
    else
    if (!strcasecmp(fext, "xls")
     || !strcasecmp(fext, "csv"))
        strcpy(outp, "application/msexcel");
    else
    if (!strcasecmp(fext, "ppt")
     || !strcasecmp(fext, "pps"))
        strcpy(outp, "application/mspowerpoint");
    else
        strcpy(outp, "application/octet-stream");
    return;
}
static int alarm_gone;
void timeout()
{
    alarm_gone = 1;
    return;
}
/*
 * Send for dynamic content, where some of the headers prepend the content
 */ 
static void web_file_send_dynamic(web_out, fname)
int web_out;
char * fname;
{
FILE * ifp;
char buf[1500];
int len;

    if (debug_level)
        (void) fprintf(stderr,"web_file_send_dynamic(%s) start\n", fname);
    if ((ifp = fopen(fname, "rb")) == (FILE *) NULL)
    {
        web_send(web_out, 45,
                  "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
        if (debug_level > 1)
            (void) fprintf(stderr,"web_file_send(%s) not found\n", fname);
        return;
    }
    else
        web_send(web_out, 36,
                  "HTTP/1.1 200 OK\r\nConnection: close\r\n");
    while((len = fread(buf,sizeof(char), sizeof(buf), ifp)) > 0)
        web_send(web_out, len, buf);
    fclose(ifp);
    if (debug_level)
        (void) fprintf(stderr,"web_file_send_dynamic(%s) complete\n", fname);
    return;
}
/*
 * Send a normal static file
 */
static void web_file_send_static(f, fp, fname)
int f;
FILE *fp;
char * fname;
{
char fbuf[16384];
char * xp1;
int n;

    if (debug_level)
        (void) fprintf(stderr,"web_file_send_static(%s) start\n", fname);
    if (fp == NULL)
    {
        web_send(f, 26, "HTTP/1.1 404 Not Found\r\n\r\n"); 
        return;
    }
    web_send(f, 36, "HTTP/1.1 200 OK\r\nConnection: close\r\n");
    memcpy(fbuf, "Content-type: ", 14);
    if ((xp1 = strrchr(fname, '.')) == NULL)
        xp1 = fname;
    else
        xp1++;
    cont_type_lookup(xp1, fbuf + 14);
    xp1 = fbuf + 14 + strlen(fbuf + 14);
    *xp1++ = '\r';
    *xp1++ = '\n';
    *xp1++ = '\r';
    *xp1++ = '\n';
    web_send(f, (xp1 - fbuf), fbuf);
/*
 * An opportunity for LINUX sendfile() or its equivalent on other operating
 * systems...
 */
    while((n = fread(fbuf,sizeof(char), sizeof(fbuf), fp)) > 0)
        web_send(f, n, fbuf);
    fclose(fp);
    shutdown(f, SD_BOTH);
    closesocket(f);
    if (debug_level)
        (void) fprintf(stderr,"web_file_send_static(%s) complete\n", fname);
    return;
}
/*
 * Naively handle a PUT
 */
static char * attempt_put(f, buf, bound, mess_len)
int f;
char * buf;
char * bound;
int mess_len;
{
FILE * fp;
int n;
char fbuf[16384];
char * cp;
int cont_len;
char * ehp;

/*
 * Prohibit gross breaches of security
 */
    while (*buf == '/' || *buf == '\\')
    {
        buf++;
        mess_len--;
    }
    if (sec_check(buf, 1) == 403)
    {
        web_send(f, 45,
                  "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
        shutdown(f, SD_BOTH);
        closesocket(f);
        return NULL;
    }
/*
 * Search for the length; exit if not found
 */
    if ((ehp = bm_match(webmenu.ncrp, buf, buf + mess_len) + 4) < (char *) 5)
        return buf;
    if ((cp = bm_casematch(webmenu.clp, buf, ehp)) == NULL)
        return buf;
    cont_len = atoi(cp + 16);
/*
 * We have made sure that we have the whole header, so this shouldn't fail ...
 */
    if ((fp = fopen(buf, "wb")) != NULL)
    {
        web_send(f, 25, "HTTP/1.1 100-Continue\r\n\r\n"); 
        n = (mess_len - (ehp - buf));
        if (mess_len > n)
        {
            fwrite(ehp, sizeof(char), n, fp);
            cont_len -= n; 
        }
        signal(SIGALRM, timeout);
        signal(SIGPIPE, timeout);
        alarm_gone = 0;
        alarm(10);
        while(cont_len > 0 && ((n = recvfrom(f, fbuf, sizeof(fbuf),0,0,0)) > 0
          || errno == EINTR))
        {
            if (alarm_gone)
            {
                web_send(f, 32, "HTTP/1.1 408 Request Timeout\r\n\r\n"); 
                fclose(fp);
                shutdown(f, SD_BOTH);
                closesocket(f);
                return NULL;
            }
            else
            if (n > 0)
            {
                fwrite(fbuf, sizeof(char), n, fp);
                cont_len -= n;
                if (cont_len > 0)
                    web_send(f, 25, "HTTP/1.1 100-Continue\r\n\r\n"); 
            }
            alarm(10);
        }
        alarm(0);
        fclose(fp);
        memcpy(fbuf, "HTTP/1.1 201 Created\r\n", 22); 
        sprintf(fbuf + 22, "Location: /%s\r\n\r\n", buf); 
        web_send(f, 37 + strlen(37 + fbuf), fbuf);
        shutdown(f, SD_BOTH);
        closesocket(f);
        return NULL;
    }
    return buf;
}
/*
 * Attempt to handle monitor requests
 */
static int mon_hwm;
static struct mon_target {
    int in_use;
    int pipe_out;
    int pipe_in;
    char * target;
    char * host;
    char * pid;
    char * port;
    char * sla;
    char * sample;
    char * dir;
    int out_fd;
    pid_t child_pid;
} mon_target[32];
/*
 * Check if URL is child of one of our monitor's
 */
static char * check_child_url(mtp, url)
struct mon_target * mtp;
char * url;
{
    if (debug_level)
        fprintf(stderr, "check_child_url(host: %s url: %s)\n", mtp->host, url);
    if (!strncmp(mtp->host, url, strlen(mtp->host)))
        return (url + strlen(mtp->host) + 1);
    return NULL;
}
/*
 * Kick off the process pipeline that will handle the collection and
 * rendition of statistics
 */
static int spawn_monitor(mtp)
struct mon_target * mtp;
{
int out_pipe[2];
int in_pipe[2];
char buf[512];
/*
 * Command to run monitors; does it work on Windows?
 * It did not, but the introduction of increp and increp.bat resolves the
 * issue.
 */
    sprintf(buf, "minitest %.64s %.6s EXEC \"logmon %.64s %.1s\" | increp %s %.6s %.64s",
             mtp->host, mtp->port, mtp->pid, mtp->sample,
             mtp->dir, mtp->sla, mtp->host);
#ifdef OLD
    sprintf(buf, "minitest %.64s %.6s EXEC 'logmon %.64s %.1s' | ( cd %s; fdreport -i %.6s -b -r -o %.64s_mon.html )",
             mtp->host, mtp->port, mtp->pid, mtp->sample,
             mtp->dir, mtp->sla, mtp->host);
#endif
    if (debug_level)
        fprintf(stderr, "Monitor Command: %s\n", buf);
/*
 * Cannot launch pipeline; give up
 */ 
    if (!(mtp->child_pid = launch_pipeline(in_pipe, out_pipe, buf)))
        return 0;
    mtp->pipe_out = in_pipe[1];
    mtp->pipe_in = out_pipe[0];
    if (debug_level)
        fprintf(stderr, "Monitor FD's: out: %d in: %d\n", mtp->pipe_out,
                 mtp->pipe_in);
    return 1;
}
/*
 * Serve up a tranche of monitor data.
 */
void serve_monitor(int i, char * ptr)
{
char fbuf[800];
char ret_buf[256];
FILE * fp;
int len;
int fd = dup(mon_target[i].pipe_in);

    if (debug_level)
        fprintf(stderr, "index: %d host: %s port: %s run: %s sample? %s dir: %d sla: %s in: %d out: %d\n", i, 
             mon_target[i].host, mon_target[i].port, mon_target[i].pid, mon_target[i].sample,
             mon_target[i].dir, mon_target[i].sla, fd, mon_target[i].out_fd);
    fp = fdopen(fd, "rb");
    setlinebuf(fp);
    while (fgets(&ret_buf[0], sizeof(ret_buf) - 1, fp) == &ret_buf[0])
    {
        len = strlen(ret_buf) - 1;
        ret_buf[len] = '\0';
        if (ret_buf[len - 1] == '\r')
        {
            len--;
            ret_buf[len] = '\0';
        }
        if (len > 5 && !memcmp(&ret_buf[len - 5], ".html", 5))
        {
            sprintf(fbuf, "%.512s/%.256s", mon_target[i].dir, ret_buf);
#ifdef EXPECT_HTML_HEAD_TO_BE_SET
/*
 * This was a piece of stupidity. If fdreport is run when html_head is set
 * by fdbase.sh, this is necessary, and works. But the output file isn't
 * valid HTML. Sp increp and increp.bat must unset html_head.
 */
            web_file_send_dynamic(mon_target[i].out_fd, fbuf);
#else
            web_file_send_static(mon_target[i].out_fd, fopen(fbuf, "rb"), fbuf);
#endif
            break;
        }
    }
    shutdown(mon_target[i].out_fd, SD_BOTH);
    closesocket(mon_target[i].out_fd);
    fclose(fp);
    return;
}
/*
 * Handle a request that needs to go to one of our pipelines
 * 
 * A monitor URL consists of:
 * - monitor
 * - variables
 *   - host
 *   - runid
 *   - directory (needed so that fdreport will run where there is a runout file)
 * 
 * The caller should have stripped leading /'s off the input URL.
 */
static char * async_handle(f, url)
int f;
char * url;
{
int i;
int j;
char fbuf[800];
int first_free;
int last_used;
int child_pid;
char * host;
char * pid;
char * x;
static char * port;
static char * sla;

    if (port == NULL && (port = getenv("E2_HOME_PORT")) == NULL)
        port = "5000";
    if (sla == NULL && (sla = getenv("E2_SLA_SIG_PCT")) == NULL)
        sla = "95";
/*
 * Clear away all the old monitor stuff
 */
    if (!strcmp(url, "zap"))
    {
        for (i = 0; i < mon_hwm; i++)
        {
            if (mon_target[i].in_use)
            {
                if (debug_level)
                    fprintf(stderr, "zapping PID %d\n",
                              mon_target[i].child_pid);
#ifdef UNIX
                kill(mon_target[i].child_pid, 15);
#endif
                close(mon_target[i].pipe_out);
                close(mon_target[i].pipe_in);
                free(mon_target[i].target);
                free(mon_target[i].host);
                mon_target[i].in_use = 0;
            }
        }
#ifdef MINGW32
        zapall(0);
#endif
        mon_hwm = 0;
        web_send(f, 38,
"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"); 
        shutdown(f, SD_BOTH);
        closesocket(f);
        return NULL;
    }
    if (strncmp(url, "monitor/", 8))
        return url;          /* Not one of ours */
    url += 8;
    fprintf(stderr, "Incoming URL: %s\n", url);
/*
 * Look for the url in the list.
 * If found, output a prod.
 * If not found, spawn a handler
 * Then spawn a child to wait for the results.
 */ 
    for (first_free = -1, last_used = -1, i = 0; i < mon_hwm; i++)
    {
        if (mon_target[i].in_use)
        {
            last_used = i;
/*
 * See if this is a monitor refresh
 */
            if (!strcmp(mon_target[i].target, url))
                break;
/*
 * See if this is a child of our monitor
 */
            if ((x = check_child_url(&mon_target[i], url)) != NULL)
            {
                if (!strncmp(x, "web_path_web", 12))
                    web_file_send_static(f, fopen(x, "rb"), x);
                else
                {
                    sprintf(fbuf, "%.512s/%.256s", mon_target[i].dir, x);
                    web_file_send_static(f, fopen(fbuf, "rb"), fbuf);
                }
                shutdown(f, SD_BOTH);
                closesocket(f);
                return NULL;
            }
        }
        else
        if (first_free == -1)
            first_free = i;
    } 
    if (i >= mon_hwm)
    {
/*
 * A monitor pipeline doesn't exist yet; create one
 */
        if (last_used == 31)
            return url;              /* Run out of slots */
        mon_hwm = last_used + 1;
        if (first_free == -1)
            first_free = mon_hwm;
        mon_target[first_free].target = strdup(url);
        mon_target[first_free].host = strdup(url);
        mon_target[first_free].host = strtok( mon_target[first_free].host,
                         "/?");
        if ((mon_target[first_free].pid = strtok( NULL, "/?")) == NULL
         || (x =  strtok( NULL, "&")) == NULL
         || strncmp(x, "dir=", 4))

        {
            free(mon_target[first_free].target);
            free(mon_target[first_free].host);
            return url;              /* No Run ID or Directory */ 
        }
        mon_target[first_free].dir = x + 4;
        mon_target[first_free].sample = "N";
        mon_target[first_free].port = port;
        mon_target[first_free].sla = sla;
        if (!spawn_monitor(&mon_target[first_free]))
        {
            free(mon_target[first_free].target);
            free(mon_target[first_free].host);
            return url;
        }
        mon_target[first_free].in_use = 1;
        if (mon_hwm <= first_free)
            mon_hwm = first_free + 1;
        i = first_free;
        if (debug_level)
            fprintf(stderr, "Created monitor pipeline for %s:%s\n",
                          mon_target[i].host, mon_target[i].pid);
    }
    else
    {
        if (debug_level)
            fprintf(stderr, "Prodding existing monitor pipeline for %s:%s\n",
                          mon_target[i].host, mon_target[i].pid);
        write(mon_target[i].pipe_out,"Go\n",3); /* Prod */
    }
    mon_target[i].out_fd = f;
#ifdef UNIX
/*
 * Tidy up any zombies
 */
    while (waitpid(0,0,WNOHANG) > 0);
#endif
/*
 * At this point, we have a pipeline identified; attempt to kick off a handler
 */
    do_asynch(serve_monitor, i, NULL);
#ifdef UNIX
    closesocket(f);
#endif
    return NULL;
}
/*
 * Naively handle a GET
 */
static char * attempt_get(f, buf, bound)
int f;
char * buf;
char * bound;
{
char * xp1;
FILE * fp;
int n;

    while (*buf =='/' || *buf =='\\')
        buf++;
    if ((n = sec_check(buf, 0)) == 403)
    {
        web_send(f, 45,
                  "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
        shutdown(f, SD_BOTH);
        closesocket(f);
        return NULL;
    }
    else
    if (n != 404 && (fp = fopen(buf, "rb")) != NULL)
    {
        web_file_send_static(f, fp, buf);
        return NULL;
    }
    else
    if (n == 404)
        return async_handle(f, buf);
    return buf;
}
/*
 * Naively handle a POST that has to be a single file upload.
 * -  The HTML form 'action' has to actually be the file name.
 * -  Anything other than the apparent contents of the file is simply ignored.
 */
static char * attempt_post(f, buf, bound, mess_len)
int f;
char * buf;
char * bound;
int mess_len;
{
char * ehp;
char * bp;
char * cp;
char * xp;
struct bm_table * boundp;
int cont_len;
int n;
FILE * fp;
char * fbuf;
/*
 * Check that the POST identifies the file name
 */
    while (*buf =='/' || *buf =='\\' || *buf == ' ')
    {
        buf++;
        mess_len--;
    }
    if (sec_check(buf, 1) == 403)
    {
        web_send(f, 45,
                  "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
        shutdown(f, SD_BOTH);
        closesocket(f);
        return NULL;
    }
/*
 * We have made sure that we have the whole header, so this shouldn't fail ...
 */
    if ((ehp = bm_match(webmenu.ncrp, buf, buf + mess_len) + 4) < (char *) 5)
        return buf;
/*
 * Search for the boundary; exit if not found
 */
    if ((bp = bm_match(webmenu.boundaryp, buf, ehp) + 9) < (char *) 10)
        return buf;
/*
 * Search for the length; exit if not found
 */
    if ((cp = bm_casematch(webmenu.clp, buf, ehp)) == NULL)
        return buf;
    cont_len = atoi(cp + 16);
    if (cont_len == 0)
    {
        web_send(f, (ehp - buf) + 4, buf); 
        shutdown(f, SD_BOTH);
        closesocket(f);
        return NULL;
    }
/*
 * Allocate space for the whole file
 */
    if ((fbuf = (char *) malloc(cont_len)) == NULL)
        return buf;
/*
 * Copy any bit of head into the start of the new buffer
 */
    if ((buf + mess_len) > (ehp + cont_len))
        mess_len -= (((buf + mess_len) - (ehp + cont_len)));
    memcpy(fbuf, ehp, (buf + mess_len) - ehp);
    xp = fbuf + ((buf + mess_len) - ehp);
    cont_len -= (xp - fbuf);
    if (cont_len > 0)
    {
/*
 * Read in the rest of the given length
 */
        signal(SIGALRM, timeout);
        signal(SIGPIPE, timeout);
        alarm_gone = 0;
        alarm(10);
        while((n = recvfrom(f, xp, cont_len,0,0,0)) > 0
           || errno == EINTR)
        {
            if (alarm_gone)
            {
                web_send(f, 32, "HTTP/1.1 408 Request Timeout\r\n\r\n"); 
                shutdown(f, SD_BOTH);
                closesocket(f);
                free(fbuf);
                return NULL;
            }
            else
            if (n > 0)
            {
                web_send(f, 25, "HTTP/1.1 100-Continue\r\n\r\n"); 
                cont_len -= n;
                xp += n;
            }
            alarm(10);
        }
        alarm(0);
    }
/*
 * Search for the start of the file
 */
    if ((cp = bm_match(webmenu.ncrp, fbuf, xp) + 4) < (char *)5)
    {
        free(fbuf);
        web_send(f, 26, "HTTP/1.1 404 Not Found\r\n\r\n"); 
        shutdown(f, SD_BOTH);
        closesocket(f);
        return NULL;
    }
/*
 * Search for the boundary
 */
    boundp = bm_compile_bin(bp, strchr(bp,'\r') - bp);
    if ((xp = bm_match(boundp, cp, xp)) == NULL)
    {
        free(fbuf);
        web_send(f, 26, "HTTP/1.1 404 Not Found\r\n\r\n"); 
        shutdown(f, SD_BOTH);
        closesocket(f);
        free(boundp);
        return NULL;
    }
    free(boundp);
/*
 * Write out the region between them.
 */
    if ((fp = fopen(buf, "wb")) != NULL)
    {
        while(*xp != '\r')
            xp--;
        fwrite(cp, sizeof(char), (xp - cp), fp);
        fclose(fp);
        free(fbuf);
        web_send(f, 35, "HTTP/1.1 302 Found\r\nLocation: /\r\n\r\n"); 
        shutdown(f, SD_BOTH);
        closesocket(f);
        return NULL;
    }
    web_send(f, 26, "HTTP/1.1 404 Not Found\r\n\r\n"); 
    free(fbuf);
    shutdown(f, SD_BOTH);
    closesocket(f);
    return NULL;
}
/*
 * Attempt to deal with requests that specify files.
 * -   Return start of URN, minus any http: stuff if can't handle
 * -   Return NULL if dealt with
 * Simple minded file type specification.
 */
char * attempt_request(f, buf, bound, mess_len)
int f;
char * buf;
char * bound;
int mess_len;
{
char * xp;
char * xp1;
FILE * fp;
int n;

    if ((xp = strchr(buf, ' ')) == NULL)
        return buf;       /* Should not happen */
    xp++;
    if (!strncmp(xp, "http://",7)
       && (xp = strchr(xp +7, '/')) == NULL)
        xp = buf + 5;
    else
        xp++;
    *bound = '\0';
    if (bound == xp)
        return xp;
    if (!strncmp(buf, "PUT ", 4))
        return attempt_put(f, xp, bound, mess_len - (xp - buf));
    else
    if (!strncmp(buf, "GET ", 4) && strcmp(xp, "/"))
        return attempt_get(f, xp, bound);
    else
    if (!strncmp(buf, "POST ", 5))
        return attempt_post(f, xp, bound, mess_len - (xp - buf));
    return xp;    
}
static int open_output()
{
int out_fd;

    if ((out_fd = fifo_connect(webmenu.out_fifo, webmenu.out_fifo)) == -1
      || ( out_fd != 1 && _dup2(out_fd, 1) != 0))
    {
        fputs("Failed to connect output FIFO", stderr);
#ifdef MINGW32
        WSACleanup();
#endif
        exit(1);
    }
    else
    if (out_fd != 1)
        close(out_fd);
    clearerr(stdout);
#ifdef MINGW32
    _setmode(1,  O_BINARY);
#endif
    return out_fd;
}
/*
 * Output something, re-opening if it fails. There needs to be a file open and
 * close, so this is encapsulated now.
 */
static void sure_put(obuf)
char * obuf;
{
    for (open_output(); fputs(obuf, stdout) < 0; open_output());
    fflush(stdout);
    close(1);
    return;
}
/*
 * Output a set of variable values extracted from the URL
 */
void output_vars(ofp, raw_string)
FILE * ofp;
char * raw_string;
{
char * bound = raw_string + strlen(raw_string);
char * obuf;
char * x;
char * x1;
char * y;
int l;
char * op;

    if (debug_level)
        fprintf(stderr, "Output vars input: %s\n", raw_string);
    for ( obuf = (char *) malloc(4 * (bound - raw_string) + 5),
          x = raw_string,
          op = obuf;
              x < bound;)
    {
        x1 = x;
        while (x < bound && *x != '=')
            x++;
        if (x >= bound)
            break;
        if (!strncmp(x1, "Submit", x - x1)
         || !strncmp(x1, "ln_cnt", x - x1))
        {
            for (x++; x < bound && *x != '&'; x++);
            x++;
            continue;
        }
        else
            x++;
        for (y = x; y < bound && *y != '&'; y++);
/*
 * x and y delimit a variable. It will be output:
 * - unless it is called ln_cnt or Submit
 * - Un-URL-escaped
 * - Delimited by '
 * - With any embedded ' marks stuffed
 * - followed by a ' '
 */
        l = url_unescape(x, y - x);
        *op++ = '\'';
        while ( l > 0)
        {
            l--;
            *op++ = *x;
            if (*x == '\'')
            {
               *op++ = '\\';
               *op++ = *x;
               *op++ = *x;
            }
            x++;
        }
        *op++ = '\'';
        *op++ = ' ';
        x = y+1;
    }
    if (op > obuf)
    {
        *op-- = '\0';
        *op = '\n';
    }
    else
    {
        *op++ ='\n';
        *op = '\0';
    }
    if (debug_level)
        fprintf(stderr, "Output vars output: %s\n", obuf);
    sure_put(obuf);
    free(obuf);
    return;
}
/*
 * Set up a connection to pick up requests through a browser
 */
static int output_setup(web_port, web_sockp, ret_buf)
int web_port;
struct sockaddr_in * web_sockp;
char * ret_buf;
{
int mess_len;
int n;
int web_out;
static int web_fd = -1;
char * bound_p; /* Prod bound */
char * ret_p; /* Prod bound */

    if (web_fd == -1)
        web_fd = listen_setup("127.0.0.1", web_port, web_sockp);
    if (web_fd == -1)
        return -1;
/*
 * We wait for a prod. This must be the root. We never actually act on this
 * ourselves; something else decides whether we are going to accept it or not.
 */
    do
    {
restart:
        mess_len = sizeof(*web_sockp);
        web_out = accept(web_fd, (struct sockaddr *)
                              web_sockp, &mess_len);
        if (web_out < 0)
            return -1;
#ifndef MINGW32
        else
        if (web_out < 3)
        {
            dup2(web_out, 9);
            close(web_out);
            web_out = 9;
        }
#endif
        signal(SIGALRM, timeout);
        signal(SIGPIPE, timeout);
        alarm_gone = 0;
        alarm(10);
        mess_len = 0;
/*
 * Make sure that we have at least read the header
 */
        while((n = recvfrom(web_out, ret_buf + mess_len, 16384 - mess_len,0,0,0)) > 0
          || errno == EINTR)
        {
            if (alarm_gone)
            {
                web_send(web_out, 32, "HTTP/1.1 408 Request Timeout\r\n\r\n"); 
                shutdown(web_out, SD_BOTH);
                closesocket(web_out);
                goto restart;
            }
            alarm(10);
            if (n > 0)
            {
                mess_len += n;
                if (bm_match(webmenu.ncrp, ret_buf, ret_buf + mess_len) != NULL)
                    break; 
            }
        }
        alarm(0);
        if (mess_len > 8 && !strncmp(ret_buf, "OPTIONS ", 8))
        {
            web_send(web_out, 134,
"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Methods: PUT, GET, POST\r\nAccess-Control-Allow-Origin: *\r\nContent-length: 0\r\nConnection: close\r\n\r\n"); 
            shutdown(web_out, SD_BOTH);
            closesocket(web_out);
            web_out = -1;
        }
        else
        {
            if (mess_len < 16
             || (strncmp(ret_buf,  "GET ", 4)
              && strncmp(ret_buf,  "PUT ", 4)
              && strncmp(ret_buf,  "POST ", 5))
             || ((bound_p = memchr( ret_buf, '\r', mess_len)) == NULL)
             || bound_p < (ret_buf + 5))
            {
                web_send(web_out, 45,
"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n"); 
                shutdown(web_out, SD_BOTH);
                closesocket(web_out);
                web_out = -1;
            }
            else
            if ((ret_p = attempt_request(web_out, ret_buf, bound_p - 9,
                     mess_len)) == NULL)
                web_out = -1;
            else
            if (webmenu.out_fifo == NULL)
            {                /* Running standalone */
                web_send(web_out, 45,
"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n"); 
                shutdown(web_out, SD_BOTH);
                closesocket(web_out);
                web_out = -1;
            }
        }
    }
    while (web_out == -1);
/*
 * Hand off the request to the output pipe
 */ 
    *(bound_p -9) = '\0';
    output_vars(stdout, ret_p); /* Does not use the Output File */
    if (debug_level > 1)
        (void) fprintf(stderr,"output_setup(%s)\n", ret_buf + 5);
    return web_out;
}
void sigterm()
{
    fputs("User Terminated\n", stderr);
#ifdef MINGW32
    WSACleanup();
#endif
    exit(0);
}
/***********************************************************************
 * Getopt support
 */
extern int optind;           /* Current Argument counter.      */
extern char *optarg;         /* Current Argument pointer.      */
extern int opterr;           /* getopt() err print flag.       */
/*
 * Initialisation to support calling routines in this file without calling
 * webmenu_main()
 */
int webini()
{
    webmenu.traverse_u = bm_compile("../");
    webmenu.traverse_w = bm_compile("..\\");
    webmenu.ncrp = bm_compile("\r\n\r\n");
    webmenu.clp = bm_casecompile("Content-length: ");
    webmenu.boundaryp = bm_casecompile("boundary=");
    return;
}
/*****************************************************************************
 * Main program starts here
 * VVVVVVVVVVVVVVVVVVVVVVVV
 */
int webmenu_main(argc, argv)
int argc;
char ** argv;
{
int web_port_id;
int in_fd;
struct sockaddr_in web_sock;
int out_port_id;
char * in_fifo = NULL;
int c;

    debug_level = 0;
    while ( ( c = getopt ( argc, argv, "d:i:o:w:" ) ) != EOF )
    {
        switch ( c )
        {
        case 'h' :
        case '?' :
            (void) fputs("minitest: E2 Systems Test Control Utility\n\
Options:\n\
 -h prints this message on stderr\n\
 -s says single step using supplied port\n\
 -o (plus name) create named pipe to hand off unrecognised URL's to\n\
 -i (plus name) create named pipe to receive response\n\
 -w (plus port) run as a mutant web server on this port\n\
Or Arguments. Either a minitest listen port\n\
 or a target host, port and minitest command.\n\
minitest commands are:\n\
SLEW - return the clock difference between this host and the target\n\
COPY - write a remote file, either from stdin, or from a further argument\n\
SCENE - execute a test scenario\n\
ABORT - abort a test scenario\n\
OVER - execute a command to over-write this program; used to update it\n",
        stderr);
            fflush(stderr);
#ifdef MINGW32
            WSACleanup();
#endif
            exit(0);
        case 'd' :
            debug_level = atoi(optarg);
            break;
        case 'o' :
            webmenu.out_fifo = strdup(optarg);
#ifndef MINGW32
            if (mkfifo(webmenu.out_fifo, 0600) < 0)
            {
                fputs("Failed to create output FIFO", stderr);
                exit(1);
            }
#endif
            break;
        case 'i' :
            in_fifo = strdup(optarg);
#ifndef MINGW32
            if (mkfifo(in_fifo, 0600) < 0)
            {
                fputs("Failed to create input FIFO", stderr);
                exit(1);
            }
#endif
            break;
        case 'w' :
            if ((web_port_id = atoi(optarg)) < 1) 
            {
                fputs("minitest: Invalid listen web port\n", stderr);
#ifdef MINGW32
                WSACleanup();
#endif
                exit(1);
            }
            break;
        } 
    }
#ifdef UNIX
    signal(SIGTERM,sigterm);
#endif
    signal(SIGINT, sigterm);
    webini();
    sock_ready("127.0.0.1", web_port_id, &web_sock);
    setlinebuf(stdin);
    setlinebuf(stdout);
/*
 * We have to connect the output socket before entering the loop,
 * but must connect the input socket after the loop has started.
 * since otherwise we hang. Furthermore, on Windows and Solaris,
 * we may have to re-open the named pipe once for each person
 * who connects.
 */
    in_fd = -1;
    while ((out_port_id = output_setup(web_port_id, &web_sock, &ret_buf[0])) > -1)
    {
        ret_buf[sizeof(ret_buf) - 1] ='\0';
/*
 * If we haven't yet connected to the named pipe for the returned value, do so
 * now. A problem might be that multiple users cannot be connected at the same
 * time; we may have hangs with the current code ...
 */
        if (webmenu.out_fifo != NULL && in_fd == -1)
        {
#ifndef LINUX
            if ((in_fd = fifo_listen(in_fifo)) == -1)
            {
                fputs("Failed to listen on input FIFO", stderr);
#ifndef MINGW32
                exit(1);
#endif
            }
#endif
reconnect_fifo:
            if ((in_fd = fifo_accept(in_fifo, in_fd)) == -1
               || (in_fd != 0 && _dup2(in_fd, 0) != 0))
            {
                fputs("Failed to accept input FIFO", stderr);
#ifdef MINGW32
                WSACleanup();
#endif
                exit(1);
            }
            else
            if (in_fd != 0)
            {
                close(in_fd);
            }
            clearerr(stdin);
#ifdef MINGW32
            _setmode(0,  O_BINARY);
#endif
        }
        if (in_fd != -1)
        {
            if ( fgets(&ret_buf[0], sizeof(ret_buf) - 1, stdin) == &ret_buf[0])
            {
                if (debug_level > 1)
                    (void) fprintf(stderr,"file name to send(%s)\n", ret_buf);
                ret_buf[strlen(ret_buf) - 1] ='\0';
                web_file_send_dynamic(out_port_id, ret_buf);
                unlink(ret_buf);
            }
            else
            {
                if (debug_level > 1)
                    (void) fprintf(stderr,"Input read failed error: %d\n", 
                               errno);
                goto reconnect_fifo;
            }
        }
        shutdown(out_port_id, SD_BOTH);
        closesocket(out_port_id);
    }
#ifdef MINGW32
    WSACleanup();
#endif
    exit(1);
}
