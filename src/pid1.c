/* Starts process inside NEWPID subsystem.
 *
 * author: Charles-Henri.de.Boysson@morganstanley.com
 */

#define _GNU_SOURCE

#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int optind;

#ifndef CLONE_NEWPID
#  define CLONE_NEWPID            0x20000000      /* New pid namespace */
#endif

#define ERR_EXIT(...)                                              \
    _err_exit(__FILE__, __LINE__, errno, __VA_ARGS__)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#define UNSHARE_PROPAGATION_DEFAULT (MS_REC | MS_SHARED)
#define CLOSE_FROM_DEFAULT (-1)

enum {
    OPT_PROPAGATION
};

struct unshare_param {
    int unshare_flags;
    unsigned long propagation;
    long closefrom_fd;
};

static inline
void _err_exit(const char *file, const int line,
               const int err, const char *msg, ...)
{
    const char *errmsg = strerror(err);
    va_list ap;

    fprintf(stderr, "%s:%d: ", file, line);
    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    va_end(ap);
    fprintf(stderr, ": %s (errno:%d)\n", errmsg, err);

    /* Die in a fire */
    raise(SIGABRT);
}

/* Disable core dumps.
 */
static inline
void disable_core(void)
{
    const struct rlimit rlim = { .rlim_cur = 0, .rlim_max = 0 };
    int rc;

    rc = setrlimit(RLIMIT_CORE, &rlim);
    if (rc != 0)
        ERR_EXIT("setrlimit");
}

/* Block all POSIX signals.
 */
static inline
void block_all_signals(void)
{
    sigset_t set;
    int rc;

    rc = sigfillset(&set);
    if (rc != 0)
        ERR_EXIT("sigfillset");

    rc = sigprocmask(SIG_SETMASK, &set, NULL);
    if (rc != 0)
        ERR_EXIT("sigprocmask");
}

/* Unblock all POSIX signals.
 */
static inline
void unblock_all_signals(void)
{
    sigset_t set;
    int rc;

    rc = sigemptyset(&set);
    if (rc != 0)
        ERR_EXIT("sigemptyset");

    rc = sigprocmask(SIG_SETMASK, &set, NULL);
    if (rc != 0)
        ERR_EXIT("sigprocmask");
}

/* Parse a fd number str */
static inline
long parse_fd(const char *str)
{
    long val;
    char *endptr;

    errno = 0;    /* To distinguish success/failure after call */
    val = strtol(str, &endptr, 10);

    if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) ||
        (errno != 0 && val == 0))
    {
        ERR_EXIT("strtol");
    }
    if (*endptr != '\0')
    {
        fprintf(stderr, "Invalid filedescriptor number: '%s'\n", str);
        exit(EXIT_FAILURE);
    }

    return val;
}

/* Close all FDs from and including `low_fd`.
 * Any errors encountered  while closing file descriptors are ignored.
 *
 * This will try to be clever and use /proc/self/fd and fallback to calling
 * close on all possible FDs otherwise.
 */
static inline
void closefrom(int low_fd)
{
    DIR *fds_dir;

    fds_dir = opendir("/proc/self/fd");
    if (fds_dir == NULL)
    {
        /* The slow way */
        long max_fd;

        max_fd = sysconf(_SC_OPEN_MAX);
        if (max_fd < 0)
            ERR_EXIT("sysconf");

        for (long i = low_fd; i < max_fd; i++)
            close(i);
    }
    else
    {
        struct dirent *cur;
        int fds_fd = dirfd(fds_dir);

        errno = 0;    /* To distinguish success/failure after call */
        cur = readdir(fds_dir);
        for (; cur != NULL; cur = readdir(fds_dir))
        {
            int cur_fd;

            if (errno != 0)
                ERR_EXIT("readdir");
            if (!(cur->d_type & DT_LNK))
                continue;

            cur_fd = parse_fd(cur->d_name);
            if (cur_fd < low_fd)
                continue;
            if (cur_fd == fds_fd)
                /* Do not close our current dir handle */
                continue;
            close(cur_fd);

            errno = 0;    /* To distinguish success/failure after call */
        }
        closedir(fds_dir);
    }
}

/* Setup a signalfd socket that will receive all signal events.
 */
static inline
int init_signalfd(void)
{
    sigset_t set;
    int fd;
    int rc;

    rc = sigfillset(&set);
    if (rc != 0)
        ERR_EXIT("sigfillset");

    fd = signalfd(-1, &set, SFD_CLOEXEC);
    if (fd < 0)
        ERR_EXIT("signalfd");

    return fd;
}

/* Wait for child process to exit and mirror its exit conditions.
 *
 * Will exit with the same values that the child process exited with and will
 * raise the same signal that killed the child process (if any).
 */
static
void wait_for_exit(int sfd, pid_t pid1)
{
    int status = 0;
    int signal = 0;
    int ret = 0;
    int rc;

    for (;;)
    {
        struct signalfd_siginfo sig;
        ssize_t s;

        s = read(sfd, &sig, sizeof(struct signalfd_siginfo));
        if (s != sizeof(struct signalfd_siginfo))
            ERR_EXIT("signalfd read");

        fprintf(stderr, "Received signal %d from %ld\n",
                sig.ssi_signo, (long) sig.ssi_pid);

        if ((sig.ssi_signo == SIGCHLD) &&
            (sig.ssi_pid == pid1))
        {
            status = sig.ssi_status;

            /* Try to reap the child */
            if (waitpid(pid1, NULL, WNOHANG) != pid1)
            {
                /* This was a non-fatal signal (CONT, STOP, ...) */
                continue;
            }

            /* child exited */
            break;
        }
        else
        {
            /* Forward all signals to child */
            kill(pid1, sig.ssi_signo);
        }
    }
    rc = close(sfd);
    if (rc != 0)
        ERR_EXIT("signalfd close");

    unblock_all_signals();

    if (WIFEXITED(status))
    {
        ret = WEXITSTATUS(status);
        fprintf(stderr, "child has exited: %d\n", ret);
        exit(ret);
    }
    else if (WIFSIGNALED(status))
    {
        signal = WTERMSIG(status);
        fprintf(stderr, "child terminated with signal: %d\n", signal);
        /* Make sure we do not core dump because of child signal */
        disable_core();
        raise(signal);
    }
    else
    {
        fprintf(stderr, "Unexpected child status: %d\n", status);
        exit(EXIT_FAILURE);
    }
}

/* Setup mount a private / mount point (required by redhat 7)
 */
static
void set_propagation(unsigned long flags)
{
    if (flags == 0)
        return;

    if (mount("none", "/", NULL, flags, NULL) != 0)
        ERR_EXIT("cannot change root filesystem propagation");
}

/* Setup a private /proc mount point in the new mount namespace.
 */
static inline
void mount_proc(void)
{
    int rc;

    rc = mount("none", "/proc", NULL,
               MS_REC|MS_PRIVATE, NULL);
    if (rc != 0)
        ERR_EXIT("mount /proc private");

    rc = mount("none", "/proc", "proc",
               MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL);
    if (rc != 0)
        ERR_EXIT("mount none /proc proc");

    return;
}

/* Setup a new environment of the child process and exec it.
 */
static
void exec_pid1(char *argv[], struct unshare_param exec_param)
{
    int rc;

    /* Instruct the kernel to send a SIGKILL to this process' pid when its
     * parent dies.
     */
    rc = prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
    if (rc != 0)
        ERR_EXIT("prctl");

    if (exec_param.unshare_flags & CLONE_NEWNS) {
        /* Make sure the new PID/IPC namespace has its own private proc.
         */
        set_propagation(exec_param.propagation);
        mount_proc();
    }

    /* Optionally clean up all FDs
     */
    if (exec_param.closefrom_fd >= 0)
        closefrom(exec_param.closefrom_fd);

    /* unblock all signals.
     */
    unblock_all_signals();

    rc = execvp(*argv, argv);
    if (rc != 0)
        ERR_EXIT("execvp");

    /* never reached */
    return;
}

/* Start a child process into its own PID, MOUNT and IPC namespace.
 *
 *  If the parent dies, the child process will receive SIGKILL (pctrl) instead
 *  of being re-parented to pid 1.
 */
static
pid_t start_link(char *argv[], struct unshare_param exec_param)
{
    pid_t pid1;
    int rc;

    rc = unshare(exec_param.unshare_flags);
    if (rc != 0)
        ERR_EXIT("unshare");

    pid1 = fork();
    if (pid1 < 0)
        ERR_EXIT("fork");

    else if (pid1 ==  0)
    {
        /* child. exec into the pid1 process */
        exec_pid1(argv, exec_param);
        /* Never reached */
        exit(EXIT_FAILURE);
    }
    /* parent. fall through */

    fprintf(stderr, "started child pid: %ld\n", (long) pid1);

    return pid1;
}

static
void usage(int exit_status)
{
    FILE *out = NULL;

    if (exit_status == EXIT_SUCCESS)
        out = stdout;
    else
        out = stderr;

    fprintf(out,
       "usage: pid1 [OPTIONS] <PROGRAM> [<ARG>, ...]\n"
       "\n"
       "  -m, --mount           unshare mounts namespace\n"
       "  -i, --ipc             unshare IPC namespace\n"
       "  -p, --pid             unshare PID namespace\n"
       "  ---propagation slave|shared|private|unchanged\n"
       "                        propagation mode, default shared\n"
       "  -c, --closefrom FD    Close all filedescriptors from and\n"
       "                        including FD\n"
    );
    fflush(out);

    exit(exit_status);
}

static
unsigned long parse_propagation(const char *str)
{
    size_t i;
    static const struct prop_opts {
        const char *name;
        unsigned long flag;
    } opts[] = {
        { "slave",  MS_REC | MS_SLAVE },
        { "private",    MS_REC | MS_PRIVATE },
        { "shared",     MS_REC | MS_SHARED },
        { "unchanged",        0 }
    };

    for (i = 0; i < ARRAY_SIZE(opts); i++) {
        if (strcmp(opts[i].name, str) == 0)
        return opts[i].flag;
    }
    fprintf(stderr, "unsupported propagation mode: %s", str);
    usage(EXIT_FAILURE);
    /* should not reach here */
    return 0;
}


static
struct unshare_param parse_opts(int argc, char *argv[])
{
    static const struct option longopts[] = {
        { "help", no_argument, NULL, 'h' },
        { "ipc",   no_argument, NULL, 'i' },
        { "mount",   no_argument, NULL, 'm' },
        { "pid",   no_argument, NULL, 'p' },
        { "propagation", required_argument, NULL, OPT_PROPAGATION },
        { "closefrom", required_argument, NULL, 'c' },
        { NULL, 0, NULL, '\0' }
    };
    int c;
    struct unshare_param param = {
        0,
        UNSHARE_PROPAGATION_DEFAULT,
        CLOSE_FROM_DEFAULT
    };

    while ((c = getopt_long(argc, argv, "+himpc:", longopts, NULL)) != -1) {
        switch (c) {
            case 'i':
                param.unshare_flags |= CLONE_NEWIPC;
                break;
            case 'p':
                param.unshare_flags |= CLONE_NEWPID;
                break;
            case 'm':
                param.unshare_flags |= CLONE_NEWNS;
                break;
            case 'c':
                param.closefrom_fd = parse_fd(optarg);
                break;
            case OPT_PROPAGATION:
                param.propagation = parse_propagation(optarg);
                break;
            case 'h':
                usage(EXIT_SUCCESS);
                break;
            default:
                usage(EXIT_FAILURE);
        }
    }
    return param;
}

int main(int argc, char *argv[])
{
    int child_cmd_index = 0;
    int sfd;
    pid_t pid1;

    struct unshare_param exec_param = parse_opts(argc, argv);
    child_cmd_index = optind;

    /* Must have program name in parameter */
    if (child_cmd_index == argc) {
        usage(EXIT_FAILURE);
    }

    fprintf(stderr, "started parent pid: %ld\n", (long) getpid());

    /* Setup signalfd */
    block_all_signals();
    sfd = init_signalfd();

    pid1 = start_link(&argv[child_cmd_index], exec_param);

    wait_for_exit(sfd, pid1);

    /* Never reached */
    exit(EXIT_FAILURE);
}

