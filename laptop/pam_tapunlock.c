/*
 * pam_tapunlock: ask tapunlockd for a phone tap and prompt for the password
 * at the same time; whichever arrives first wins.
 *
 *   tap verified      -> PAM_SUCCESS (the prompt is cancelled)
 *   password typed    -> stored as PAM_AUTHTOK, PAM_IGNORE, so the next
 *                        module (pam_unix try_first_pass) checks it
 *   daemon absent/off -> PAM_IGNORE without prompting
 *
 * Cancelling a conversation mid-read skips the cleanup of the reader (sudo's
 * tgetpass leaves alarm(), its signal handlers and cbreak mode behind), so the
 * module snapshots those before prompting and restores them after a cancel.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <security/pam_ext.h>
#include <security/pam_modules.h>

#ifndef TAPUNLOCK_SOCKET
#define TAPUNLOCK_SOCKET "/run/tap-unlock/pam.sock"
#endif
#ifndef TAPUNLOCK_DAEMON_USER
#define TAPUNLOCK_DAEMON_USER "tapunlock"
#endif

static const int reader_signals[] = {
    SIGALRM, SIGINT, SIGHUP, SIGQUIT, SIGTERM, SIGTSTP, SIGTTIN, SIGTTOU,
};
#define NSIGNALS (sizeof reader_signals / sizeof reader_signals[0])

struct daemon_conn {
    int fd;
    char buf[64];
    size_t len;
};

struct prompt {
    pam_handle_t *pamh;
    char text[128];
    char *password;
    int retval;
    int done_fd;
};

static uid_t daemon_uid(void)
{
    char buf[1024];
    struct passwd pw, *res = NULL;
    if (getpwnam_r(TAPUNLOCK_DAEMON_USER, &pw, buf, sizeof buf, &res) != 0 || res == NULL)
        return (uid_t)-1;
    return pw.pw_uid;
}

static int connect_daemon(void)
{
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    struct ucred cred;
    socklen_t len = sizeof cred;
    struct timeval tv = {.tv_sec = 2};
    uid_t expected = daemon_uid();
    int fd;

    if (expected == (uid_t)-1)
        return -1;
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    memcpy(addr.sun_path, TAPUNLOCK_SOCKET, sizeof TAPUNLOCK_SOCKET);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0 ||
        getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0 ||
        cred.uid != expected ||
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int read_line(struct daemon_conn *c, char *line, size_t size)
{
    for (;;) {
        char *nl = memchr(c->buf, '\n', c->len);
        if (nl != NULL) {
            size_t n = (size_t)(nl - c->buf);
            if (n >= size)
                return 0;
            memcpy(line, c->buf, n);
            line[n] = '\0';
            c->len -= n + 1;
            memmove(c->buf, nl + 1, c->len);
            return 1;
        }
        if (c->len == sizeof c->buf)
            return 0;
        ssize_t r = recv(c->fd, c->buf + c->len, sizeof c->buf - c->len, 0);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            return 0;
        c->len += (size_t)r;
    }
}

static int json_safe(const char *s)
{
    for (; *s; s++)
        if (*s == '"' || *s == '\\' || (unsigned char)*s < 0x20)
            return 0;
    return 1;
}

static void notify_sudo(const char *user, int seconds)
{
    char buf[1024], body[256] = "?", uidarg[32], gidarg[32], bus[96], ms[16];
    struct passwd pw, *res = NULL;
    posix_spawnattr_t attr;
    pid_t pid;
    int fd;

    if (getpwnam_r(user, &pw, buf, sizeof buf, &res) != 0 || res == NULL)
        return;
    fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t n = read(fd, body, sizeof body - 1);
        close(fd);
        if (n > 0) {
            body[n] = '\0';
            for (ssize_t i = 0; i < n - 1; i++)
                if (body[i] == '\0')
                    body[i] = ' ';
        }
    }
    snprintf(uidarg, sizeof uidarg, "--reuid=%u", (unsigned)pw.pw_uid);
    snprintf(gidarg, sizeof gidarg, "--regid=%u", (unsigned)pw.pw_gid);
    snprintf(bus, sizeof bus, "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%u/bus",
             (unsigned)pw.pw_uid);
    snprintf(ms, sizeof ms, "%d", seconds * 1000);
    if (access(bus + strlen("DBUS_SESSION_BUS_ADDRESS=unix:path="), F_OK) != 0)
        return;

    char *argv[] = {
        "setsid", "-f", "setpriv", uidarg, gidarg, "--init-groups",
        "env", bus, "notify-send", "-a", "Tap Unlock", "-i", "dialog-password",
        "-t", ms, "sudo 等待贴手机确认", body, NULL,
    };
    char *envp[] = {"PATH=/usr/bin", NULL};
    if (posix_spawnattr_init(&attr) != 0)
        return;
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSID);
    if (posix_spawn(&pid, "/usr/bin/setsid", NULL, &attr, argv, envp) == 0)
        waitpid(pid, NULL, 0); /* setsid -f exits as soon as it has forked */
    posix_spawnattr_destroy(&attr);
}

static void *prompt_thread(void *arg)
{
    struct prompt *p = arg;
    char *resp = NULL;
    int rv = pam_prompt(p->pamh, PAM_PROMPT_ECHO_OFF, &resp, "%s", p->text);

    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    p->retval = rv;
    p->password = resp;
    while (write(p->done_fd, "x", 1) < 0 && errno == EINTR)
        ;
    return NULL;
}

static int wait_either(struct daemon_conn *c, int done_fd)
{
    struct pollfd fds[2] = {
        {.fd = done_fd, .events = POLLIN},
        {.fd = c->fd, .events = POLLIN},
    };
    char line[32];

    for (;;) {
        if (poll(fds, c->fd >= 0 ? 2 : 1, -1) < 0) {
            if (errno == EINTR)
                continue;
            return 0;
        }
        if (fds[0].revents)
            return 0;
        if (c->fd >= 0 && fds[1].revents) {
            if (read_line(c, line, sizeof line) && strcmp(line, "OK") == 0)
                return 1;
            /* TIMEOUT, refusal or daemon gone: keep waiting for the password. */
            close(c->fd);
            c->fd = -1;
        }
    }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const char *user = NULL, *service = NULL;
    struct daemon_conn c = {.fd = -1};
    struct prompt p = {.pamh = pamh, .retval = PAM_CONV_ERR};
    struct sigaction saved_sa[NSIGNALS];
    struct termios saved_tty;
    sigset_t block, oldmask;
    pthread_t thread;
    char line[32], request[256];
    int seconds, tty = -1, have_tty = 0, pipefd[2], tapped;
    void *thread_result = NULL;

    (void)flags;
    (void)argc;
    (void)argv;

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL ||
        pam_get_item(pamh, PAM_SERVICE, (const void **)&service) != PAM_SUCCESS || service == NULL ||
        !json_safe(user) || !json_safe(service))
        return PAM_IGNORE;

    c.fd = connect_daemon();
    if (c.fd < 0)
        return PAM_IGNORE;
    int n = snprintf(request, sizeof request, "{\"user\": \"%s\", \"service\": \"%s\"}", user, service);
    if (n < 0 || (size_t)n >= sizeof request || send(c.fd, request, (size_t)n, MSG_NOSIGNAL) != n ||
        !read_line(&c, line, sizeof line) || sscanf(line, "WAIT %d", &seconds) != 1 ||
        seconds <= 0 || pipe2(pipefd, O_CLOEXEC) != 0) {
        close(c.fd);
        return PAM_IGNORE;
    }

    if (strcmp(service, "sudo") == 0)
        notify_sudo(user, seconds);
    snprintf(p.text, sizeof p.text, "密码（或 %d 秒内贴手机）：", seconds);
    p.done_fd = pipefd[1];

    tty = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (tty >= 0)
        have_tty = tcgetattr(tty, &saved_tty) == 0;
    sigemptyset(&block);
    for (size_t i = 0; i < NSIGNALS; i++) {
        sigaction(reader_signals[i], NULL, &saved_sa[i]);
        sigaddset(&block, reader_signals[i]);
    }

    if (pthread_create(&thread, NULL, prompt_thread, &p) != 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        if (tty >= 0)
            close(tty);
        close(c.fd);
        return PAM_IGNORE;
    }
    /* Route Ctrl+C & co. to the prompting thread so the reader sees them. */
    pthread_sigmask(SIG_BLOCK, &block, &oldmask);
    tapped = wait_either(&c, pipefd[0]);
    pthread_sigmask(SIG_SETMASK, &oldmask, NULL);

    if (tapped)
        pthread_cancel(thread);
    pthread_join(thread, &thread_result);
    if (thread_result == PTHREAD_CANCELED) {
        alarm(0);
        for (size_t i = 0; i < NSIGNALS; i++)
            sigaction(reader_signals[i], &saved_sa[i], NULL);
        if (have_tty) {
            tcsetattr(tty, TCSAFLUSH, &saved_tty);
            while (write(tty, "\n", 1) < 0 && errno == EINTR)
                ;
        }
    }
    close(pipefd[0]);
    close(pipefd[1]);
    if (tty >= 0)
        close(tty);
    if (c.fd >= 0)
        close(c.fd);

    if (tapped) {
        if (p.password != NULL) {
            explicit_bzero(p.password, strlen(p.password));
            free(p.password);
        }
        return PAM_SUCCESS;
    }
    if (p.retval == PAM_SUCCESS && p.password != NULL)
        pam_set_item(pamh, PAM_AUTHTOK, p.password);
    if (p.password != NULL) {
        explicit_bzero(p.password, strlen(p.password));
        free(p.password);
    }
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}
