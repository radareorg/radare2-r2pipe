#ifndef V_R2PIPE_STREAM_POSIX_H
#define V_R2PIPE_STREAM_POSIX_H

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <crt_externs.h>
#else
extern char **environ;
#endif

static int v_r2p_spawn(const char *exe, char *const argv[], char *const env[],
                       const char *cwd, bool inherit_stderr, int *child) {
	int fds[2];
#ifdef SOCK_CLOEXEC
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) == -1) {
#else
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == -1) {
#endif
		return -errno;
	}
	int err = 0;
	for (int i = 0; i < 2; i++) {
		if (fds[i] <= STDERR_FILENO) {
			int fd = fcntl(fds[i], F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
			if (fd == -1) {
				err = errno;
				goto fail;
			}
			close(fds[i]);
			fds[i] = fd;
		}
#ifndef SOCK_CLOEXEC
		if (fcntl(fds[i], F_SETFD, FD_CLOEXEC) == -1) {
			err = errno;
			goto fail;
		}
#endif
	}
	if (fcntl(fds[0], F_SETFL, O_NONBLOCK) == -1) {
		err = errno;
		goto fail;
	}
#ifdef SO_NOSIGPIPE
	int on = 1;
	if (setsockopt(fds[0], SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on)) == -1) {
		err = errno;
		goto fail;
	}
#endif

	posix_spawn_file_actions_t actions;
	if ((err = posix_spawn_file_actions_init(&actions))) {
		goto fail;
	}
	if (!(err = posix_spawn_file_actions_addclose(&actions, fds[0])) &&
	    !(err = posix_spawn_file_actions_adddup2(&actions, fds[1], STDIN_FILENO)) &&
	    !(err = posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO)) &&
	    !(err = posix_spawn_file_actions_addclose(&actions, fds[1])) &&
	    (inherit_stderr || !(err = posix_spawn_file_actions_addopen(&actions,
			STDERR_FILENO, "/dev/null", O_WRONLY, 0)))) {
		if (*cwd) {
			err = posix_spawn_file_actions_addchdir_np(&actions, cwd);
		}
		if (!err) {
#if defined(__APPLE__)
			char **parent_env = *_NSGetEnviron();
#else
			char **parent_env = environ;
#endif
			pid_t pid;
			err = posix_spawn(&pid, exe, &actions, NULL, argv, env ? env : parent_env);
			if (!err) {
				*child = pid;
			}
		}
	}
	posix_spawn_file_actions_destroy(&actions);
	if (!err) {
		close(fds[1]);
		return fds[0];
	}
fail:
	close(fds[0]);
	close(fds[1]);
	return -err;
}

static int v_r2p_dup(int fd, bool writable) {
	struct stat st;
	if (fstat(fd, &st) == -1) {
		return -errno;
	}
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1) {
		return -errno;
	}
	if (!S_ISFIFO(st.st_mode) || (flags & O_ACCMODE) == (writable ? O_RDONLY : O_WRONLY)) {
		return -EBADF;
	}
	int duplicate = fcntl(fd, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
	return duplicate < 0 ? -errno : duplicate;
}

static int v_r2p_pipe_buf(int fd) {
	long size = fpathconf(fd, _PC_PIPE_BUF);
	return size <= 0 ? 512 : size < 8192 ? (int)size : 8191;
}

static int v_r2p_poll(int fd, bool write_ready, int timeout_ms) {
	struct pollfd pfd = {fd, write_ready ? POLLOUT : POLLIN, 0};
	int ret = poll(&pfd, 1, timeout_ms);
	if (ret > 0 && write_ready && (pfd.revents & (POLLERR | POLLHUP))) {
		return -EPIPE;
	}
	return ret < 0 ? -errno : ret;
}

static int v_r2p_read(int fd, unsigned char *data, int size) {
	ssize_t count = read(fd, data, (size_t)size);
	return count < 0 ? -errno : (int)count;
}

// Ignore SIGPIPE for this write while preserving the embedding application's
// signal disposition and any SIGPIPE that was already pending on this thread.
static int v_r2p_write(int fd, const unsigned char *data, int size, bool socket_fd) {
	if (socket_fd) {
#ifdef MSG_NOSIGNAL
		ssize_t count = send(fd, data, (size_t)size, MSG_NOSIGNAL);
		return count < 0 ? -errno : (int)count;
#elif defined(SO_NOSIGPIPE)
		ssize_t count = write(fd, data, (size_t)size);
		return count < 0 ? -errno : (int)count;
#endif
	}
#ifdef F_SETNOSIGPIPE
	// Darwin can deliver SIGPIPE to another thread in the process. Suppress
	// it on this descriptor for the write, then restore the previous flag.
	int previous = fcntl(fd, F_GETNOSIGPIPE);
	if (previous >= 0 && (previous || !fcntl(fd, F_SETNOSIGPIPE, 1))) {
		ssize_t count = write(fd, data, (size_t)size);
		int err = count < 0 ? errno : 0;
		if (!previous) {
			fcntl(fd, F_SETNOSIGPIPE, 0);
		}
		return err ? -err : (int)count;
	}
#endif
	sigset_t mask, old, pending;
	sigemptyset(&mask);
	sigaddset(&mask, SIGPIPE);
	int err = pthread_sigmask(SIG_BLOCK, &mask, &old);
	if (err) {
		return -err;
	}
	bool had_pending = sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE);
	ssize_t count = write(fd, data, (size_t)size);
	err = count < 0 ? errno : 0;
	if (err == EPIPE && !had_pending && sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE)) {
		int signo;
		sigwait(&mask, &signo);
	}
	pthread_sigmask(SIG_SETMASK, &old, NULL);
	return err ? -err : (int)count;
}

static bool v_r2p_reap(int pid, bool block) {
	pid_t result;
	do {
		result = waitpid(pid, NULL, block ? 0 : WNOHANG);
	} while (result == -1 && errno == EINTR);
	return result != 0;
}

#endif
