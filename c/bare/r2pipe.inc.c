/* r2pipe.inc.c - zero-dependency single-file r2pipe for C (unix+windows)
 *
 * source https://github.com/radareorg/radare2-r2pipe under `/c/bare/r2pipe.inc.c`
 *
 * Include directly into one of your .c files:
 *
 *     #define R2P_ENABLE_DLOPEN 1
 *     #define R2P_ENABLE_SPAWN  1
 *     #include "r2pipe.inc.c"
 *
 *     int main(void) {
 *         R2Pipe *r = r2p_open(R2P_SPAWN, "/bin/ls", "-aaa");
 *         char *out = r2p_cmd(r, "pd 5");
 *         puts(out);
 *         free(out);
 *         r2p_close(r);
 *     }
 *
 * Use only libc and platform APIs. No json, no sockets, no deps.
 */

#ifndef R2PIPE_INC_C
#define R2PIPE_INC_C

/* Opt-in/out: default both methods on. Set to 0 to compile out. */
#ifndef R2P_ENABLE_DLOPEN
#define R2P_ENABLE_DLOPEN 1
#endif
#ifndef R2P_ENABLE_SPAWN
#define R2P_ENABLE_SPAWN  1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#if defined(_WIN32) || defined(_WIN64)
#  define R2P_WINDOWS 1
#  include <windows.h>
#else
#  define R2P_UNIX 1
#  if R2P_ENABLE_SPAWN
#    include <unistd.h>
#    include <fcntl.h>
#    include <sys/types.h>
#    include <sys/wait.h>
#  endif
#  if R2P_ENABLE_DLOPEN
#    include <dlfcn.h>
#  endif
#endif

typedef enum {
	R2P_DLOPEN = 0,
	R2P_SPAWN  = 1
} R2PipeMode;

typedef struct R2Pipe R2Pipe;

struct R2Pipe {
	int mode;
#if R2P_ENABLE_DLOPEN
	void  *lib;
	void  *core;
	void *(*fn_new)(void);
	void  (*fn_free)(void *);
	char *(*fn_cmd_str)(void *, const char *);
#endif
#if R2P_ENABLE_SPAWN
#  if R2P_WINDOWS
	HANDLE child;
	HANDLE in_rd;   /* read side: child's stdout */
	HANDLE out_wr;  /* write side: child's stdin */
#  else
	int pid;
	int in_fd;
	int out_fd;
#  endif
#endif
};

/* ---- public api ---------------------------------------------------- */
static R2Pipe *r2p_open(int mode, const char *file, const char *flags);
static char   *r2p_cmd (R2Pipe *r, const char *cmd);
static void    r2p_close(R2Pipe *r);

/* ---- helpers ------------------------------------------------------- */
static char **r2p__split(const char *s, int *n_out) {
	*n_out = 0;
	if (!s || !*s) {
		return NULL;
	}
	int cap = 8;
	int n = 0;
	char **argv = (char **)calloc((size_t)cap, sizeof(char *));
	if (!argv) {
		return NULL;
	}
	char *copy = strdup(s);
	if (!copy) {
		free(argv);
		return NULL;
	}
	char *p = copy;
	while (*p) {
		while (*p == ' ' || *p == '\t') {
			p++;
		}
		if (!*p) {
			break;
		}
		char *start = p;
		while (*p && *p != ' ' && *p != '\t') {
			p++;
		}
		size_t len = (size_t)(p - start);
		if (n + 2 > cap) {
			cap *= 2;
			char **nb = (char **)realloc(argv, (size_t)cap * sizeof(char *));
			if (!nb) {
				break;
			}
			argv = nb;
		}
		argv[n] = (char *)malloc(len + 1);
		if (!argv[n]) {
			break;
		}
		memcpy(argv[n], start, len);
		argv[n][len] = '\0';
		n++;
	}
	free(copy);
	if (argv) {
		argv[n] = NULL;
	}
	*n_out = n;
	return argv;
}

#if R2P_ENABLE_DLOPEN
static void r2p__free_split(char **argv, int n) {
	if (!argv) {
		return;
	}
	for (int i = 0; i < n; i++) {
		free(argv[i]);
	}
	free(argv);
}
#endif

/* ---- dlopen backend ----------------------------------------------- */
#if R2P_ENABLE_DLOPEN

static void *r2p__lib_open(void) {
	static const char *names[] = {
#  if R2P_WINDOWS
		"libr_core.dll",
		"r_core.dll",
#  elif defined(__APPLE__)
		"libr_core.dylib",
		"/opt/homebrew/lib/libr_core.dylib",
		"/usr/local/lib/libr_core.dylib",
#  else
		"libr_core.so",
		"libr_core.so.0",
#  endif
		NULL
	};
	for (int i = 0; names[i]; i++) {
#  if R2P_WINDOWS
		HMODULE h = LoadLibraryA(names[i]);
		if (h) {
			return (void *)h;
		}
#  else
		void *h = dlopen(names[i], RTLD_NOW | RTLD_GLOBAL);
		if (h) {
			return h;
		}
#  endif
	}
	return NULL;
}

static void *r2p__sym(void *lib, const char *name) {
#  if R2P_WINDOWS
	return (void *)GetProcAddress((HMODULE)lib, name);
#  else
	return dlsym(lib, name);
#  endif
}

static void r2p__lib_close(void *lib) {
	if (!lib) {
		return;
	}
#  if R2P_WINDOWS
	FreeLibrary((HMODULE)lib);
#  else
	dlclose(lib);
#  endif
}

static R2Pipe *r2p__open_dlopen(const char *file, const char *flags) {
	R2Pipe *r = (R2Pipe *)calloc(1, sizeof(R2Pipe));
	if (!r) {
		return NULL;
	}
	r->mode = R2P_DLOPEN;
	r->lib = r2p__lib_open();
	if (!r->lib) {
		fprintf(stderr, "r2pipe: cannot load libr_core\n");
		free(r);
		return NULL;
	}
	/* prefer r_core_new0 (fully-initializing ctor), fall back to r_core_new */
	void *sn = r2p__sym(r->lib, "r_core_new0");
	if (!sn) {
		sn = r2p__sym(r->lib, "r_core_new");
	}
	void *sf = r2p__sym(r->lib, "r_core_free");
	void *sc = r2p__sym(r->lib, "r_core_cmd_str");
	if (!sn || !sf || !sc) {
		fprintf(stderr, "r2pipe: missing r_core_* symbols\n");
		r2p__lib_close(r->lib);
		free(r);
		return NULL;
	}
	r->fn_new     = (void *(*)(void))sn;
	r->fn_free    = (void  (*)(void *))sf;
	r->fn_cmd_str = (char *(*)(void *, const char *))sc;
	r->core = r->fn_new();
	if (!r->core) {
		r2p__lib_close(r->lib);
		free(r);
		return NULL;
	}
	/* apply each flag as an r2 command (in r2, "-d", "-aaa", ... map to
	 * the same behavior as the commandline flags of the same name). */
	int nf = 0;
	char **fa = r2p__split(flags, &nf);
	for (int i = 0; i < nf; i++) {
		char *o = r->fn_cmd_str(r->core, fa[i]);
		if (o) {
			free(o);
		}
	}
	r2p__free_split(fa, nf);
	/* open the binary last */
	if (file && *file) {
		size_t len = strlen(file) + 4;
		char *oc = (char *)malloc(len);
		if (oc) {
			snprintf(oc, len, "o %s", file);
			char *o = r->fn_cmd_str(r->core, oc);
			if (o) {
				free(o);
			}
			free(oc);
		}
	}
	return r;
}

#endif /* R2P_ENABLE_DLOPEN */

/* ---- spawn backend ------------------------------------------------- */
#if R2P_ENABLE_SPAWN

#  if R2P_WINDOWS

static R2Pipe *r2p__open_spawn(const char *file, const char *flags) {
	R2Pipe *r = (R2Pipe *)calloc(1, sizeof(R2Pipe));
	if (!r) {
		return NULL;
	}
	r->mode = R2P_SPAWN;
	/* build cmdline: radare2 <flags> -q0 "<file>" */
	size_t need = strlen("radare2.exe -q0 ") + 8;
	if (flags) {
		need += strlen(flags) + 2;
	}
	if (file) {
		need += strlen(file) + 4;
	}
	char *cmdline = (char *)malloc(need);
	if (!cmdline) {
		free(r);
		return NULL;
	}
	if (flags && *flags) {
		if (file && *file) {
			snprintf(cmdline, need, "radare2.exe %s -q0 \"%s\"", flags, file);
		} else {
			snprintf(cmdline, need, "radare2.exe %s -q0", flags);
		}
	} else {
		if (file && *file) {
			snprintf(cmdline, need, "radare2.exe -q0 \"%s\"", file);
		} else {
			snprintf(cmdline, need, "radare2.exe -q0");
		}
	}
	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;
	HANDLE cin_rd = NULL, cin_wr = NULL, cout_rd = NULL, cout_wr = NULL;
	if (!CreatePipe(&cout_rd, &cout_wr, &sa, 0)) {
		free(cmdline);
		free(r);
		return NULL;
	}
	if (!CreatePipe(&cin_rd, &cin_wr, &sa, 0)) {
		CloseHandle(cout_rd);
		CloseHandle(cout_wr);
		free(cmdline);
		free(r);
		return NULL;
	}
	SetHandleInformation(cout_rd, HANDLE_FLAG_INHERIT, 0);
	SetHandleInformation(cin_wr, HANDLE_FLAG_INHERIT, 0);
	STARTUPINFOA si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.hStdInput = cin_rd;
	si.hStdOutput = cout_wr;
	si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
	si.dwFlags = STARTF_USESTDHANDLES;
	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));
	BOOL ok = CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
	free(cmdline);
	CloseHandle(cin_rd);
	CloseHandle(cout_wr);
	if (!ok) {
		fprintf(stderr, "r2pipe: CreateProcess failed (radare2 in PATH?)\n");
		CloseHandle(cout_rd);
		CloseHandle(cin_wr);
		free(r);
		return NULL;
	}
	CloseHandle(pi.hThread);
	r->child  = pi.hProcess;
	r->in_rd  = cout_rd;
	r->out_wr = cin_wr;
	/* consume banner up to NUL (on windows r2 emits it twice in some builds) */
	char c;
	DWORD got;
	while (ReadFile(r->in_rd, &c, 1, &got, NULL) && got == 1 && c != '\0') {}
	return r;
}

static char *r2p__cmd_spawn(R2Pipe *r, const char *cmd) {
	size_t cl = strlen(cmd);
	char *line = (char *)malloc(cl + 2);
	if (!line) {
		return NULL;
	}
	memcpy(line, cmd, cl);
	line[cl] = '\n';
	line[cl + 1] = '\0';
	DWORD wrote;
	WriteFile(r->out_wr, line, (DWORD)(cl + 1), &wrote, NULL);
	free(line);
	size_t cap = 4096, len = 0;
	char *buf = (char *)malloc(cap);
	if (!buf) {
		return NULL;
	}
	char c;
	DWORD got;
	while (ReadFile(r->in_rd, &c, 1, &got, NULL) && got == 1) {
		if (c == '\0') {
			break;
		}
		if (len + 2 > cap) {
			cap *= 2;
			char *nb = (char *)realloc(buf, cap);
			if (!nb) {
				break;
			}
			buf = nb;
		}
		buf[len++] = c;
	}
	buf[len] = '\0';
	return buf;
}

static void r2p__close_spawn(R2Pipe *r) {
	const char *bye = "q!!\n";
	DWORD w;
	WriteFile(r->out_wr, bye, (DWORD)strlen(bye), &w, NULL);
	CloseHandle(r->out_wr);
	CloseHandle(r->in_rd);
	WaitForSingleObject(r->child, 5000);
	CloseHandle(r->child);
}

#  else  /* unix spawn */

static R2Pipe *r2p__open_spawn(const char *file, const char *flags) {
	int in_pipe[2];  /* child stdout -> parent */
	int out_pipe[2]; /* parent -> child stdin  */
	if (pipe(in_pipe) != 0) {
		return NULL;
	}
	if (pipe(out_pipe) != 0) {
		close(in_pipe[0]);
		close(in_pipe[1]);
		return NULL;
	}
	pid_t pid = fork();
	if (pid < 0) {
		close(in_pipe[0]);
		close(in_pipe[1]);
		close(out_pipe[0]);
		close(out_pipe[1]);
		return NULL;
	}
	if (pid == 0) {
		/* child */
		dup2(out_pipe[0], 0);
		dup2(in_pipe[1], 1);
		close(in_pipe[0]);
		close(in_pipe[1]);
		close(out_pipe[0]);
		close(out_pipe[1]);
		int nf = 0;
		char **fa = r2p__split(flags, &nf);
		/* r2 cli is order-sensitive: when "-0" appears BEFORE the quit
		 * flag, NUL framing comes out broken (zero bytes on stdout). To
		 * stay safe regardless of what the caller passed, we always put
		 * "-q0" first — and skip it if the caller already gave -0 / -q0
		 * to avoid double quit. */
		int has_zero = 0;
		for (int i = 0; i < nf; i++) {
			if (!strcmp(fa[i], "-0") || !strcmp(fa[i], "-q0")) {
				has_zero = 1;
				break;
			}
		}
		int ac = 0;
		char **av = (char **)calloc((size_t)(nf + 4), sizeof(char *));
		if (!av) {
			_exit(127);
		}
		av[ac++] = (char *)"radare2";
		av[ac++] = (char *)"-q0";
		for (int i = 0; i < nf; i++) {
			/* drop a redundant -q0 from the caller; -0 is fine after -q0 */
			if (has_zero && !strcmp(fa[i], "-q0")) {
				continue;
			}
			av[ac++] = fa[i];
		}
		if (file && *file) {
			av[ac++] = (char *)file;
		}
		av[ac] = NULL;
		execvp("radare2", av);
		_exit(127);
	}
	/* parent */
	close(in_pipe[1]);
	close(out_pipe[0]);
	R2Pipe *r = (R2Pipe *)calloc(1, sizeof(R2Pipe));
	if (!r) {
		close(in_pipe[0]);
		close(out_pipe[1]);
		return NULL;
	}
	r->mode = R2P_SPAWN;
	r->pid = (int)pid;
	r->in_fd = in_pipe[0];
	r->out_fd = out_pipe[1];
	/* Wait for the r2pipe banner (NUL terminator). If the child died
	 * before sending it (typically execvp failing because radare2 is not
	 * in PATH), the read returns 0 and we treat this as open failure. */
	char c;
	int got_banner = 0;
	while (read(r->in_fd, &c, 1) == 1) {
		if (c == '\0') { got_banner = 1; break; }
	}
	if (!got_banner) {
		close(r->in_fd);
		close(r->out_fd);
		waitpid((pid_t)r->pid, NULL, 0);
		free(r);
		return NULL;
	}
	return r;
}

static char *r2p__cmd_spawn(R2Pipe *r, const char *cmd) {
	size_t cl = strlen(cmd);
	char *line = (char *)malloc(cl + 2);
	if (!line) {
		return NULL;
	}
	memcpy(line, cmd, cl);
	line[cl] = '\n';
	line[cl + 1] = '\0';
	size_t total = cl + 1;
	size_t done = 0;
	while (done < total) {
		ssize_t k = write(r->out_fd, line + done, total - done);
		if (k <= 0) {
			break;
		}
		done += (size_t)k;
	}
	free(line);
	size_t cap = 4096, len = 0;
	char *buf = (char *)malloc(cap);
	if (!buf) {
		return NULL;
	}
	char c;
	while (read(r->in_fd, &c, 1) == 1) {
		if (c == '\0') {
			break;
		}
		if (len + 2 > cap) {
			cap *= 2;
			char *nb = (char *)realloc(buf, cap);
			if (!nb) {
				break;
			}
			buf = nb;
		}
		buf[len++] = c;
	}
	buf[len] = '\0';
	return buf;
}

static void r2p__close_spawn(R2Pipe *r) {
	const char *bye = "q!!\n";
	ssize_t _w = write(r->out_fd, bye, strlen(bye));
	(void)_w;
	close(r->out_fd);
	close(r->in_fd);
	int st;
	waitpid((pid_t)r->pid, &st, 0);
}

#  endif /* R2P_WINDOWS */
#endif /* R2P_ENABLE_SPAWN */

/* ---- dispatch ----------------------------------------------------- */
static R2Pipe *r2p_open(int mode, const char *file, const char *flags) {
#if R2P_ENABLE_DLOPEN
	if (mode == R2P_DLOPEN) {
		return r2p__open_dlopen(file, flags);
	}
#endif
#if R2P_ENABLE_SPAWN
	if (mode == R2P_SPAWN) {
		return r2p__open_spawn(file, flags);
	}
#endif
	(void)file;
	(void)flags;
	fprintf(stderr, "r2pipe: mode %d not available (check R2P_ENABLE_*)\n", mode);
	return NULL;
}

static char *r2p_cmd(R2Pipe *r, const char *cmd) {
	if (!r || !cmd) {
		return NULL;
	}
#if R2P_ENABLE_DLOPEN
	if (r->mode == R2P_DLOPEN) {
		return r->fn_cmd_str(r->core, cmd);
	}
#endif
#if R2P_ENABLE_SPAWN
	if (r->mode == R2P_SPAWN) {
		return r2p__cmd_spawn(r, cmd);
	}
#endif
	return NULL;
}

static void r2p_close(R2Pipe *r) {
	if (!r) {
		return;
	}
#if R2P_ENABLE_DLOPEN
	if (r->mode == R2P_DLOPEN) {
		if (r->core && r->fn_free) {
			r->fn_free(r->core);
		}
		r2p__lib_close(r->lib);
		free(r);
		return;
	}
#endif
#if R2P_ENABLE_SPAWN
	if (r->mode == R2P_SPAWN) {
		r2p__close_spawn(r);
		free(r);
		return;
	}
#endif
	free(r);
}

#endif /* R2PIPE_INC_C */
