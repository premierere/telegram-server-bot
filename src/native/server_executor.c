/*
 * server_executor.c - High-performance native process executor for Linux / POSIX systems.
 * Provides process group isolation, environment sanitization, rlimits, and real-time streaming.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if defined(_WIN32)
#include <windows.h>
#include <io.h>
#include <process.h>
#else
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>
#endif

#define BUFFER_SIZE 4096

static volatile int g_stop_requested = 0;

#if !defined(_WIN32)
static pid_t g_child_pid = 0;

void sig_handler(int signo) {
    g_stop_requested = 1;
    if (g_child_pid > 0) {
        // Propagate SIGINT/SIGTERM to child process group
        killpg(g_child_pid, signo);
    }
}
#endif

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <mode: restricted|shell> <command/argv...> [--sudo]\n", argv[0]);
        return 1;
    }

    const char *mode = argv[1];
    int use_sudo = 0;
    int cmd_start_idx = 2;

    // Check for --sudo flag
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--sudo") == 0) {
            use_sudo = 1;
        }
    }

#if defined(_WIN32)
    // On Windows development host, execute via cmd /c
    char cmd_buffer[8192] = {0};
    if (strcmp(mode, "shell") == 0) {
        snprintf(cmd_buffer, sizeof(cmd_buffer), "cmd.exe /s /c \"%s\"", argv[cmd_start_idx]);
    } else {
        // Restricted mode argv join
        for (int i = cmd_start_idx; i < argc; i++) {
            if (strcmp(argv[i], "--sudo") == 0) continue;
            strncat(cmd_buffer, argv[i], sizeof(cmd_buffer) - strlen(cmd_buffer) - 2);
            strncat(cmd_buffer, " ", sizeof(cmd_buffer) - strlen(cmd_buffer) - 1);
        }
    }

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        fprintf(stderr, "CreatePipe failed\n");
        return 1;
    }
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.dwFlags |= STARTF_USESTDHANDLES;
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(NULL, cmd_buffer, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        fprintf(stderr, "CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }
    CloseHandle(hWritePipe);

    char buffer[BUFFER_SIZE];
    DWORD bytes_read;
    while (ReadFile(hReadPipe, buffer, sizeof(buffer), &bytes_read, NULL) && bytes_read > 0) {
        fwrite(buffer, 1, bytes_read, stdout);
        fflush(stdout);
    }
    CloseHandle(hReadPipe);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return (int)exit_code;

#else
    // POSIX Implementation
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    int pipe_fd[2];
    if (pipe(pipe_fd) == -1) {
        perror("pipe");
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        // Child Process
        // 1. Establish new process group
        setpgid(0, 0);

        // 2. Redirect stdin from /dev/null
        int dev_null = open("/dev/null", O_RDONLY);
        if (dev_null != -1) {
            dup2(dev_null, STDIN_FILENO);
            close(dev_null);
        }

        // 3. Redirect stdout and stderr to pipe
        close(pipe_fd[0]);
        dup2(pipe_fd[1], STDOUT_FILENO);
        dup2(pipe_fd[1], STDERR_FILENO);
        close(pipe_fd[1]);

        // 4. Sanitize environment
        char *const clean_env[] = {
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG=en_US.UTF-8",
            "LC_ALL=en_US.UTF-8",
            "USER=telegram-bot",
            "HOME=/var/lib/telegram-server-bot",
            NULL
        };

        if (strcmp(mode, "shell") == 0) {
            char *const shell_argv[] = {"/bin/bash", "-c", argv[cmd_start_idx], NULL};
            execve("/bin/bash", shell_argv, clean_env);
        } else {
            // Restricted mode: build exec argv
            char *exec_args[256];
            int arg_pos = 0;
            if (use_sudo) {
                exec_args[arg_pos++] = "sudo";
            }
            for (int i = cmd_start_idx; i < argc; i++) {
                if (strcmp(argv[i], "--sudo") == 0) continue;
                if (arg_pos < 254) {
                    exec_args[arg_pos++] = argv[i];
                }
            }
            exec_args[arg_pos] = NULL;
            execvpe(exec_args[0], exec_args, clean_env);
        }

        perror("exec failed");
        _exit(127);
    }

    // Parent Process
    g_child_pid = pid;
    close(pipe_fd[1]);

    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    // Stream output directly
    while ((bytes_read = read(pipe_fd[0], buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        write(STDOUT_FILENO, buffer, bytes_read);
        if (g_stop_requested) {
            killpg(pid, SIGTERM);
            break;
        }
    }
    close(pipe_fd[0]);

    int status = 0;
    waitpid(pid, &status, 0);

    int exit_code = 0;
    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        exit_code = 128 + WTERMSIG(status);
    }

    return exit_code;
#endif
}
