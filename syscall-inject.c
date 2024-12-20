#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>

// software and version name
#define NAME "syscall-inject"
#define VERSION "1.3"

// global target PID
pid_t targetPid;

// error checking macro
#define CHECKERROR(cond, msg) \
    if (cond) { \
        fprintf(stderr, "\033[1;37m[\033[0m\033[1;31m!\033[0m\033[1;37m]\033[0m Error: %s failed at %s:%d. errno: %d (%s)\n", msg, __FILE__, __LINE__, errno, strerror(errno)); \
        exit(EXIT_FAILURE); \
    }

// display help information
void showHelp() {
    printf("Usage: %s [options] <pid> <syscall_number> | -m <syscall_list>\n", NAME);
    printf("\n");
    printf("Options:\n");
    printf("    -h, --help                  Display this help message.\n");
    printf("    -v, --version               Display version information.\n");
    printf("    -m, --multiple              Inject multiple system calls, comma-separated (e.g., \"60,39,1\").\n");
    printf("\n");
    printf("Arguments:\n");
    printf("    <pid>                       The process ID of the target process.\n");
    printf("    <syscall_number>            The system call number to inject into the process.\n");
    printf("\n");
    printf("Example:\n");
    printf("    $ %s 1234 60\n", NAME);
    printf("    $ %s -m 1234 60,39,1\n", NAME);
    exit(EXIT_SUCCESS);
}

// display version information
void showVersion() {
    printf("%s Version %s\n", NAME, VERSION);
    printf("Licensed under the terms of the GNU General Public License.\n");
    exit(EXIT_SUCCESS);
}

// handle signals gracefully
void handleSignal(int sig) {
    printf("\nCaught signal %d, detaching from the target process (PID: %d)...\n", sig, targetPid);
    ptrace(PTRACE_DETACH, targetPid, NULL, NULL);
    exit(EXIT_FAILURE);
}

// verify if a process with the given PID exists
int isProcessRunning(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *file = fopen(path, "r");
    if (!file) return 0;

    char buf[256];
    while (fgets(buf, sizeof(buf), file)) {
        if (strncmp(buf, "State:", 6) == 0) {
            if (strstr(buf, "Z") != NULL) {
                fclose(file);
                return 0;
            }
            break;
        }
    }
    fclose(file);
    return 1;
}

// validate PID format and existence
int validatePid(pid_t pid) {
    if (errno == ERANGE || pid <= 0) {
        fprintf(stderr, "\033[1;37m[\033[0m\033[1;31m!\033[0m\033[1;37m]\033[0m Error: Invalid PID format.\n");
        return 0;
    }
    if (!isProcessRunning(pid)) {
        fprintf(stderr, "\033[1;37m[\033[0m\033[1;31m!\033[0m\033[1;37m]\033[0m Error: Target process with PID %d does not exist.\n", pid);
        return 0;
    }
    return 1;
}

// validate syscall number
int validateSyscallNumber(long syscall) {
    if (syscall < 0 || syscall > 456) {
        fprintf(stderr, "\033[1;37m[\033[0m\033[1;31m!\033[0m\033[1;37m]\033[0m Error: Invalid syscall number %ld (must be between 0 and 456).\n", syscall);
        return 0;
    }
    return 1;
}

// attach to a process and inject a syscall
void injectSyscall(pid_t targetPid, long *syscallNumbers, int count) {
    struct user_regs_struct regs, original_regs;
    int status;

    // attach to the target process
    CHECKERROR(ptrace(PTRACE_ATTACH, targetPid, NULL, NULL) == -1, "PTRACE_ATTACH");
    waitpid(targetPid, &status, 0);
    printf("\033[1;37m[\033[0m\033[1;32m+\033[0m\033[1;37m]\033[0m Attached to process: %d\n", targetPid);

    // get the current state of the registers
    CHECKERROR(ptrace(PTRACE_GETREGS, targetPid, NULL, &regs) == -1, "PTRACE_GETREGS");
    memcpy(&original_regs, &regs, sizeof(struct user_regs_struct));

    // inject each syscall
    for (int i = 0; i < count; i++) {
        regs.orig_rax = syscallNumbers[i];
        regs.rax = syscallNumbers[i];
        printf("\033[1;37m[\033[0m\033[1;32m+\033[0m\033[1;37m]\033[0m Injecting system call number: %ld\n", syscallNumbers[i]);

        // set the modified registers
        CHECKERROR(ptrace(PTRACE_SETREGS, targetPid, NULL, &regs) == -1, "PTRACE_SETREGS");

        // execute the syscall
        CHECKERROR(ptrace(PTRACE_SYSCALL, targetPid, NULL, NULL) == -1, "PTRACE_SYSCALL");
        waitpid(targetPid, &status, 0);

        // get the return value from the syscall
        CHECKERROR(ptrace(PTRACE_GETREGS, targetPid, NULL, &regs) == -1, "PTRACE_GETREGS");
        printf("\033[1;37m[\033[0m\033[1;32m+\033[0m\033[1;37m]\033[0m System call return value: %ld\n", regs.rax);
    }

    // restore the original registers
    CHECKERROR(ptrace(PTRACE_SETREGS, targetPid, NULL, &original_regs) == -1, "PTRACE_SETREGS");

    // detach from the process
    CHECKERROR(ptrace(PTRACE_DETACH, targetPid, NULL, NULL) == -1, "PTRACE_DETACH");
    printf("\033[1;37m[\033[0m\033[1;32m+\033[0m\033[1;37m]\033[0m Detached from process: %d\n", targetPid);
}

// parse syscall list from a comma-separated string
int parseSyscallList(char *list, long *syscalls, int maxCount) {
    char *token = strtok(list, ",");
    int count = 0;

    while (token != NULL && count < maxCount) {
        syscalls[count] = strtol(token, NULL, 10);
        if (errno == ERANGE) {
            fprintf(stderr, "Error: Invalid syscall number in list.\n");
            return count;
        }
        count++;
        token = strtok(NULL, ",");
    }
    return count;
}

// main function
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [options] <pid> <syscall_number> | -m <syscall_list>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // handle signals
    signal(SIGINT, handleSignal);
    signal(SIGTERM, handleSignal);

    // call help function
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        showHelp();
    }

    // call version function
    if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
        showVersion();
    }

    long *syscalls = NULL;
    int syscallCount = 0;

    if (strcmp(argv[1], "-m") == 0 || strcmp(argv[1], "--multiple") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s -m <pid> <syscall_list>\n", argv[0]);
            exit(EXIT_FAILURE);
        }

        targetPid = strtol(argv[2], NULL, 10);
        if (!validatePid(targetPid)) exit(EXIT_FAILURE);

        syscallCount = parseSyscallList(argv[3], syscalls, 100);
        if (syscallCount <= 0) {
            fprintf(stderr, "\033[1;37m[\033[0m\033[1;31m!\033[0m\033[1;37m]\033[0m Error: Invalid syscall list %s\n", argv[3]);
            exit(EXIT_FAILURE);
        }

        // validate syscall numbers
        for (int i = 0; i < syscallCount; i++) {
            if (!validateSyscallNumber(syscalls[i])) exit(EXIT_FAILURE);
        }

    } else {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s <pid> <syscall_number>\n", argv[0]);
            exit(EXIT_FAILURE);
        }

        targetPid = strtol(argv[1], NULL, 10);
        if (!validatePid(targetPid)) exit(EXIT_FAILURE);

        syscalls = malloc(sizeof(long) * 1);
        syscalls[0] = strtol(argv[2], NULL, 10);
        if (errno == ERANGE || syscalls[0] <= 0) {
            fprintf(stderr, "\033[1;37m[\033[0m\033[1;31m!\033[0m\033[1;37m]\033[0m Error: Invalid syscall number format.\n");
            exit(EXIT_FAILURE);
        }
        syscallCount = 1;

        if (!validateSyscallNumber(syscalls[0])) exit(EXIT_FAILURE);
    }

    // inject syscalls
    injectSyscall(targetPid, syscalls, syscallCount);

    free(syscalls);
    return 0;
}
