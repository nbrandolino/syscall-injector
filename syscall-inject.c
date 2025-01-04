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
#include <stdarg.h>
#include <signal.h>

// software and version name
#define NAME "syscall-inject"
#define VERSION "1.3"

// global target PID
pid_t targetPid;

// error checking macro
#define CHECKERROR(cond, msg) \
    if (cond) { \
        LOG_ERROR("%s failed at %s:%d. errno: %d (%s)", msg, __FILE__, __LINE__, errno, strerror(errno)); \
        exit(EXIT_FAILURE); \
    }

// display error messages with consistent logging
void logMessage(const char *level, const char *format, ...) {
    va_list args;
    va_start(args, format);
    printf("\033[1;37m[%s]\033[0m ", level);
    vprintf(format, args);
    printf("\n");
    va_end(args);
}

#define LOG_ERROR(format, ...) logMessage("\033[1;31mERROR\033[0m", format, ##__VA_ARGS__)
#define LOG_SUCCESS(format, ...) logMessage("\033[1;32mSUCCESS\033[0m", format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) logMessage("\033[1;34mINFO\033[0m", format, ##__VA_ARGS__)

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
    LOG_INFO("%s Version %s", NAME, VERSION);
    LOG_INFO("Licensed under the terms of the GNU General Public License.");
    exit(EXIT_SUCCESS);
}

// handle signals gracefully
void handleSignal(int sig) {
    LOG_INFO("Caught signal %d, detaching from the target process (PID: %d)...", sig, targetPid);
    ptrace(PTRACE_DETACH, targetPid, NULL, NULL);
    exit(EXIT_FAILURE);
}

// verify if a process with the given PID exists
int isProcessRunning(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    // check if the /proc/<pid>/status file exists and is readable
    FILE *file = fopen(path, "r");
    if (!file) {
        if (errno == ENOENT) {
            LOG_ERROR("Process with PID %d does not exist.", pid);
        } else {
            LOG_ERROR("Failed to open /proc/%d/status for PID %d. errno: %d (%s)", pid, pid, errno, strerror(errno));
        }
        return 0;
    }

    char buf[256];
    while (fgets(buf, sizeof(buf), file)) {
        // check if the process is a zombie (state = 'Z')
        if (strncmp(buf, "State:", 6) == 0 && strstr(buf, "Z")) {
            fclose(file);
            LOG_ERROR("Process with PID %d is in a 'zombie' state.", pid);
            return 0;
        }
    }
    fclose(file);
    return 1;
}

// validate PID format and existence
int validatePid(pid_t pid) {
    if (pid <= 0) {
        LOG_ERROR("Invalid PID format: %d.", pid);
        return 0;
    }
    if (!isProcessRunning(pid)) {
        return 0;
    }
    return 1;
}

// validate syscall number
int validateSyscallNumber(long syscall) {
    if (syscall < 0 || syscall > 456) {
        LOG_ERROR("Invalid syscall number %ld (must be between 0 and 456).", syscall);
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
    LOG_SUCCESS("Attached to process: %d", targetPid);

    // get the current state of the registers
    CHECKERROR(ptrace(PTRACE_GETREGS, targetPid, NULL, &regs) == -1, "PTRACE_GETREGS");
    memcpy(&original_regs, &regs, sizeof(struct user_regs_struct));

    // inject each syscall
    for (int i = 0; i < count; i++) {
        regs.orig_rax = syscallNumbers[i];
        regs.rax = syscallNumbers[i];
        LOG_INFO("Injecting system call number: %ld", syscallNumbers[i]);

        // set the modified registers
        CHECKERROR(ptrace(PTRACE_SETREGS, targetPid, NULL, &regs) == -1, "PTRACE_SETREGS");

        // execute the syscall
        CHECKERROR(ptrace(PTRACE_SYSCALL, targetPid, NULL, NULL) == -1, "PTRACE_SYSCALL");
        waitpid(targetPid, &status, 0);

        // get the return value from the syscall
        CHECKERROR(ptrace(PTRACE_GETREGS, targetPid, NULL, &regs) == -1, "PTRACE_GETREGS");
        LOG_SUCCESS("System call return value: %ld", regs.rax);
    }

    // restore the original registers
    CHECKERROR(ptrace(PTRACE_SETREGS, targetPid, NULL, &original_regs) == -1, "PTRACE_SETREGS");

    // detach from the process
    CHECKERROR(ptrace(PTRACE_DETACH, targetPid, NULL, NULL) == -1, "PTRACE_DETACH");
    LOG_SUCCESS("Detached from process: %d", targetPid);
}

// parse syscall list from a comma-separated string
int parseSyscallList(char *list, long *syscalls, int maxCount) {
    char *token = strtok(list, ",");
    int count = 0;

    while (token != NULL && count < maxCount) {
        syscalls[count] = strtol(token, NULL, 10);
        if (errno == ERANGE) {
            LOG_ERROR("Invalid syscall number in list.");
            return count;
        }
        count++;
        token = strtok(NULL, ",");
    }
    return count;
}

// dynamically allocate memory for syscalls
long *allocateSyscallsMemory(int count) {
    long *syscalls = malloc(sizeof(long) * count);
    if (syscalls == NULL) {
        LOG_ERROR("Memory allocation failed for syscalls.");
        exit(EXIT_FAILURE);
    }
    return syscalls;
}

// main function
int main(int argc, char *argv[]) {
    if (argc < 2) {
        LOG_ERROR("Insufficient arguments. Use -h for help.");
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

    // check for multiple syscall injection
    if (strcmp(argv[1], "-m") == 0 || strcmp(argv[1], "--multiple") == 0) {
        if (argc != 4) {
            LOG_ERROR("Usage: %s -m <pid> <syscall_list>", argv[0]);
            exit(EXIT_FAILURE);
        }

        targetPid = strtol(argv[2], NULL, 10);
        if (!validatePid(targetPid)) exit(EXIT_FAILURE);

        syscallCount = parseSyscallList(argv[3], syscalls, 100);
        if (syscallCount <= 0) {
            LOG_ERROR("Invalid syscall list %s", argv[3]);
            exit(EXIT_FAILURE);
        }

        // validate syscall numbers
        for (int i = 0; i < syscallCount; i++) {
            if (!validateSyscallNumber(syscalls[i])) exit(EXIT_FAILURE);
        }

    } else {
        if (argc != 3) {
            LOG_ERROR("Usage: %s <pid> <syscall_number>", argv[0]);
            exit(EXIT_FAILURE);
        }

        targetPid = strtol(argv[1], NULL, 10);
        if (!validatePid(targetPid)) exit(EXIT_FAILURE);

        // dynamically allocate memory for syscalls array
        syscallCount = 1;
        syscalls = allocateSyscallsMemory(syscallCount);

        syscalls[0] = strtol(argv[2], NULL, 10);
        if (errno == ERANGE || syscalls[0] <= 0) {
            LOG_ERROR("Invalid syscall number format.");
            free(syscalls);
            exit(EXIT_FAILURE);
        }

        if (!validateSyscallNumber(syscalls[0])) exit(EXIT_FAILURE);
    }

    // inject syscalls
    injectSyscall(targetPid, syscalls, syscallCount);

    // free dynamically allocated memory
    free(syscalls);
    return 0;
}
