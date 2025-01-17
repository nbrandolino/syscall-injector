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
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/mman.h>

// software and version name
#define NAME "syscall-inject"
#define VERSION "1.6.5"

// global target PID
pid_t targetPid;
long *syscalls = NULL;

// error checking macro
#define CHECKERROR(cond, msg) \
    if (cond) { \
        LOG_ERROR("%s failed at %s:%d with errno %d: %s", msg, __FILE__, __LINE__, errno, strerror(errno)); \
        return; \
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

// function prototype for freeSyscallsMemory
void freeSyscallsMemory(long *syscalls);

// display help information
void showHelp() {
    printf("Usage: %s [options] <pid> <syscall_number> | -m <syscall_list>\n", NAME);
    printf("\n");
    printf("Options:\n");
    printf("    -h, --help                  Display this help message.\n");
    printf("    -v, --version               Display version information.\n");
    printf("    -m, --multiple              Inject multiple system calls, comma-separated (e.g., \"60,39,1\").\n");
    printf("    -l, --list                  List open files, memory map, and environment variables of the target process.\n");
    printf("\n");
    printf("Arguments:\n");
    printf("    <pid>                       The process ID of the target process.\n");
    printf("    <syscall_number>            The system call number to inject into the process.\n");
    printf("\n");
    printf("Example:\n");
    printf("    $ %s 1234 60\n", NAME);
    printf("    $ %s -m 1234 60,39,1\n", NAME);
    printf("    $ %s -l 1234\n", NAME);
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
    if (ptrace(PTRACE_DETACH, targetPid, NULL, NULL) == -1) {
        LOG_ERROR("Failed to detach from PID %d. errno: %d (%s)", targetPid, errno, strerror(errno));
    } else {
        LOG_SUCCESS("Detached from process %d", targetPid);
    }
    // perform cleanup before exiting to avoid memory leaks
    if (syscalls != NULL) {
        freeSyscallsMemory(syscalls);
    }
    exit(EXIT_FAILURE);
}

// verify if a process with the given PID exists
int isProcessRunning(pid_t pid) {
    if (kill(pid, 0) == -1) {
        if (errno == ESRCH) {
            LOG_ERROR("Process with PID %d does not exist.", pid);
        } else {
            LOG_ERROR("Failed to check existence of PID %d. errno: %d (%s)", pid, errno, strerror(errno));
        }
        return 0;
    }
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
    const long MAX_SYSCALL_NUMBER = 456;
    if (syscall < 0 || syscall > MAX_SYSCALL_NUMBER) {
        LOG_ERROR("Invalid syscall number %ld (must be between 0 and %ld).", syscall, MAX_SYSCALL_NUMBER);
        return 0;
    }
    return 1;
}

// anti-debugging
int isBeingTraced(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *status = fopen(path, "r");
    if (!status) {
        LOG_ERROR("Failed to open /proc/%d/status", pid);
        return 1;
    }
    char line[256];
    while (fgets(line, sizeof(line), status)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracerPid = atoi(line + 10);
            if (tracerPid != 0) {
                fclose(status);
                return 1;
            }
        }
    }
    fclose(status);
    return 0;
}

// attach to the process, inject syscalls, and then detach
void injectSyscall(pid_t targetPid, long *syscallNumbers, int count) {
    struct user_regs_struct regs, original_regs;
    int status;

    // check for debugger presence
    if (isBeingTraced(targetPid)) {
        LOG_ERROR("Process %d is being traced, aborting syscall injection.", targetPid);
        return;
    }

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
        char *endptr;
        syscalls[count] = strtol(token, &endptr, 10);
        if (*endptr != '\0') {
            LOG_ERROR("Invalid syscall number in list: '%s'.", token);
            return count;
        }
        count++;
        token = strtok(NULL, ",");
    }
    return count;
}

// dynamically allocate memory for syscalls with proper error checking
long *allocateSyscallsMemory(int count) {
    long *syscalls = malloc(sizeof(long) * count);
    if (syscalls == NULL) {
        LOG_ERROR("Memory allocation failed for syscalls.");
        exit(EXIT_FAILURE);
    }
    return syscalls;
}

// free dynamically allocated memory for syscalls
void freeSyscallsMemory(long *syscalls) {
    if (syscalls != NULL) {
        free(syscalls);
    }
}

// check if the program has root privileges
int isRoot() {
    return geteuid() == 0;
}

// list open files, memory map, and environment variables of the target process
void listProcessInfo(pid_t pid) {
    char path[512];

    // list open files
    snprintf(path, sizeof(path), "/proc/%d/fd", pid);
    DIR *dir = opendir(path);
    if (dir == NULL) {
        LOG_ERROR("Failed to open /proc/%d/fd", pid);
        return;
    }
    struct dirent *entry;
    LOG_INFO("Open files for PID %d:", pid);
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_LNK) {
            char link[1024];
            snprintf(path, sizeof(path), "/proc/%d/fd/%s", pid, entry->d_name);
            ssize_t len = readlink(path, link, sizeof(link) - 1);
            if (len != -1) {
                link[len] = '\0';
                LOG_INFO("  %s -> %s", entry->d_name, link);
            }
        }
    }
    closedir(dir);

    // list memory map
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *maps = fopen(path, "r");
    if (maps) {
        LOG_INFO("Memory map for PID %d:", pid);
        char line[256];
        while (fgets(line, sizeof(line), maps)) {
            line[strcspn(line, "\n")] = '\0';
            LOG_INFO("  %s", line);
        }
        fclose(maps);
    } else {
        LOG_ERROR("Failed to open /proc/%d/maps", pid);
    }

    // list environment variables
    snprintf(path, sizeof(path), "/proc/%d/environ", pid);
    FILE *environ = fopen(path, "r");
    if (environ) {
        LOG_INFO("Environment variables for PID %d:", pid);
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), environ)) {
            for (char *p = buffer; *p; ++p) {
                putchar(*p == '\0' ? '\n' : *p);
            }
        }
        fclose(environ);
    } else {
        LOG_ERROR("Failed to open /proc/%d/environ", pid);
    }
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
    signal(SIGSEGV, handleSignal);
    signal(SIGBUS, handleSignal);
    signal(SIGILL, handleSignal);

    // check if root privileges are required
    if (!isRoot()) {
        LOG_ERROR("This operation requires root privileges. Please run as root.");
        exit(EXIT_FAILURE);
    }

    // call help function
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        showHelp();
    }

    // call version function
    if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
        showVersion();
    }

    // list process info
    if (strcmp(argv[1], "-l") == 0 || strcmp(argv[1], "--list") == 0) {
        if (argc != 3) {
            LOG_ERROR("Usage: %s -l <pid>", argv[0]);
            exit(EXIT_FAILURE);
        }
        targetPid = strtol(argv[2], NULL, 10);
        if (!validatePid(targetPid)) exit(EXIT_FAILURE);
        listProcessInfo(targetPid);
        return 0;
    }

    int syscallCount = 0;

    // check for multiple syscall injection
    if (strcmp(argv[1], "-m") == 0 || strcmp(argv[1], "--multiple") == 0) {
        if (argc != 4) {
            LOG_ERROR("Usage: %s -m <syscall_list>", argv[0]);
            exit(EXIT_FAILURE);
        }
        targetPid = strtol(argv[2], NULL, 10);
        if (!validatePid(targetPid)) exit(EXIT_FAILURE);
        syscallCount = parseSyscallList(argv[3], syscalls, 128);
    } else {
        if (argc != 3) {
            LOG_ERROR("Usage: %s <pid> <syscall_number>", argv[0]);
            exit(EXIT_FAILURE);
        }
        targetPid = strtol(argv[1], NULL, 10);
        if (!validatePid(targetPid)) exit(EXIT_FAILURE);
        syscallCount = 1;
        syscalls = allocateSyscallsMemory(1);
        syscalls[0] = strtol(argv[2], NULL, 10);
        if (!validateSyscallNumber(syscalls[0])) exit(EXIT_FAILURE);
    }

    // inject syscalls
    injectSyscall(targetPid, syscalls, syscallCount);

    // free allocated memory
    freeSyscallsMemory(syscalls);
    return 0;
}
