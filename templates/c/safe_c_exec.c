/* 安全模板：safe_c_exec — C 语言安全外部程序执行（few-shot 示例）
 *
 * 演示要点：
 * - 绝不用 system()/popen()（命令注入 CWE-78）
 * - execve 固定 argv 数组，不经过 shell 解析
 * - 用户输入先白名单校验再使用
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* 白名单校验主机名：仅允许字母数字与点 */
static int is_valid_host(const char *host) {
    if (host == NULL || *host == '\0') {
        return 0;
    }
    for (const char *p = host; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '.' || *p == '-')) {
            return 0;
        }
    }
    return 1;
}

/* 安全 ping — execv 参数列表，绝不用 system("ping " + host) */
int safe_ping(const char *host) {
    if (!is_valid_host(host)) { /* 用户输入必须先校验 */
        return -1;
    }
    char *argv[] = {"/sbin/ping", "-c", "1", (char *)host, NULL};
    pid_t pid = fork();
    if (pid == 0) {
        execv(argv[0], argv); /* 绝不经过 shell */
        _exit(127);
    }
    return pid > 0 ? 0 : -1;
}
