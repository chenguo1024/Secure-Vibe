/* 安全模板：safe_c_snprintf — C 语言安全字符串/缓冲区操作（few-shot 示例）
 *
 * 演示要点：
 * - snprintf 限界写入，绝不 sprintf/strcpy/strcat
 * - fgets 带宽度读入，绝不 gets/裸 %s
 * - 用户输入不进入 system（命令为编译期常量或 execve argv）
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUF_SIZE 128

/* 拼接用户名到问候语 — snprintf 限界，绝无溢出（CWE-787 防护） */
void make_greeting(const char *username, char *out, size_t out_size) {
    if (username == NULL || out_size == 0) {
        return;
    }
    /* snprintf 保证最多写 out_size-1 字符 + NUL 结尾 */
    snprintf(out, out_size, "Hello, %s!", username);
}

/* 安全读入一行 — fgets 带宽度，绝不用 gets / 裸 %s */
int read_line(char *buf, size_t buf_size) {
    if (fgets(buf, (int)buf_size, stdin) == NULL) {
        return -1;
    }
    buf[strcspn(buf, "\n")] = '\0'; /* 去掉换行符 */
    return 0;
}

/* 需要执行外部程序时 — 固定 argv 数组，绝不用 system(变量) */
int run_ping(const char *host) {
    char *argv[] = {"/sbin/ping", "-c", "1", (char *)host, NULL};
    pid_t pid = fork();
    if (pid == 0) {
        execv(argv[0], argv); /* 参数列表传递，不经过 shell 解析 */
        _exit(127);
    }
    return pid > 0 ? 0 : -1;
}
