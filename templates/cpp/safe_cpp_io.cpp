// 安全模板：safe_cpp_io — C++ 安全 I/O 与字符串管理（few-shot 示例）
//
// 演示要点：
// - std::string 管理字符串，绝不 std::strcpy/std::sprintf
// - std::getline 读入，绝不 cin >> char 数组
// - 绝不用 system()；外部程序用 C++ 需要时走 fork/execv（同 C 模板）

#include <iostream>
#include <string>

namespace safe_io {

// 安全读入一行 — std::getline 无缓冲区溢出风险
bool read_line(std::string &out) {
    if (!std::getline(std::cin, out)) {
        return false;
    }
    return true;
}

// 拼接问候语 — std::string 自动管理内存
std::string make_greeting(const std::string &username) {
    if (username.empty() || username.size() > 64) {
        return {}; // 输入校验：长度边界
    }
    return "Hello, " + username + "!";
}

} // namespace safe_io
