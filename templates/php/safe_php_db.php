<?php
/**
 * 安全模板：safe_php_db — PHP 安全数据库查询与输出（few-shot 示例）
 *
 * 演示要点：
 * - PDO 预处理语句，绝不拼接 SQL（CWE-89 防护）
 * - htmlspecialchars 转义输出，绝不裸 echo 超全局（CWE-80 防护）
 * - 输入先过滤再使用
 */

// 数据库连接（生产环境凭据从环境变量读取，绝不硬编码）
function get_db(): PDO {
    $dsn = sprintf('mysql:host=%s;dbname=%s;charset=utf8mb4',
        getenv('DB_HOST'), getenv('DB_NAME'));
    return new PDO($dsn, getenv('DB_USER'), getenv('DB_PASS'), [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false, // 真预处理，防注入
    ]);
}

// 按用户名查订单 — 预处理语句，绝不拼接 $_GET
function find_orders(PDO $db, string $username): array {
    if ($username === '' || mb_strlen($username) > 64) {
        throw new InvalidArgumentException('invalid username'); // 输入校验
    }
    $stmt = $db->prepare('SELECT id, item, created_at FROM orders WHERE user = :u');
    $stmt->execute([':u' => $username]); // 参数绑定，绝不拼进 SQL 字符串
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// 输出订单列表 — htmlspecialchars 转义，绝不裸 echo
function render_orders(array $orders): void {
    foreach ($orders as $o) {
        $item = htmlspecialchars((string)$o['item'], ENT_QUOTES, 'UTF-8');
        echo '<li>' . $item . '</li>';
    }
}
