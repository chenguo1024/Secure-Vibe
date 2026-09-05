// 安全模板：safe_java_db — Java 安全数据库查询（few-shot 示例）
//
// 演示要点：
// - PreparedStatement 占位符传参，绝不拼接 SQL（CWE-89 防护）
// - ProcessBuilder 参数列表直传，绝不 Runtime.exec 拼字符串（CWE-78 防护）
// - SecureRandom 生成安全随机（CWE-338 防护）

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public final class SafeJavaDb {

    private SafeJavaDb() {
    }

    // 按用户名查订单 — 占位符传参，绝不拼 SQL
    public String findOrders(Connection conn, String username) throws SQLException {
        if (username == null || username.isEmpty() || username.length() > 64) {
            throw new IllegalArgumentException("invalid username");
        }
        // "?" 占位符 + setString，用户输入永不进入 SQL 字符串本身
        String sql = "SELECT id, item FROM orders WHERE user = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                StringBuilder sb = new StringBuilder();
                while (rs.next()) {
                    sb.append(rs.getString("item")).append('\n');
                }
                return sb.toString();
            }
        }
    }

    // 生成安全 token — SecureRandom，绝不 new Random()
    public String generateToken() {
        SecureRandom rng = new SecureRandom();
        byte[] bytes = new byte[32];
        rng.nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
