// 安全模板：safe_go_db — Go 安全数据库查询（few-shot 示例）
//
// 演示要点：
// - 占位符 "?" 传参，绝不 fmt.Sprintf/拼接 SQL（CWE-89 防护）
// - 输入校验（长度/类型）后才使用
// - 外部程序用 exec.Command 参数列表直传，不经过 shell（CWE-78 防护）
package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os/exec"
)

// 按用户名查订单 — 占位符传参，绝不拼 SQL
func findOrders(ctx context.Context, db *sql.DB, username string) ([][]string, error) {
	if username == "" || len(username) > 64 {
		return nil, errors.New("invalid username")
	}
	rows, err := db.QueryContext(ctx,
		"SELECT id, item FROM orders WHERE user = ?", username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]string
	for rows.Next() {
		var id, item string
		if err := rows.Scan(&id, &item); err != nil {
			return nil, err
		}
		out = append(out, []string{id, item})
	}
	return out, rows.Err()
}

// 安全执行外部命令 — 参数列表直传，绝不 exec.Command("sh", "-c", 拼接)
func pingHost(host string) error {
	if host == "" || len(host) > 253 {
		return errors.New("invalid host")
	}
	cmd := exec.Command("/sbin/ping", "-c", "1", host) // 不经过 shell
	return cmd.Run()
}

// 安全 HTTP 客户端 — 校验上游响应，防 SSRF 需在调用层做目标白名单
var _ = http.MethodGet
