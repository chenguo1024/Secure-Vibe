/**
 * 安全模板：safe_js_dom — JavaScript 安全 DOM 操作（few-shot 示例）
 *
 * 演示要点：
 * - textContent 赋值，绝不 innerHTML（DOM XSS 防护）
 * - addEventListener 绑定事件，绝不内联 onclick（CSP 兼容）
 * - postMessage 指定明确 targetOrigin，绝不 "*"
 * - URL 参数用 URLSearchParams 解析 + textContent 输出
 */

// 安全渲染用户数据 — textContent，绝不 innerHTML（CWE-79 防护）
function renderSearchResult(container, query) {
    const params = new URLSearchParams(new URL(window.location.href).search);
    const q = params.get("q") ?? ""; // URL 参数解析，不做 innerHTML 拼接
    const el = document.createElement("p");
    el.textContent = "搜索结果: " + q; // textContent 自动转义
    container.appendChild(el);
}

// 事件绑定 — addEventListener，绝不内联 onclick（CSP 兼容）
document.addEventListener("DOMContentLoaded", () => {
    const btn = document.querySelector("#search-btn");
    if (btn) {
        btn.addEventListener("click", (ev) => {
            ev.preventDefault();
            const container = document.querySelector("#results");
            renderSearchResult(container);
        });
    }
});

// 跨源消息 — targetOrigin 指定明确源，绝不 "*"（CWE-346 防护）
function notifyParent(payload) {
    if (window.parent !== window) {
        window.parent.postMessage(payload, "https://app.example.com");
    }
}

// 接收消息 — 必须校验 origin
window.addEventListener("message", (ev) => {
    if (ev.origin !== "https://app.example.com") {
        return; // 陌生源直接丢弃
    }
    const box = document.querySelector("#msg");
    if (box) {
        box.textContent = String(ev.data); // textContent 而非 innerHTML
    }
});
