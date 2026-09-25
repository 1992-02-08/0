# ☁️ 合并订阅 (SubMerge)

自动合并多个机场订阅源，去重、去广告/提示词节点，按延迟排序，每日 0 点自动更新。

## 📥 订阅链接

| 客户端 | 链接 |
|---|---|
| Clash / Mihomo / ClashX | `https://raw.githubusercontent.com/1992-02-08/0/main/clash.yaml` |
| v2rayNG / Shadowrocket / NekoBox / sing-box | `https://raw.githubusercontent.com/1992-02-08/0/main/base64.txt` |
| 纯节点列表 | `https://raw.githubusercontent.com/1992-02-08/0/main/nodes.txt` |

## 📊 当前内容

见 `meta.json`（节点数、地区分布、更新时间）。

## 🔄 自动更新

GitHub Actions 每日 00:00 (UTC+8) 运行，抓取 → 清洗 → 测速排序 → 提交。

## 📁 产物说明

- `https://raw.githubusercontent.com/1992-02-08/0/main/clash.yaml` — 完整 Clash/Mihomo 配置，含地区分组、自动选择、AI/媒体分流规则
- `https://raw.githubusercontent.com/1992-02-08/0/main/base64.txt` — Base64 通用订阅，兼容绝大多数客户端
- `https://raw.githubusercontent.com/1992-02-08/0/main/nodes.txt` — 明文分享链接
- `meta.json` — 元信息与节点延迟
