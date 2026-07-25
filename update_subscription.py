#!/usr/bin/env python3
import base64
import json
import os
import re
import sys
import time
import yaml
from urllib.parse import urlparse, parse_qs, unquote
from urllib.request import Request, urlopen

WORKSPACE = os.path.dirname(os.path.abspath(__file__))

API_ENDPOINTS = [
    "http://89.185.80.175:8081/dazhutou/a0047a2b602e532d70b5282e424606f2",
    "https://dash.knjc.cfd/api/v1/client/subscribe?token=780d32c6a5fec66192b046685af32c4d",
    "https://dash.pqjc.site/api/v1/pq/61c22bd6d8c7bcc810c1906cf612bfd9",
]
TOTAL_TRAFFIC_GB = 4608  # 4.5T = 4608 GB
TRAFFIC_OVERRIDES_FILE = os.path.join(WORKSPACE, 'traffic_overrides.json')

def load_traffic_overrides():
    if not os.path.exists(TRAFFIC_OVERRIDES_FILE):
        return {}
    with open(TRAFFIC_OVERRIDES_FILE, 'r') as f:
        data = json.load(f)
    return data.get('traffic_overrides', {})

def parse_vless(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    node = {
        'name': unquote(parsed.fragment) if parsed.fragment else parsed.hostname,
        'type': 'vless',
        'server': parsed.hostname,
        'port': int(parsed.port),
        'uuid': parsed.username,
        'network': params.get('type', ['tcp'])[0],
        'tls': False,
    }
    security = params.get('security', ['none'])[0]
    fp = params.get('fp', ['chrome'])[0]
    if security == 'reality':
        node['tls'] = True
        node['flow'] = params.get('flow', [''])[0]
        node['servername'] = params.get('sni', [''])[0]
        node['client-fingerprint'] = fp
        node['reality-opts'] = {
            'public-key': params.get('pbk', [''])[0],
            'short-id': params.get('sid', [''])[0],
        }
    elif security == 'tls':
        node['tls'] = True
        node['servername'] = params.get('sni', [params.get('host', [''])[0]])[0]
        node['client-fingerprint'] = fp
    if node['network'] in ('ws', 'websocket'):
        node['network'] = 'ws'
        node['ws-opts'] = {
            'path': unquote(params.get('path', ['/'])[0]),
            'headers': {'Host': params.get('host', [''])[0]},
        }
    return node

def parse_anytls(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return {
        'name': unquote(parsed.fragment) if parsed.fragment else parsed.hostname,
        'type': 'anytls',
        'server': parsed.hostname,
        'port': int(parsed.port),
        'password': parsed.username,
        'sni': params.get('sni', [''])[0],
        'skip-cert-verify': params.get('insecure', ['0'])[0] == '1',
        'udp': True,
    }

def parse_hysteria2(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    node = {
        'name': unquote(parsed.fragment) if parsed.fragment else parsed.hostname,
        'type': 'hysteria2',
        'server': parsed.hostname,
        'port': int(parsed.port),
        'password': parsed.username,
        'sni': params.get('sni', [''])[0],
        'skip-cert-verify': params.get('insecure', ['false'])[0].lower() == 'true',
    }
    pinsha = params.get('pinSHA256', [''])[0]
    if pinsha:
        node['fingerprint'] = pinsha
    return node

def parse_vmess(url):
    content = url.split('://', 1)[1]
    data = json.loads(base64.b64decode(content).decode('utf-8'))
    node = {
        'name': data.get('ps', 'vmess'),
        'type': 'vmess',
        'server': data['add'],
        'port': int(data['port']),
        'uuid': data['id'],
        'alterId': int(data.get('aid', 0)),
        'cipher': 'auto',
        'network': data.get('net', 'tcp'),
        'tls': data.get('tls', '') == 'tls',
    }
    if node['network'] == 'ws':
        node['ws-opts'] = {
            'path': data.get('path', '/'),
            'headers': {'Host': data.get('host', '')},
        }
    fp = data.get('fp', '')
    if fp:
        node['client-fingerprint'] = fp
    if data.get('host'):
        node['servername'] = data['host']
    return node

def fetch_subscription(url):
    req = Request(url, headers={'User-Agent': 'v2rayN/6.0'})
    resp = urlopen(req, timeout=15)
    traffic = {}
    for key in ('subscription-userinfo', 'Subscription-Userinfo'):
        val = resp.headers.get(key, '')
        if val:
            for kv in val.split(';'):
                kv = kv.strip()
                if '=' in kv:
                    k, v = kv.split('=', 1)
                    traffic[k.strip()] = v.strip()
            break
    body = resp.read()
    if not body or not body.strip():
        return [], traffic

    raw_text = body.strip().decode('utf-8', errors='ignore')

    if raw_text.startswith('{'):
        try:
            err = json.loads(raw_text)
            msg = err.get('message', raw_text[:80])
            raise Exception(f"API error: {msg}")
        except json.JSONDecodeError:
            raise Exception(f"Unexpected JSON: {raw_text[:80]}")

    padding = 4 - len(raw_text) % 4
    if padding != 4:
        raw_text += '=' * padding

    try:
        decoded = base64.b64decode(raw_text).decode('utf-8', errors='ignore')
    except Exception:
        decoded = raw_text

    raw_lines = [l.strip() for l in decoded.split('\n') if l.strip()]

    nodes = []
    system_keywords = ['更新订阅', '特殊时期', '如果只显示', '客户端太旧', '使用教程', '更新一下客户端', '剩余流量', '套餐到期']
    for line in raw_lines:
        try:
            if line.startswith('vless://'):
                node = parse_vless(line)
            elif line.startswith('anytls://'):
                node = parse_anytls(line)
            elif line.startswith('hysteria2://'):
                node = parse_hysteria2(line)
            elif line.startswith('vmess://'):
                node = parse_vmess(line)
            else:
                continue
            if any(kw in node['name'] for kw in system_keywords):
                continue
            nodes.append(node)
        except Exception:
            continue
    return nodes, traffic

def format_traffic(bytes_val):
    if bytes_val >= 1024**4:
        return f"{bytes_val/(1024**4):.2f}T"
    elif bytes_val >= 1024**3:
        return f"{bytes_val/(1024**3):.2f}G"
    elif bytes_val >= 1024**2:
        return f"{bytes_val/(1024**2):.2f}M"
    return f"{bytes_val/1024:.2f}K"

def main():
    all_nodes = []
    total_download = 0
    total_upload = 0
    total_cap = 0
    traffic_overrides = load_traffic_overrides()

    for i, url in enumerate(API_ENDPOINTS):
        name = f"API{i+1}"
        try:
            nodes, traffic = fetch_subscription(url)
            all_nodes.extend(nodes)
            dl = traffic.get('download', '0')
            ul = traffic.get('upload', '0')
            cap = traffic.get('total', '0')

            override = traffic_overrides.get(url, {})
            override_dl = override.get('download_gb', 0)
            override_ul = override.get('upload_gb', 0)

            if dl != '0' or ul != '0':
                total_download += int(dl)
                total_upload += int(ul)
                total_cap = max(total_cap, int(cap))
                print(f"[{name}] {len(nodes)} nodes, traffic: {format_traffic(int(dl))} down, cap: {format_traffic(int(cap))}")
            elif override_dl > 0 or override_ul > 0:
                total_download += int(override_dl * 1024**3)
                total_upload += int(override_ul * 1024**3)
                print(f"[{name}] {len(nodes)} nodes, manual traffic: {override_dl}G down")
            else:
                if nodes:
                    total_cap = max(total_cap, int(TOTAL_TRAFFIC_GB * 1024**3 / 3))
                print(f"[{name}] {len(nodes)} nodes (no traffic data)")
        except Exception as e:
            print(f"[{name}] ERROR: {e}")

    used_gb = (total_download + total_upload) / (1024**3)
    cap_gb = TOTAL_TRAFFIC_GB if total_cap == 0 else max(TOTAL_TRAFFIC_GB, total_cap / (1024**3))
    usage_pct = (used_gb / cap_gb * 100) if cap_gb > 0 else 0

    if not all_nodes:
        print("No nodes fetched, skipping update")
        sys.exit(1)

    display_name = f"手动选择 | {used_gb:.1f}G/{cap_gb:.0f}G ({usage_pct:.1f}%)"

    proxy_names = [p['name'] for p in all_nodes]

    proxy_groups = [{
        'name': display_name,
        'type': 'select',
        'proxies': proxy_names,
    }]

    config = {
        'mixed-port': 7890,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '0.0.0.0:9090',
        'proxies': all_nodes,
        'proxy-groups': proxy_groups,
        'rules': ['MATCH,' + display_name],
    }

    output_path = os.path.join(WORKSPACE, '1992.yaml')
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(f"# Updated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Traffic: {used_gb:.1f}G / {cap_gb:.0f}G ({usage_pct:.1f}%)\n")
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False, width=200)

    print(f"\nGenerated: {len(all_nodes)} nodes -> {output_path}")
    print(f"Traffic: {used_gb:.1f}G / {cap_gb:.0f}G ({usage_pct:.1f}%)")

    os.chdir(WORKSPACE)
    os.system("git add 1992.yaml")
    ret = os.system(f"git commit -m 'Auto-update: {len(all_nodes)} nodes, {used_gb:.1f}G/{cap_gb:.0f}G traffic'")
    if ret == 0:
        os.system("git push")
        print("Pushed to GitHub")
    else:
        print("No changes to commit")

if __name__ == '__main__':
    main()
