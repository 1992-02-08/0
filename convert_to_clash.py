#!/usr/bin/env python3
import base64
import json
import re
import yaml
from urllib.parse import urlparse, parse_qs, unquote

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
            'short-id': params.get('sid', [''])[0]
        }
    elif security == 'tls':
        node['tls'] = True
        node['servername'] = params.get('sni', [params.get('host', [''])[0]])[0]
        node['client-fingerprint'] = fp
    
    if node['network'] in ('ws', 'websocket'):
        node['network'] = 'ws'
        node['ws-opts'] = {
            'path': unquote(params.get('path', ['/'])[0]),
            'headers': {'Host': params.get('host', [''])[0]}
        }
    
    return node

def parse_anytls(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    node = {
        'name': unquote(parsed.fragment) if parsed.fragment else parsed.hostname,
        'type': 'anytls',
        'server': parsed.hostname,
        'port': int(parsed.port),
        'password': parsed.username,
        'sni': params.get('sni', [''])[0],
        'skip-cert-verify': params.get('insecure', ['0'])[0] == '1',
        'udp': True,
    }
    return node

def parse_hysteria2(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    name = unquote(parsed.fragment) if parsed.fragment else parsed.hostname
    
    node = {
        'name': name,
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
            'headers': {'Host': data.get('host', '')}
        }
    
    fp = data.get('fp', '')
    if fp:
        node['client-fingerprint'] = fp
    
    if data.get('host'):
        node['servername'] = data['host']
    
    return node

def main():
    with open('subscription_raw.txt', 'r') as f:
        lines = [l.strip() for l in f if l.strip()]
    
    proxies = []
    system_keywords = ['更新订阅', '特殊时期', '如果只显示', '客户端太旧', '使用教程', '更新一下客户端', '剩余流量', '套餐到期']
    for line in lines:
        try:
            if line.startswith('vless://'):
                node = parse_vless(line)
                if any(kw in node['name'] for kw in system_keywords):
                    continue
                proxies.append(node)
            elif line.startswith('anytls://'):
                proxies.append(parse_anytls(line))
            elif line.startswith('hysteria2://'):
                proxies.append(parse_hysteria2(line))
            elif line.startswith('vmess://'):
                node = parse_vmess(line)
                if '如果只显示此节点' in node['name'] or '客户端太旧' in node['name'] or '使用教程' in node['name'] or '更新一下客户端' in node['name']:
                    continue
                proxies.append(node)
        except Exception as e:
            print(f"Skip: {line[:80]}... ({e})")
    
    proxy_names = [p['name'] for p in proxies]
    
    proxy_groups = [
        {
            'name': '手动选择',
            'type': 'select',
            'proxies': proxy_names,
        }
    ]
    
    rules = [
        'MATCH,手动选择',
    ]
    
    config = {
        'mixed-port': 7890,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '0.0.0.0:9090',
        'proxies': proxies,
        'proxy-groups': proxy_groups,
        'rules': rules,
    }
    
    with open('clash_subscription.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False, width=200)
    
    print(f'Converted {len(proxies)}/{len(lines)} nodes to Clash Meta YAML')

if __name__ == '__main__':
    main()
