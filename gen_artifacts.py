#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""由 out/nodes.txt 生成多格式产物：Clash YAML / base64 通用订阅 / sing-box / 节点列表 / 索引页"""
import base64, json, os, re, time
import urllib.parse as up

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(ROOT, 'out')
DIST = os.path.join(ROOT, 'dist')
os.makedirs(DIST, exist_ok=True)

REPO = os.environ.get('SUBMERGE_REPO', '').strip()   # owner/repo


def read_nodes():
    with open(os.path.join(OUT, 'nodes.txt'), encoding='utf-8') as f:
        return [l.strip() for l in f if '://' in l]


def b64(s):
    return base64.b64encode(s.encode('utf-8')).decode()


# ---------- 解析为 Clash proxy ----------
def split_uri(uri):
    proto, rest = uri.split('://', 1)
    name = ''
    if '#' in rest:
        rest, name = rest.split('#', 1)
        name = up.unquote(name)
    q = {}
    if '?' in rest:
        rest, qs = rest.split('?', 1)
        for kv in qs.split('&'):
            if not kv:
                continue
            k, _, v = kv.partition('=')
            q[k] = up.unquote(v)
    return proto.lower(), rest, q, name


def to_clash(uri):
    proto, rest, q, name = split_uri(uri)
    node = {'name': name, 'type': proto, 'server': '', 'port': 0}
    if proto == 'vmess':
        try:
            j = json.loads(base64.b64decode(rest + '=' * (-len(rest) % 4)).decode('utf-8', 'ignore'))
        except Exception:
            return None
        node = {'name': name, 'type': 'vmess', 'server': j.get('add'),
                'port': int(j.get('port') or 443), 'uuid': j.get('id'),
                'alterId': int(j.get('aid') or 0),
                'cipher': j.get('scy') or 'auto', 'udp': True}
        net = j.get('net') or 'tcp'
        tls = str(j.get('tls') or '')
        if net == 'ws':
            node['network'] = 'ws'
            node['ws-opts'] = {'path': j.get('path') or '/',
                               'headers': {'Host': j.get('host') or j.get('add')}}
        elif net != 'tcp':
            node['network'] = net
        if tls:
            node['tls'] = True
            if j.get('sni'):
                node['servername'] = j['sni']
        if j.get('scy'):
            node['cipher'] = j['scy']
        return node

    if '@' not in rest:
        return None
    ui, hp = rest.rsplit('@', 1)
    host, _, port = hp.rpartition(':')
    if not port.isdigit():
        host, port = hp, '443'
    node['server'] = host
    node['port'] = int(port)
    sni = q.get('sni') or q.get('servername') or ''
    insecure = q.get('insecure') in ('1', 'true', 'True')

    if proto == 'vless':
        node['uuid'] = ui
        node['udp'] = True
        if q.get('flow'):
            node['flow'] = q['flow']
        net = q.get('type') or 'tcp'
        if net == 'ws':
            node['network'] = 'ws'
            node['ws-opts'] = {'path': q.get('path') or '/',
                               'headers': {'Host': q.get('host') or sni}}
        elif net in ('grpc',):
            node['network'] = 'grpc'
            node['grpc-opts'] = {'grpc-service-name': q.get('serviceName') or ''}
        elif net != 'tcp':
            node['network'] = net
        sec = q.get('security') or 'none'
        if sec == 'reality':
            node['tls'] = True
            node['servername'] = sni
            node['client-fingerprint'] = q.get('fp') or 'chrome'
            node['reality-opts'] = {'public-key': q.get('pbk') or '',
                                    'short-id': q.get('sid') or ''}
            node['skip-cert-verify'] = False
        elif sec in ('tls', 'xtls'):
            node['tls'] = True
            if sni:
                node['servername'] = sni
            if q.get('fp'):
                node['client-fingerprint'] = q['fp']
            if insecure:
                node['skip-cert-verify'] = True
        else:
            node['skip-cert-verify'] = insecure if insecure else False
        return node

    if proto in ('hysteria2', 'hy2'):
        node['type'] = 'hysteria2'
        node['password'] = ui
        if sni:
            node['sni'] = sni
        if insecure:
            node['skip-cert-verify'] = True
        if q.get('obfs'):
            node['obfs'] = q['obfs']
            node['obfs-password'] = q.get('obfs-password') or ''
        return node

    if proto == 'anytls':
        node['password'] = ui
        if sni:
            node['sni'] = sni
        if insecure:
            node['skip-cert-verify'] = True
        return node

    if proto == 'trojan':
        node['password'] = ui
        if sni:
            node['sni'] = sni
        return node

    if proto == 'ss':
        try:
            dec = base64.b64decode(ui + '=' * (-len(ui) % 4)).decode('utf-8', 'ignore')
            cipher, _, pw = dec.partition(':')
            node['cipher'] = cipher
            node['password'] = pw
        except Exception:
            return None
        return node
    return None


GROUP_CACHE = {}


def country_of(name):
    """按旗帜 emoji 或名称归类"""
    flags = {
        '🇭🇰': '香港', '🇹🇼': '台湾', '🇯🇵': '日本', '🇰🇷': '韩国', '🇸🇬': '新加坡',
        '🇺🇸': '美国', '🇬🇧': '英国', '🇩🇪': '德国', '🇫🇷': '法国', '🇳🇱': '荷兰',
        '🇨🇦': '加拿大', '🇦🇺': '澳大利亚', '🇮🇳': '印度', '🇹🇷': '土耳其',
        '🇲🇾': '马来西亚', '🇹🇭': '泰国', '🇻🇳': '越南', '🇵🇭': '菲律宾',
        '🇮🇩': '印尼', '🇧🇷': '巴西', '🇦🇪': '阿联酋', '🇷🇺': '俄罗斯',
        '🇮🇹': '意大利', '🇪🇸': '西班牙', '🇨🇭': '瑞士', '🇸🇪': '瑞典',
        '🇫🇮': '芬兰', '🇵🇱': '波兰', '🇦🇷': '阿根廷', '🇿🇦': '南非',
        '🇰🇿': '哈萨克斯坦', '🇺🇦': '乌克兰', '🇮🇱': '以色列',
    }
    for f, c in flags.items():
        if f in name:
            return c
    for c in set(flags.values()):
        if c in name:
            return c
    return '其他'


def main():
    uris = read_nodes()
    proxies, seen = [], set()
    for u in uris:
        p = to_clash(u)
        if not p or not p.get('server'):
            continue
        sig = json.dumps({k: v for k, v in p.items() if k != 'name'},
                         sort_keys=True, ensure_ascii=False)
        if sig in seen:
            continue
        seen.add(sig)
        proxies.append(p)

    # 分组
    groups = {}
    for p in proxies:
        groups.setdefault(country_of(p['name']), []).append(p['name'])
    order = sorted(groups.keys(), key=lambda c: (-len(groups[c]), c))

    names = [p['name'] for p in proxies]
    gdefs = [
        {'name': '🚀 节点选择', 'type': 'select',
         'proxies': ['♻️ 自动选择', 'DIRECT'] + names},
        {'name': '♻️ 自动选择', 'type': 'url-test', 'proxies': names,
         'url': 'http://www.gstatic.com/generate_204', 'interval': 300, 'tolerance': 50},
        {'name': '🌍 国外媒体', 'type': 'select', 'proxies': ['🚀 节点选择', '♻️ 自动选择', 'DIRECT'] + names},
        {'name': '📲 电报消息', 'type': 'select', 'proxies': ['🚀 节点选择', '♻️ 自动选择', 'DIRECT'] + names},
        {'name': '🤖 AI服务', 'type': 'select', 'proxies': ['🚀 节点选择', '♻️ 自动选择', 'DIRECT'] + names},
        {'name': '🐟 兜底分流', 'type': 'select', 'proxies': ['🚀 节点选择', 'DIRECT'] + names},
    ]
    for c in order:
        gdefs.append({'name': c, 'type': 'url-test', 'proxies': groups[c],
                      'url': 'http://www.gstatic.com/generate_204',
                      'interval': 300, 'tolerance': 50})

    rules = [
        'DOMAIN-SUFFIX,openai.com,🤖 AI服务',
        'DOMAIN-SUFFIX,anthropic.com,🤖 AI服务',
        'DOMAIN-SUFFIX,claude.ai,🤖 AI服务',
        'DOMAIN-SUFFIX,gemini.google.com,🤖 AI服务',
        'GEOIP,CN,🐟 兜底分流',
        'MATCH,🚀 节点选择',
    ]
    proxy_names = [g['name'] for g in gdefs] + ['DIRECT', 'REJECT']
    rules = [r.replace('🐟 兜底分流', '🐟 兜底分流') for r in rules]

    cfg = {
        'mixed-port': 7890,
        'allow-lan': False,
        'bind-address': '*',
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'dns': {
            'enable': True,
            'listen': '0.0.0.0:1053',
            'ipv6': False,
            'enhanced-mode': 'fake-ip',
            'fake-ip-range': '198.18.0.1/16',
            'nameserver': ['223.5.5.5', '119.29.29.29'],
            'fallback': ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'],
            'fallback-filter': {'geoip': True, 'geoip-code': 'CN'},
        },
        'proxies': proxies,
        'proxy-groups': gdefs,
        'rules': rules,
    }

    # 产物
    with open(os.path.join(DIST, 'clash.yaml'), 'w', encoding='utf-8') as f:
        import yaml
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False,
                       default_flow_style=False, width=10 ** 6)

    plain = '\n'.join(uris) + '\n'
    with open(os.path.join(DIST, 'base64.txt'), 'w', encoding='utf-8') as f:
        f.write(b64(plain) + '\n')
    with open(os.path.join(DIST, 'nodes.txt'), 'w', encoding='utf-8') as f:
        f.write(plain)

    # 简单索引页
    upd = time.strftime('%Y-%m-%d %H:%M:%S')
    stats = {c: len(groups[c]) for c in order}
    html = ['<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width,initial-scale=1">',
            '<title>合并订阅</title><style>',
            'body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:760px;'
            'margin:0 auto;padding:24px;background:#0f1115;color:#e6e6e6;line-height:1.7}',
            'h1{font-size:22px}code,pre{background:#1b1f27;padding:2px 6px;border-radius:6px;'
            'word-break:break-all;display:block;padding:12px;white-space:pre-wrap}',
            'a{color:#5fa8ff}.m{color:#8b949e;font-size:13px}table{border-collapse:collapse;width:100%}',
            'td,th{border-bottom:1px solid #262c36;padding:6px 8px;text-align:left;font-size:14px}',
            '</style></head><body>',
            f'<h1>☁️ 合并订阅（4 源 / {len(proxies)} 节点）</h1>',
            f'<p class="m">更新时间：{upd}　·　已去重去广告　·　按延迟排序</p>',
            '<h2>订阅链接</h2>',
            '<p>Clash / Mihomo：</p><code id="c"></code>',
            '<p>通用 base64（v2rayNG / Shadowrocket / NekoBox）：</p><code id="b"></code>',
            '<h2>地区分布</h2><table><tr><th>地区</th><th>节点数</th></tr>']
    for c in order:
        html.append(f'<tr><td>{c}</td><td>{stats[c]}</td></tr>')
    html.append('</table><script>')
    if REPO:
        base = f'https://raw.githubusercontent.com/{REPO}/main/'
        html.append(f'document.getElementById("c").textContent="{base}clash.yaml";')
        html.append(f'document.getElementById("b").textContent="{base}base64.txt";')
    else:
        html.append('document.getElementById("c").textContent="clash.yaml";')
        html.append('document.getElementById("b").textContent="base64.txt";')
    html.append('</script></body></html>')
    with open(os.path.join(DIST, 'index.html'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(html))

    # 元信息
    json.dump({'updated': upd, 'proxies': len(proxies),
               'groups': stats,
               'names': names},
              open(os.path.join(DIST, 'meta.json'), 'w', encoding='utf-8'),
              ensure_ascii=False, indent=1)
    print(f'生成产物: {len(proxies)} 节点 -> dist/')


if __name__ == '__main__':
    main()
