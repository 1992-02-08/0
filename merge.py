#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""订阅合并器：抓取 -> 解析 -> 去提示词 -> 去重 -> 测速排序 -> 输出"""
import base64, json, os, re, sys, time, socket, ssl
import urllib.parse as up
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(ROOT, 'raw')
OUT = os.path.join(ROOT, 'out')
os.makedirs(RAW, exist_ok=True)
os.makedirs(OUT, exist_ok=True)

# ---------------- 订阅源 ----------------
SOURCES = [
    ("DZT",  "https://api6.nimenshishangdi.cc/dazhutou/1ddd08c00b96f662a1b8cddee019f41e"),
    ("KNJC", "https://dash.knjc.cfd/api/v1/client/subscribe?token=780d32c6a5fec66192b046685af32c4d"),
    ("PQJC", "https://dash.pqjc.site/api/v1/pq/61c22bd6d8c7bcc810c1906cf612bfd9"),
    ("LX",   "https://liangxin.xyz/api/v1/liangxin?OwO=8cc0726e490d8757ac48d86878f1797c"),
]

# 需要剔除的提示词/广告关键词
PROMPT_WORDS = [
    '剩余流量', '套餐到期', '到期时间', '距离下次重置', '重置剩余', '过期时间',
    '订阅地址', '订阅链接', '订阅失效', '请重新', '重新复制', '复制导入', '导入失败',
    '官网', '官方网址', '客服', '群组', '电报', 'telegram', 't.me', 'tg频道',
    '购买', '续费', '续期', '充值', '机场', '本订阅', '禁止', '节点异常', '无法使用',
    '更新订阅', '获取订阅', '点击', '访问', '网址', '防失联', '备用', '公告', '通知',
    '流量：', '流量:', '剩余：', '剩余:', 'Expire', 'Traffic', 'Website', 'Subscribe',
    '剩余', '流量', '到期', '重置',
]
PROMPT_RE = re.compile('|'.join(re.escape(w) for w in PROMPT_WORDS), re.I)

# 全局无意义节点名（整条丢弃，通常是服务端模板占位）
DROP_IF_MATCH = [
    '订阅地址失效', '请重新复制导入', '订阅已失效', '订阅失效', '请更新订阅',
    '节点已过期', '过期请续费', '剩余流量', '套餐到期', '长期有效',
]


def log(*a):
    print(*a, flush=True)


def fetch_all():
    """抓取所有订阅（curl 子进程，带重试与 UA）"""
    import subprocess
    # 注意：不能用 clash/v2rayNG 之类 UA，服务端会返回 Clash YAML 配置而非 base64 节点
    ua = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
          '(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36')
    for tag, url in SOURCES:
        path = os.path.join(RAW, tag + '.txt')
        ok = False
        for attempt in range(3):
            cmd = ['curl', '-sL', '--http1.1', '-m', '40', '-A', ua,
                   '-H', 'Accept: */*', '-o', path, '-w', '%{http_code}', url]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                code = r.stdout.strip()
            except Exception as e:
                code = 'ERR:' + str(e)
            size = os.path.getsize(path) if os.path.exists(path) else 0
            log(f'  [{tag}] try{attempt+1} http={code} size={size}')
            if code == '200' and size > 100:
                ok = True
                break
            time.sleep(2)
        if not ok:
            log(f'  !! [{tag}] 抓取失败')
    return


def b64d(s):
    s = s.strip().replace('\n', '').replace('\r', '')
    s = s.replace('-', '+').replace('_', '/')
    s += '=' * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode('utf-8', 'ignore')
    except Exception:
        return ''


def decode_sub(path):
    """订阅文件 -> 节点行列表；自动识别 base64 / 明文 / Clash-YAML"""
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        body = f.read().strip()
    if not body:
        return []
    # Clash / YAML 配置：服务端按 UA 返回的，需要走 clash 解析
    head = body[:400]
    if re.search(r'^\s*(mixed-port|port|proxies|proxy-groups|rules)\s*:', head, re.M):
        return parse_clash_yaml(body)
    if body.lstrip().startswith(('{', '[')):
        return parse_clash_json(body)
    txt = b64d(body)
    if '://' not in txt:
        txt = body
    return [l.strip() for l in txt.splitlines() if '://' in l]


def _clash_proxy_to_uri(p):
    """Clash proxy dict -> 分享链接（仅覆盖常见协议）"""
    t = (p.get('type') or '').lower()
    name = str(p.get('name', ''))
    host = str(p.get('server', ''))
    port = str(p.get('port', ''))
    frag = '#' + up.quote(name, safe='')
    q = []

    def add(k, v, default=None):
        if v is None or v == '' or v == default:
            return
        q.append('%s=%s' % (k, up.quote(str(v), safe='')))

    if t == 'vmess':
        j = {'v': '2', 'ps': name, 'add': host, 'port': port,
             'id': p.get('uuid', ''), 'aid': str(p.get('alterId', 0)),
             'scy': p.get('cipher', 'auto'), 'net': p.get('network', 'tcp'),
             'type': 'none', 'host': p.get('ws-opts', {}).get('headers', {}).get('Host', '')
             if isinstance(p.get('ws-opts'), dict) else '',
             'path': p.get('ws-opts', {}).get('path', '')
             if isinstance(p.get('ws-opts'), dict) else '',
             'tls': 'tls' if p.get('tls') else '',
             'sni': p.get('servername', '')}
        return 'vmess://' + base64.b64encode(
            json.dumps(j, ensure_ascii=False).encode()).decode()

    if t == 'vless':
        add('type', p.get('network', 'tcp'), 'tcp')
        add('encryption', 'none')
        add('security', 'tls' if p.get('tls') else 'none')
        add('flow', p.get('flow'))
        add('sni', p.get('servername'))
        add('fp', p.get('client-fingerprint'))
        if p.get('reality-opts'):
            ro = p['reality-opts']
            add('pbk', ro.get('public-key'))
            add('sid', ro.get('short-id'))
        ws = p.get('ws-opts') or {}
        if ws:
            add('host', (ws.get('headers') or {}).get('Host'))
            add('path', ws.get('path'))
        return 'vless://%s@%s:%s?%s%s' % (p.get('uuid', ''), host, port, '&'.join(q), frag)

    if t in ('hysteria2', 'hy2'):
        add('sni', p.get('sni'))
        add('insecure', '1' if p.get('skip-cert-verify') else '0')
        obfs = p.get('obfs')
        if obfs:
            add('obfs', obfs)
            add('obfs-password', p.get('obfs-password'))
        auth = p.get('password') or p.get('auth') or ''
        return 'hysteria2://%s@%s:%s/?%s%s' % (auth, host, port, '&'.join(q), frag)

    if t == 'trojan':
        add('sni', p.get('sni'))
        add('type', p.get('network', 'tcp'), 'tcp')
        return 'trojan://%s@%s:%s?%s%s' % (p.get('password', ''), host, port, '&'.join(q), frag)

    if t == 'ss':
        userinfo = base64.b64encode(
            ('%s:%s' % (p.get('cipher', ''), p.get('password', ''))).encode()).decode()
        return 'ss://%s@%s:%s%s' % (userinfo, host, port, frag)

    if t == 'anytls':
        add('sni', p.get('sni'))
        add('insecure', '1' if p.get('skip-cert-verify') else '0')
        return 'anytls://%s@%s:%s?%s%s' % (p.get('password', ''), host, port,
                                           '&'.join(q), frag)
    return ''


def parse_clash_yaml(body):
    out = []
    try:
        import yaml
        data = yaml.safe_load(body)
        proxies = (data or {}).get('proxies') or []
    except Exception:
        import subprocess
        r = subprocess.run(['yq', '-o=json', '.proxies', '-'],
                           input=body, capture_output=True, text=True)
        proxies = json.loads(r.stdout) if r.stdout.strip() not in ('', 'null') else []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        u = _clash_proxy_to_uri(p)
        if u:
            out.append(u)
    return out


def parse_clash_json(body):
    try:
        data = json.loads(body)
    except Exception:
        return []
    out = []
    for p in (data.get('proxies') or []):
        u = _clash_proxy_to_uri(p) if isinstance(p, dict) else ''
        if u:
            out.append(u)
    return out


def clean_tag(tag):
    """清理节点名：去提示词、去 emoji 残留空格"""
    t = up.unquote(tag).strip()
    t = PROMPT_RE.sub('', t)
    t = re.sub(r'[|｜]{2,}', '|', t)
    t = re.sub(r'^[|｜\-\s:：,，]+', '', t)
    t = re.sub(r'[|｜\-\s:：,，]+$', '', t)
    t = re.sub(r'\(\s*\)|（\s*）', '', t)
    t = re.sub(r'\s{2,}', ' ', t).strip()
    return t


def drop_node(tag):
    """整条丢弃：名字完全由提示词构成"""
    t = up.unquote(tag).strip()
    return any(d in t for d in DROP_IF_MATCH)


def parse_node(line):
    """返回 dict: proto, key(去重), name, host, port, raw"""
    if line.startswith('JSON:'):
        return None
    proto = line.split('://', 1)[0].lower()
    rest = line.split('://', 1)[1]
    name = ''
    if '#' in rest:
        rest, name = rest.split('#', 1)
    if proto == 'vmess':
        try:
            j = json.loads(b64d(rest))
        except Exception:
            return None
        host = str(j.get('add', ''))
        port = str(j.get('port', ''))
        key = 'vmess|%s|%s|%s|%s|%s|%s' % (j.get('id'), host, port,
                                           j.get('net'), j.get('path'), j.get('sni') or j.get('host'))
        return {'proto': proto, 'name': name, 'host': host, 'port': port,
                'key': key, 'raw': line}
    # 通用: proto://userinfo@host:port?params
    q = ''
    if '?' in rest:
        rest, q = rest.split('?', 1)
    host, port = '', ''
    if '@' in rest:
        ui, hp = rest.rsplit('@', 1)
    else:
        ui, hp = '', rest
    if hp.startswith('['):
        m = re.match(r'\[(.*?)\]:(\d+)', hp)
        if m:
            host, port = m.group(1), m.group(2)
    else:
        m = re.match(r'(.*?):(\d+)$', hp)
        if m:
            host, port = m.group(1), m.group(2)
        else:
            host = hp
    # 去重 key：协议+凭据+地址+端口+关键参数（忽略节点名）
    keys = []
    for kv in q.split('&'):
        if not kv:
            continue
        k = kv.split('=')[0].lower()
        if k in ('sni', 'servername', 'host', 'path', 'pbk', 'sid', 'flow',
                 'type', 'security', 'encryption', 'mport', 'pinSHA256',
                 'insecure', 'mode', 'headerType', 'serviceName', 'fp'):
            keys.append(kv)
    key = '|'.join([proto, ui, host, port] + sorted(keys))
    return {'proto': proto, 'name': name, 'host': host, 'port': port,
            'key': key, 'raw': line}


def tcp_test(host, port, timeout=3.0):
    """多轮 TCP 握手取中位数(ms)，失败返回 None"""
    if not host or not port:
        return None
    lats = []
    for _ in range(3):
        t0 = time.time()
        try:
            with socket.create_connection((host, int(port)), timeout=timeout):
                lats.append((time.time() - t0) * 1000)
        except Exception:
            pass
        time.sleep(0.05)
    if not lats:
        return None
    lats.sort()
    return int(lats[len(lats) // 2])


def main():
    log('== 1. 抓取订阅 ==')
    fetch_all()

    log('== 2. 解析与清洗 ==')
    all_nodes, seen = [], set()
    stat = {}
    for tag, _ in SOURCES:
        p = os.path.join(RAW, tag + '.txt')
        if not os.path.exists(p):
            continue
        lines = decode_sub(p)
        kept = 0
        for l in lines:
            n = parse_node(l)
            if not n:
                continue
            if drop_node(n['name']):
                continue
            newname = clean_tag(n['name']) or n['host']
            if not newname:
                continue
            n['name'] = newname
            n['src'] = tag
            if n['key'] in seen:
                continue
            seen.add(n['key'])
            all_nodes.append(n)
            kept += 1
        stat[tag] = (len(lines), kept)
        log(f'  {tag}: 原始 {len(lines)} -> 保留 {kept}')
    log(f'  合计去重后: {len(all_nodes)}')

    # 名称冲突加来源后缀
    from collections import Counter
    c = Counter(n['name'] for n in all_nodes)
    for n in all_nodes:
        if c[n['name']] > 1:
            n['name'] = f"{n['name']} [{n['src']}]"

    log('== 3. 并发测速(TCP握手延迟) ==')
    results = []
    with ThreadPoolExecutor(max_workers=48) as ex:
        futs = {ex.submit(tcp_test, n['host'], n['port']): n for n in all_nodes}
        for f in as_completed(futs):
            n = futs[f]
            try:
                n['latency'] = f.result()
            except Exception:
                n['latency'] = None
            results.append(n)
    alive = [n for n in results if n.get('latency') is not None]
    dead = [n for n in results if n.get('latency') is None]
    log(f'  可用 {len(alive)} / 不可用 {len(dead)}')
    alive.sort(key=lambda x: x['latency'])

    # 输出
    now = time.strftime('%Y-%m-%d %H:%M:%S')
    ordered = alive + dead
    plain = '\n'.join(n['raw'].split('#')[0] + '#' + up.quote(n['name'], safe='') for n in ordered)

    with open(os.path.join(OUT, 'nodes.txt'), 'w', encoding='utf-8') as f:
        f.write(plain + '\n')
    with open(os.path.join(OUT, 'sub.txt'), 'w', encoding='utf-8') as f:
        f.write(base64.b64encode(plain.encode('utf-8')).decode() + '\n')
    with open(os.path.join(OUT, 'nodes_meta.json'), 'w', encoding='utf-8') as f:
        json.dump({'updated': now, 'total': len(ordered), 'alive': len(alive),
                   'dead': len(dead),
                   'nodes': [{'name': n['name'], 'proto': n['proto'], 'src': n['src'],
                              'host': n['host'], 'port': n['port'],
                              'latency': n.get('latency')} for n in ordered]},
                  f, ensure_ascii=False, indent=1)
    log(f'== 4. 输出完成 -> {OUT} (共 {len(ordered)} 节点) ==')
    for n in ordered[:15]:
        log(f"   {n.get('latency')}ms  {n['name']}")


if __name__ == '__main__':
    main()
