#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
blocklist.py — 节点黑名单过滤

在 merge.py 的节点清洗层调用, 源头剔除黑名单节点。
由于 filter 作用在 all_nodes 上, 下游所有产物 (clash.yaml / nodes.txt /
base64.txt / meta.json / index.html) 自动干净, 策略组也不会出现悬空引用。

用法:
    from blocklist import is_blocked, filter_nodes

    all_nodes = filter_nodes(all_nodes)

配置:
    BLOCKLIST 常量 — 子串匹配(小写), 命中即丢
    也可用环境变量 BLOCK_EXTRA 追加, 逗号分隔
"""

import os
import re

# ------------------------------------------------------------------
# 黑名单: 子串匹配, 大小写不敏感
# 命中节点名 (name) 或主机名 (host) 任一即整条丢弃
# ------------------------------------------------------------------
BLOCKLIST = [
    'mugen',
    'bestcf',
    '6bnw.top',
]

# 正则模式(可选, 优先级高于子串), 写在 BLOCK_REGEX 里
BLOCK_REGEX = [
    # r'^mugen\d+\..*$',
    # r'^bestcf\..*$',
]

# 是否同时匹配 host 字段(默认开启)
MATCH_HOST = True


def _extra():
    """从环境变量追加关键字"""
    v = os.environ.get('BLOCK_EXTRA', '').strip()
    if not v:
        return []
    return [s.strip().lower() for s in v.split(',') if s.strip()]


def _patterns():
    return [s.lower() for s in BLOCKLIST if s] + _extra()


def _regexes():
    out = []
    for r in BLOCK_REGEX:
        try:
            out.append(re.compile(r, re.I))
        except re.error:
            pass
    return out


def is_blocked(name, host=''):
    """
    判断单个节点是否命中黑名单。
    name: 节点显示名
    host: 节点主机 (server), 可选
    """
    n = str(name or '').strip()
    h = str(host or '').strip()
    cand = [n.lower()]
    if MATCH_HOST and h:
        cand.append(h.lower())

    for p in _patterns():
        for c in cand:
            if p in c:
                return True
    for rx in _regexes():
        for c in cand:
            if rx.search(c):
                return True
    return False


def filter_nodes(nodes, verbose=True):
    """
    过滤节点列表。nodes 为 dict 列表 (需含 'name' / 'host' 键)。
    返回过滤后的列表。
    """
    kept, dropped = [], []
    for n in nodes:
        if is_blocked(n.get('name'), n.get('host', '')):
            dropped.append(n.get('name', '?'))
        else:
            kept.append(n)

    if verbose and dropped:
        print(f'  [blocklist] 剔除 {len(dropped)} 个节点: {dropped}', flush=True)
    elif verbose:
        print('  [blocklist] 无节点命中黑名单', flush=True)
    return kept


def filter_names(names):
    """只过滤名字列表(用于其它产物)"""
    return [n for n in names if not is_blocked(n)]


if __name__ == '__main__':
    # 自测
    tests = [
        ('mugen11.6bnw.top', 'mugen11.6bnw.top', True),
        ('mugen44.6bnw.top', '', True),
        ('bestcf.top', 'bestcf.top', True),
        ('🇺🇸美国01 | 电信联通推荐-0.1倍', 'us1.aiopen.sbs', False),
        ('', 'mugen33.6bnw.top', True),      # 仅 host 命中
        ('🇯🇵日本东京01', 'jp.example.com', False),
    ]
    ok = True
    for name, host, want in tests:
        got = is_blocked(name, host)
        flag = '✅' if got == want else '❌'
        if got != want:
            ok = False
        print(f'  {flag} is_blocked({name!r}, {host!r}) = {got}')
    print('\n全部通过' if ok else '\n有失败')
