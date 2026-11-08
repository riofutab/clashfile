#!/usr/bin/env python3
"""把 subconverter 生成的 Clash 规则转成 Shadowrocket 配置模板（不含节点）。

用法（在仓库根目录）: python3 -m shadowrocket.build <ini> <clash.yaml> <输出目录>
输出:
  shadowrocket.json        [General]/[Host] 文本与策略组；策略组带 "$items"，由 Worker 按实际节点名展开
  shadowrocket-rules.conf  [Rule] 段原文，Worker 原样拼在后面，不解析（省 CPU）

节点不写进配置：Shadowrocket 的节点来自首页订阅（famsub 回 base64），策略组按节点名引用它们。
"""
import json
import sys
import urllib.request
from pathlib import Path

from singbox.build import parse_clash_rules, parse_groups

# Shadowrocket 认的规则类型，原样输出（含 no-resolve 等尾参数）
PASS_THROUGH = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD', 'IP-CIDR', 'IP-CIDR6',
                'IP-ASN', 'GEOIP', 'DST-PORT', 'USER-AGENT', 'URL-REGEX'}
# Shadowrocket 不支持 GEOSITE。小集合在构建时展开成域名规则；这两个太大（11 万、2.7 万域名），
# 改用 Loyalsoldier 按同一份 v2fly 数据生成的 Surge DOMAIN-SET
REMOTE_GEOSITE = {
    'cn': 'https://fastly.jsdelivr.net/gh/Loyalsoldier/surge-rules@release/direct.txt',
    'geolocation-!cn': 'https://fastly.jsdelivr.net/gh/Loyalsoldier/surge-rules@release/proxy.txt',
}
GEOSITE_URL = 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/{name}.list'
# 超过这个数就不该内联了，构建失败，提示改进 REMOTE_GEOSITE
MAX_INLINE_GEOSITE = 20000
# 与 GeneralClashConfig_FakeIP.yml 的 rule-providers 对应，名字必须一致
PROVIDERS = {
    'reject-domainset': ['DOMAIN-SET', 'https://ruleset.skk.moe/List/domainset/reject.conf'],
}
USER_AGENT = 'clashfile-shadowrocket/1.0'
BUILTIN_POLICIES = {'DIRECT', 'REJECT'}

# 对应 Clash 模板：局域网/私网不进 TUN 也不走代理；公司内网域名用内网 DNS（会解析出私网地址）
# block-quic：走代理的 QUIC 直接拒绝，让浏览器和 App 立即改用 TCP。不加时每个新站点第一次打开
#   都可能要等 QUIC 超时才退回 TCP（2026-11-08 反馈首次打开明显慢于 Stash，节点相同）
LAN = '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,169.254.0.0/16,100.64.0.0/10'
HEAD = f"""[General]
ipv6 = false
prefer-ipv6 = false
dns-server = https://dns.alidns.com/dns-query,https://doh.pub/dns-query,223.5.5.5,119.29.29.29
fallback-dns-server = system
private-ip-answer = true
dns-direct-fallback-proxy = true
block-quic = all-proxy
skip-proxy = {LAN},localhost,*.local,captive.apple.com
tun-excluded-routes = {LAN},224.0.0.0/4,255.255.255.255/32

[Host]
*.teamway.com = server:10.0.60.4

"""


def fetch_geosite(name):
    req = urllib.request.Request(GEOSITE_URL.format(name=name), headers={'User-Agent': USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode('utf-8').splitlines()


def geosite_rules(name, lines, tail):
    """MetaCubeX 文本格式：+.example.com 是后缀，example.com 是完整域名。"""
    out = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('+.'):
            out.append(['DOMAIN-SUFFIX', line[2:], *tail])
        else:
            out.append(['DOMAIN', line, *tail])
    if not out:
        raise SystemExit(f'GEOSITE {name} 是空的，多半是下载出错')
    if len(out) > MAX_INLINE_GEOSITE:
        raise SystemExit(f'GEOSITE {name} 有 {len(out)} 条，太大不能内联，在 REMOTE_GEOSITE 里给它配远程规则集')
    return out


def convert_rules(clash_rules, load_geosite):
    """逐条转换并保持顺序。返回 Shadowrocket 规则行、最终策略和跳过的类型计数。"""
    out, skipped, final = [], {}, None
    for parts in clash_rules:
        kind = parts[0]
        if kind == 'MATCH':
            final = parts[1]
            continue
        tail = parts[2:]  # 目标策略及 no-resolve 等参数
        if kind in PASS_THROUGH:
            out.append(parts)
        elif kind == 'GEOSITE':
            name = parts[1].lower()
            if name in REMOTE_GEOSITE:
                out.append(['DOMAIN-SET', REMOTE_GEOSITE[name], *tail])
            else:
                out.extend(geosite_rules(name, load_geosite(name), tail))
        elif kind == 'RULE-SET':
            if parts[1] not in PROVIDERS:
                raise SystemExit(f'RULE-SET {parts[1]} 没有对应的 Shadowrocket 规则集，先在 PROVIDERS 里加上')
            out.append([*PROVIDERS[parts[1]], *tail])
        else:
            # PROCESS-NAME 等：iOS 拿不到进程信息；SRC-PORT：Shadowrocket 不支持
            skipped[kind] = skipped.get(kind, 0) + 1
    if final is None:
        raise SystemExit('Clash 规则里没有 MATCH，生成的配置会缺少 FINAL')
    return out, final, skipped


def proxy_groups(groups):
    out = []
    for g in groups:
        if g['kind'] != 'select':
            raise SystemExit(f"策略组类型 {g['kind']}（{g['name']}）还没有对应的 Shadowrocket 写法")
        out.append({'tag': g['name'], '$items': g['items']})
    return out


def check_policies(rules, final, groups):
    """Shadowrocket 遇到未定义的策略不会报错，只会让规则失效，所以在构建时拦下。"""
    known = BUILTIN_POLICIES | {g['tag'] for g in groups}
    unknown = sorted({r[2] for r in rules} - known | ({final} - known))
    if unknown:
        raise SystemExit(f'规则引用了未定义的策略组：{unknown}')


def build(ini_text, clash_text, load_geosite=fetch_geosite):
    rules, final, skipped = convert_rules(parse_clash_rules(clash_text), load_geosite)
    head = {'head': HEAD, 'groups': proxy_groups(parse_groups(ini_text))}
    check_policies(rules, final, head['groups'])
    rules_text = '[Rule]\n' + ''.join(','.join(r) + '\n' for r in rules) + f'FINAL,{final}\n'
    return head, rules_text, len(rules), skipped


def main():
    ini_path, clash_path, out_dir = sys.argv[1:4]
    head, rules_text, n, skipped = build(Path(ini_path).read_text(encoding='utf-8'),
                                         Path(clash_path).read_text(encoding='utf-8'))
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'shadowrocket.json').write_text(json.dumps(head, ensure_ascii=False, indent=1), encoding='utf-8')
    (out / 'shadowrocket-rules.conf').write_text(rules_text, encoding='utf-8')
    print(f'Shadowrocket 规则 {n} 条，策略组 {len(head["groups"])} 个，跳过 {skipped or "无"}')


if __name__ == '__main__':
    main()
