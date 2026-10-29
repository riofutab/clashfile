#!/usr/bin/env python3
"""把 subconverter 生成的 Clash 规则转成 sing-box 1.14 配置模板（不含节点）。

用法: build.py <ini> <clash.yaml> <输出目录>
  ini        ACL4SSR 配置（取策略组定义：名字正则在 Worker 里按实际节点展开）
  clash.yaml subconverter 用同一份 ini 生成的 Clash 配置（取已展开的逐条规则）
输出:
  base.json  除 route.rules 外的完整配置；策略组带 "$items"，由 Worker 展开后删掉
  rules.json route.rules 数组，Worker 原样拼进 base.json，不解析（省 CPU）

为什么不用 subconverter 的 sing-box 输出：它把同一目标的相邻规则合并成一条，
domain 和 process_name 落进同一条规则。sing-box 里这两类条件是「且」，
手机上拿不到进程名，整条规则永远不命中。这里只合并「或」关系的字段。
"""
import json
import re
import sys
from pathlib import Path

# 同属 sing-box 默认规则的第一组条件，组内为「或」，可以合并进同一条规则
ADDR_FIELDS = {
    'DOMAIN': 'domain',
    'DOMAIN-SUFFIX': 'domain_suffix',
    'DOMAIN-KEYWORD': 'domain_keyword',
    'DOMAIN-REGEX': 'domain_regex',
    'IP-CIDR': 'ip_cidr',
    'IP-CIDR6': 'ip_cidr',
}
# 与第一组是「且」关系，必须各自成规则
OTHER_FIELDS = {
    'PROCESS-NAME': 'process_name',
    'PROCESS-PATH': 'process_path',
    'SRC-IP-CIDR': 'source_ip_cidr',
    'SRC-PORT': 'source_port',
    'DST-PORT': 'port',
}
PORT_FIELDS = {'source_port', 'port'}

GEO_URL = 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/{kind}/{name}.srs'
# 与 GeneralClashConfig_FakeIP.yml 的 rule-providers 一一对应，名字必须一致
PROVIDERS = {
    'reject-domainset': {
        'type': 'remote', 'tag': 'reject-domainset', 'format': 'source',
        'url': 'https://ruleset.skk.moe/sing-box/domainset/reject.json',
        'download_detour': '🚀 节点选择', 'update_interval': '1d',
    },
}
MAIN_GROUP = '🚀 节点选择'
FINAL_FALLBACK = 'DIRECT'


def parse_groups(ini_text):
    """custom_proxy_group=名字`类型`项…；[]X 是引用，其余是节点名正则。"""
    groups = []
    for line in ini_text.splitlines():
        if not line.startswith('custom_proxy_group='):
            continue
        parts = line[len('custom_proxy_group='):].split('`')
        name, kind, items = parts[0], parts[1], parts[2:]
        group = {'name': name, 'kind': kind}
        if kind in ('url-test', 'fallback', 'load-balance'):
            # 末尾两项是测速地址和「间隔,超时,容差」
            items, url, timing = items[:-2], items[-2], items[-1]
            interval, _, tolerance = (timing.split(',') + ['', '', ''])[:3]
            group.update(url=url, interval=int(interval or 300), tolerance=int(tolerance or 50))
        group['items'] = [{'ref': i[2:]} if i.startswith('[]') else {'re': i} for i in items]
        groups.append(group)
    return groups


def reject_groups(groups):
    """首项是 []REJECT 的组（广告拦截类）。sing-box 1.13 起没有 block 出站，
    选择器里放不进「拒绝」，这些组改成规则动作 reject，不再生成选择器。"""
    return {g['name'] for g in groups if g['items'] and g['items'][0] == {'ref': 'REJECT'}}


def parse_clash_rules(yaml_text):
    """只读 rules: 段，subconverter 输出是一行一条「  - 类型,值,目标[,参数]」。"""
    rules, in_rules = [], False
    for line in yaml_text.splitlines():
        if not line.startswith(' '):
            in_rules = line.rstrip() == 'rules:'
            continue
        if in_rules:
            m = re.match(r"^\s+- '?(.*?)'?\s*$", line)
            if m:
                rules.append(m.group(1).split(','))
    return rules


def wildcard_regex(pattern):
    """mihomo DOMAIN-WILDCARD：* 任意多个字符，? 单个字符，整个域名锚定。"""
    return '^' + re.escape(pattern).replace(r'\*', '.*').replace(r'\?', '.') + '$'


def target_of(name, rejects):
    if name == 'REJECT' or name in rejects:
        return {'action': 'reject'}
    return {'outbound': name}


def port_value(field, v):
    if '-' in v:
        return field + '_range', v.replace('-', ':')
    return field, int(v)


def convert_rules(clash_rules, rejects):
    """逐条转换，只把「同目标 + 可合并」的相邻规则合并，保证先匹配先生效的顺序不变。"""
    out, rule_sets, skipped = [], {}, {}
    final = FINAL_FALLBACK
    cur, cur_key = None, None

    def flush():
        nonlocal cur, cur_key
        if cur:
            out.append(cur)
        cur, cur_key = None, None

    for parts in clash_rules:
        kind = parts[0]
        if kind == 'MATCH':
            final = parts[1]
            continue
        if len(parts) < 3:
            skipped[kind] = skipped.get(kind, 0) + 1
            continue
        value, target = parts[1], parts[2]
        if kind in ADDR_FIELDS:
            field, group_key = ADDR_FIELDS[kind], 'addr'
        elif kind == 'DOMAIN-WILDCARD':
            field, value, group_key = 'domain_regex', wildcard_regex(value), 'addr'
        elif kind in OTHER_FIELDS:
            field = OTHER_FIELDS[kind]
            if field in PORT_FIELDS:
                field, value = port_value(field, value)
            group_key = field
        elif kind in ('GEOSITE', 'GEOIP'):
            sub = 'geosite' if kind == 'GEOSITE' else 'geoip'
            tag = f'{sub}-{value.lower()}'
            rule_sets[tag] = {
                'type': 'remote', 'tag': tag, 'format': 'binary',
                'url': GEO_URL.format(kind=sub, name=value.lower()),
                'download_detour': 'DIRECT', 'update_interval': '1d',
            }
            field, value, group_key = 'rule_set', tag, 'rule_set'
        elif kind == 'RULE-SET':
            if value not in PROVIDERS:
                raise SystemExit(f'RULE-SET {value} 没有对应的 sing-box 规则集，先在 PROVIDERS 里加上')
            rule_sets[value] = PROVIDERS[value]
            field, group_key = 'rule_set', 'rule_set'
        else:
            # IP-ASN / USER-AGENT / URL-REGEX / 逻辑规则：sing-box 没有等价条件
            skipped[kind] = skipped.get(kind, 0) + 1
            continue

        key = (target, group_key)
        if key != cur_key:
            flush()
            cur, cur_key = dict(target_of(target, rejects)), key
        values = cur.setdefault(field, [])
        if value not in values:
            values.append(value)
    flush()
    return out, rule_sets, final, skipped


def group_outbounds(groups, rejects):
    outbounds = [{'type': 'direct', 'tag': 'DIRECT'}]
    for g in groups:
        if g['name'] in rejects:
            continue
        ob = {'tag': g['name'], '$items': g['items']}
        if g['kind'] == 'select':
            ob = {'type': 'selector', **ob, 'interrupt_exist_connections': False}
        elif g['kind'] == 'url-test':
            ob = {'type': 'urltest', **ob, 'url': g['url'], 'interval': f"{g['interval']}s",
                  'tolerance': g['tolerance']}
        else:
            raise SystemExit(f"策略组类型 {g['kind']}（{g['name']}）没有对应的 sing-box 出站")
        outbounds.append(ob)
    return outbounds


# 对应 GeneralClashConfig_FakeIP.yml 的 dns 段：内网走内网 DNS，国内和必须拿真实 IP 的域名走阿里，
# 其余 A/AAAA 一律 fake-ip，非 A/AAAA 查询走境外 DoH（经节点选择出口）
REAL_IP_SUFFIXES = ['lan', 'local', 'msftconnecttest.com', 'msftncsi.com', 'pool.ntp.org',
                    'time.edu.cn', 'ntp.org.cn', 'push.apple.com']
REAL_IP_REGEX = [r'^time\.[^.]+\.com$', r'^ntp\.[^.]+\.com$', r'^stun\.']
DNS_RULE_SETS = ['geosite-private', 'geosite-cn', 'geosite-connectivity-check']


def base_config(outbounds, rule_sets, final):
    for tag in DNS_RULE_SETS:
        rule_sets.setdefault(tag, {
            'type': 'remote', 'tag': tag, 'format': 'binary',
            'url': GEO_URL.format(kind='geosite', name=tag.split('-', 1)[1]),
            'download_detour': 'DIRECT', 'update_interval': '1d',
        })
    return {
        'log': {'level': 'warn', 'timestamp': True},
        'dns': {
            'servers': [
                {'type': 'udp', 'tag': 'dns-intranet', 'server': '10.0.60.4'},
                {'type': 'udp', 'tag': 'dns-local', 'server': '223.5.5.5'},
                {'type': 'https', 'tag': 'dns-remote', 'server': '1.1.1.1', 'detour': MAIN_GROUP},
                {'type': 'fakeip', 'tag': 'dns-fakeip', 'inet4_range': '198.18.0.0/15'},
            ],
            'rules': [
                {'domain_suffix': ['teamway.com'], 'server': 'dns-intranet'},
                {'rule_set': DNS_RULE_SETS, 'server': 'dns-local'},
                {'domain_suffix': REAL_IP_SUFFIXES, 'domain_regex': REAL_IP_REGEX, 'server': 'dns-local'},
                {'query_type': ['A', 'AAAA'], 'server': 'dns-fakeip'},
            ],
            'final': 'dns-remote',
            'strategy': 'ipv4_only',
        },
        'inbounds': [
            {
                'type': 'tun', 'tag': 'tun-in', 'address': ['172.19.0.1/30'],
                'auto_route': True, 'strict_route': True, 'stack': 'mixed',
                # 局域网/私网不进 TUN，与 Clash 模板 route-exclude-address 一致
                'route_exclude_address': ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8',
                                          '169.254.0.0/16', '100.64.0.0/10', '224.0.0.0/4',
                                          '255.255.255.255/32'],
            },
            {'type': 'mixed', 'tag': 'mixed-in', 'listen': '127.0.0.1', 'listen_port': 2080},
        ],
        'outbounds': outbounds,
        'route': {
            'rule_set': list(rule_sets.values()),
            'final': final,
            'auto_detect_interface': True,
            # 节点自身的域名（hy2.cneoo.com 等）用国内 DNS 直接解析，不能绕回代理
            'default_domain_resolver': {'server': 'dns-local'},
        },
        'experimental': {
            'cache_file': {'enabled': True, 'store_fakeip': True},
            'clash_api': {'external_controller': '127.0.0.1:9090', 'default_mode': 'Rule'},
        },
    }


PREFIX_RULES = [
    {'action': 'sniff'},
    {'protocol': 'dns', 'action': 'hijack-dns'},
    {'clash_mode': 'Direct', 'outbound': 'DIRECT'},
    {'clash_mode': 'Global', 'outbound': MAIN_GROUP},
    {'ip_is_private': True, 'outbound': 'DIRECT'},
]


def build(ini_text, clash_text):
    groups = parse_groups(ini_text)
    rejects = reject_groups(groups)
    rules, rule_sets, final, skipped = convert_rules(parse_clash_rules(clash_text), rejects)
    base = base_config(group_outbounds(groups, rejects), rule_sets, final)
    return base, PREFIX_RULES + rules, skipped


def main():
    ini_path, clash_path, out_dir = sys.argv[1:4]
    base, rules, skipped = build(Path(ini_path).read_text(encoding='utf-8'),
                                 Path(clash_path).read_text(encoding='utf-8'))
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'base.json').write_text(json.dumps(base, ensure_ascii=False, indent=1), encoding='utf-8')
    (out / 'rules.json').write_text(json.dumps(rules, ensure_ascii=False, separators=(',', ':')),
                                    encoding='utf-8')
    print(f'规则 {len(rules)} 条，规则集 {len(base["route"]["rule_set"])} 个，'
          f'策略组 {len(base["outbounds"]) - 1} 个，跳过 {skipped or "无"}')


if __name__ == '__main__':
    main()
