#!/usr/bin/env python3
"""把模板拼成一份可校验的完整配置（一个假节点，策略组按 Worker 的规则展开），给 sing-box check 用。

用法: sample.py <输出目录> <样例文件>
"""
import json
import re
import sys
from pathlib import Path

NODE = {
    'type': 'hysteria2', 'tag': '🇺🇸 US 01 · GIA Hy2', 'server': 'example.com', 'server_port': 443,
    'server_ports': ['31000:31499'], 'hop_interval': '30s', 'password': 'x',
    'tls': {'enabled': True, 'server_name': 'example.com', 'alpn': ['h3']},
}


def main():
    out, sample = Path(sys.argv[1]), Path(sys.argv[2])
    base = json.loads((out / 'base.json').read_text(encoding='utf-8'))
    known = {'DIRECT', *(o['tag'] for o in base['outbounds'])}
    for o in base['outbounds']:
        items = o.pop('$items', None)
        if items is None:
            continue
        lst = []
        for it in items:
            add = ([it['ref']] if it['ref'] in known else []) if 'ref' in it else \
                [NODE['tag']] if re.search(it['re'], NODE['tag']) else []
            lst += [t for t in add if t not in lst]
        o['outbounds'] = lst or ['DIRECT']
    base['outbounds'].append(NODE)
    base['route']['rules'] = json.loads((out / 'rules.json').read_text(encoding='utf-8'))
    sample.write_text(json.dumps(base, ensure_ascii=False), encoding='utf-8')


if __name__ == '__main__':
    main()
