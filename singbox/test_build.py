"""python3 -m unittest singbox/test_build.py"""
import unittest

from build import build, parse_groups

INI = '\n'.join([
    'custom_proxy_group=🚀 节点选择`select`[]♻️ 自动选择`^(?!剩余)(?!.*家宽)`家宽`[]DIRECT',
    'custom_proxy_group=♻️ 自动选择`url-test`^(?!剩余)(?!.*家宽)`http://www.gstatic.com/generate_204`300,,50',
    'custom_proxy_group=🤖 OpenAi`select`家宽`[]🚀 节点选择',
    'custom_proxy_group=🛑 广告拦截`select`[]REJECT`[]DIRECT',
    'custom_proxy_group=🎯 全球直连`select`[]DIRECT`[]🚀 节点选择',
])


def clash(*rules):
    return 'proxies:\n  - {name: x}\nrules:\n' + ''.join(f'  - {r}\n' for r in rules)


class BuildTest(unittest.TestCase):
    def rules(self, *lines):
        base, rules, skipped = build(INI, clash(*lines))
        return base, rules[5:], skipped  # 去掉固定的前置规则

    def test_process_name_never_shares_a_rule_with_domains(self):
        _, rules, _ = self.rules('DOMAIN-SUFFIX,openai.com,🤖 OpenAi', 'PROCESS-NAME,chatgpt,🤖 OpenAi',
                                 'DOMAIN,api.openai.com,🤖 OpenAi')
        self.assertEqual(rules, [
            {'outbound': '🤖 OpenAi', 'domain_suffix': ['openai.com']},
            {'outbound': '🤖 OpenAi', 'process_name': ['chatgpt']},
            {'outbound': '🤖 OpenAi', 'domain': ['api.openai.com']},
        ])

    def test_adjacent_same_target_or_fields_merge_and_order_is_kept(self):
        _, rules, _ = self.rules('DOMAIN-SUFFIX,a.com,🤖 OpenAi', 'IP-CIDR,1.1.1.0/24,🤖 OpenAi,no-resolve',
                                 'DOMAIN-SUFFIX,b.com,🎯 全球直连', 'DOMAIN-SUFFIX,c.com,🤖 OpenAi')
        self.assertEqual(rules, [
            {'outbound': '🤖 OpenAi', 'domain_suffix': ['a.com'], 'ip_cidr': ['1.1.1.0/24']},
            {'outbound': '🎯 全球直连', 'domain_suffix': ['b.com']},
            {'outbound': '🤖 OpenAi', 'domain_suffix': ['c.com']},
        ])

    def test_reject_group_becomes_reject_action_and_is_not_an_outbound(self):
        base, rules, _ = self.rules('DOMAIN-KEYWORD,adservice,🛑 广告拦截', 'DOMAIN,x.com,REJECT')
        self.assertEqual(rules, [{'action': 'reject', 'domain_keyword': ['adservice']},
                                 {'action': 'reject', 'domain': ['x.com']}])
        self.assertNotIn('🛑 广告拦截', [o['tag'] for o in base['outbounds']])

    def test_geosite_and_rule_set_become_remote_rule_sets(self):
        base, rules, _ = self.rules('GEOSITE,geolocation-!cn,🚀 节点选择', 'RULE-SET,reject-domainset,🛑 广告拦截')
        self.assertEqual(rules, [{'outbound': '🚀 节点选择', 'rule_set': ['geosite-geolocation-!cn']},
                                 {'action': 'reject', 'rule_set': ['reject-domainset']}])
        sets = {s['tag']: s for s in base['route']['rule_set']}
        self.assertTrue(sets['geosite-geolocation-!cn']['url'].endswith('/geo/geosite/geolocation-!cn.srs'))
        self.assertEqual(sets['reject-domainset']['format'], 'source')

    def test_unknown_rule_set_fails_the_build(self):
        with self.assertRaises(SystemExit):
            build(INI, clash('RULE-SET,nope,🚀 节点选择'))

    def test_match_sets_final_and_unsupported_rules_are_counted(self):
        base, rules, skipped = self.rules('IP-ASN,13335,🚀 节点选择', 'MATCH,🎯 全球直连')
        self.assertEqual(rules, [])
        self.assertEqual(base['route']['final'], '🎯 全球直连')
        self.assertEqual(skipped, {'IP-ASN': 1})

    def test_domain_wildcard_becomes_anchored_regex(self):
        _, rules, _ = self.rules('DOMAIN-WILDCARD,beacons*.gvt?.com,🛑 广告拦截')
        self.assertEqual(rules, [{'action': 'reject', 'domain_regex': [r'^beacons.*\.gvt.\.com$']}])

    def test_ports_and_port_ranges(self):
        _, rules, _ = self.rules('SRC-PORT,41641,🎯 全球直连', 'DST-PORT,6881-6889,🎯 全球直连')
        self.assertEqual(rules, [{'outbound': '🎯 全球直连', 'source_port': [41641]},
                                 {'outbound': '🎯 全球直连', 'port_range': ['6881:6889']}])

    def test_url_test_group_keeps_regex_items_and_timing(self):
        g = {x['name']: x for x in parse_groups(INI)}['♻️ 自动选择']
        self.assertEqual(g['items'], [{'re': '^(?!剩余)(?!.*家宽)'}])
        self.assertEqual((g['url'], g['interval'], g['tolerance']),
                         ('http://www.gstatic.com/generate_204', 300, 50))


if __name__ == '__main__':
    unittest.main()
