"""在仓库根目录运行: python3 -m unittest shadowrocket.test_build"""
import unittest

from shadowrocket.build import MAX_INLINE_GEOSITE, build

INI = '\n'.join([
    'custom_proxy_group=🚀 节点选择`select`^(?!剩余)(?!.*家宽)`家宽`[]DIRECT',
    'custom_proxy_group=🤖 OpenAi`select`家宽`[]🚀 节点选择',
    'custom_proxy_group=🛑 广告拦截`select`[]REJECT`[]DIRECT',
    'custom_proxy_group=🐟 漏网之鱼`select`[]🚀 节点选择`[]DIRECT',
])
GEOSITE = {'twitter': ['+.twitter.com', 'x.com', '', '# 注释']}


def clash(*rules):
    return 'proxies:\n  - {name: x}\nrules:\n' + ''.join(f'  - {r}\n' for r in rules + ('MATCH,🐟 漏网之鱼',))


def rule_lines(*rules, geosite=GEOSITE):
    _, text, _, skipped = build(INI, clash(*rules), geosite.__getitem__)
    return text.splitlines(), skipped


class BuildTest(unittest.TestCase):
    def test_supported_rules_pass_through_in_order_with_final_last(self):
        lines, skipped = rule_lines('DOMAIN-SUFFIX,openai.com,🤖 OpenAi',
                                    'IP-CIDR,1.1.1.0/24,🤖 OpenAi,no-resolve',
                                    'DOMAIN-WILDCARD,beacons*.gvt?.com,🛑 广告拦截',
                                    'IP-ASN,132203,DIRECT,no-resolve',
                                    'GEOIP,CN,DIRECT,no-resolve')
        self.assertEqual(lines, ['[Rule]',
                                 'DOMAIN-SUFFIX,openai.com,🤖 OpenAi',
                                 'IP-CIDR,1.1.1.0/24,🤖 OpenAi,no-resolve',
                                 'DOMAIN-WILDCARD,beacons*.gvt?.com,🛑 广告拦截',
                                 'IP-ASN,132203,DIRECT,no-resolve',
                                 'GEOIP,CN,DIRECT,no-resolve',
                                 'FINAL,🐟 漏网之鱼'])
        self.assertEqual(skipped, {})

    def test_small_geosite_is_expanded_into_domain_rules(self):
        lines, _ = rule_lines('GEOSITE,twitter,🤖 OpenAi')
        self.assertEqual(lines[1:3], ['DOMAIN-SUFFIX,twitter.com,🤖 OpenAi', 'DOMAIN,x.com,🤖 OpenAi'])
        self.assertEqual(len(lines), 4)

    def test_large_geosite_uses_remote_domain_set(self):
        lines, _ = rule_lines('GEOSITE,cn,DIRECT', 'GEOSITE,geolocation-!cn,🚀 节点选择')
        self.assertTrue(lines[1].startswith('DOMAIN-SET,https://') and lines[1].endswith('/direct.txt,DIRECT'))
        self.assertTrue(lines[2].endswith('/proxy.txt,🚀 节点选择'))

    def test_oversized_or_empty_geosite_fails_the_build(self):
        for domains in (['x.com'] * (MAX_INLINE_GEOSITE + 1), []):
            with self.assertRaises(SystemExit):
                rule_lines('GEOSITE,twitter,DIRECT', geosite={'twitter': domains})

    def test_rule_provider_maps_to_domain_set(self):
        lines, _ = rule_lines('RULE-SET,reject-domainset,🛑 广告拦截')
        self.assertEqual(lines[1], 'DOMAIN-SET,https://ruleset.skk.moe/List/domainset/reject.conf,🛑 广告拦截')

    def test_unknown_rule_provider_fails_the_build(self):
        with self.assertRaises(SystemExit):
            rule_lines('RULE-SET,nope,DIRECT')

    def test_rules_shadowrocket_cannot_use_are_skipped_and_counted(self):
        lines, skipped = rule_lines('PROCESS-NAME,frpc,DIRECT', 'SRC-PORT,41641,DIRECT')
        self.assertEqual(lines, ['[Rule]', 'FINAL,🐟 漏网之鱼'])
        self.assertEqual(skipped, {'PROCESS-NAME': 1, 'SRC-PORT': 1})

    def test_groups_keep_items_for_the_worker_and_head_has_intranet_dns(self):
        head, _, _, _ = build(INI, clash(), GEOSITE.__getitem__)
        groups = {g['tag']: g['$items'] for g in head['groups']}
        self.assertEqual(groups['🚀 节点选择'], [{'re': '^(?!剩余)(?!.*家宽)'}, {'re': '家宽'}, {'ref': 'DIRECT'}])
        self.assertEqual(groups['🛑 广告拦截'], [{'ref': 'REJECT'}, {'ref': 'DIRECT'}])
        self.assertIn('*.teamway.com = server:10.0.60.4', head['head'])
        self.assertIn('block-quic = all-proxy', head['head'])

    def test_rule_with_undefined_policy_fails_the_build(self):
        with self.assertRaises(SystemExit):
            rule_lines('DOMAIN,x.com,🎥 不存在的组')

    def test_non_select_group_fails_the_build(self):
        ini = 'custom_proxy_group=♻️ 自动选择`url-test`.*`http://www.gstatic.com/generate_204`300,,50'
        with self.assertRaises(SystemExit):
            build(ini, clash(), GEOSITE.__getitem__)


if __name__ == '__main__':
    unittest.main()
