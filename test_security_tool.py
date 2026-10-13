import copy
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import security_tool as tool

NOW = datetime(2026, 10, 13, 12, tzinfo=timezone.utc)


class ReportingTests(unittest.TestCase):
    def test_demo_generates_explainable_findings(self):
        results = tool.audit(copy.deepcopy(tool.DEMO), {}, NOW)
        self.assertTrue(results)
        self.assertTrue(all(item['remediation'] and item['evidence'] for item in results))

    def test_fingerprints_are_deterministic(self):
        self.assertEqual(tool.audit(copy.deepcopy(tool.DEMO), {}, NOW),
                         tool.audit(copy.deepcopy(tool.DEMO), {}, NOW))

    def test_active_and_expired_suppressions(self):
        rows = tool.audit(copy.deepcopy(tool.DEMO), {}, NOW)
        item = {'fingerprint': rows[0]['fingerprint'], 'reason': 'Synthetic exception review',
                'expires': '2027-01-01T00:00:00Z'}
        self.assertEqual(len(tool.build_report(rows, [item], NOW)['suppressed']), 1)
        item['expires'] = '2026-01-01T00:00:00Z'
        self.assertEqual(len(tool.build_report(rows, [item], NOW)['suppressed']), 0)

    def test_invalid_exception_and_input(self):
        with self.assertRaises(ValueError):
            tool.build_report([], [{'fingerprint': 'x', 'reason': '', 'expires': 'bad'}], NOW)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            tool.audit({}, {}, NOW)
        duplicate = {'fingerprint': 'same', 'reason': 'Synthetic test exception', 'expires': '2027-01-01T00:00:00Z'}
        with self.assertRaises(ValueError):
            tool.build_report([], [duplicate, duplicate], NOW)

    def test_json_ambiguity_rejected(self):
        for content in ['{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}']:
            with self.assertRaises(ValueError):
                tool.decode_json(content)

    def test_sarif_contains_rules_and_stable_fingerprints(self):
        report = tool.build_report(tool.audit(copy.deepcopy(tool.DEMO), {}, NOW), now=NOW)
        result = tool.sarif(report)
        self.assertEqual(result['version'], '2.1.0')
        self.assertEqual(len(result['runs'][0]['results']), len(report['findings']))
        self.assertTrue(all(x['partialFingerprints'] for x in result['runs'][0]['results']))

    def test_cli_demo_and_missing_input(self):
        script = Path(__file__).with_name('security_tool.py')
        result = subprocess.run([sys.executable, str(script), '--demo', '--now', NOW.isoformat()],
                                capture_output=True, text=True)
        self.assertIn(result.returncode, [0, 1], result.stderr)
        self.assertEqual(json.loads(result.stdout)['tool'], tool.TOOL)
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)

class PolicyTests(unittest.TestCase):
    def test_deny_not_reported_as_allow(self):
        data = copy.deepcopy(tool.DEMO)
        for statement in data['policies'][0]['document']['Statement']:
            statement['Effect'] = 'Deny'
        self.assertEqual(tool.audit(data, {}, NOW), [])

    def test_narrow_read_policy(self):
        data = {'policies': [{'id': 'read', 'document': {'Statement': {'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::example/reports/*'}}}]}
        self.assertEqual(tool.audit(data, {}, NOW), [])

    def test_condition_does_not_hide_admin(self):
        data = copy.deepcopy(tool.DEMO)
        data['policies'][0]['document']['Statement'] = [data['policies'][0]['document']['Statement'][0]]
        data['policies'][0]['document']['Statement'][0]['Condition'] = {'Bool': {'aws:MultiFactorAuthPresent': 'true'}}
        self.assertEqual(tool.audit(data, {}, NOW)[0]['severity'], 'high')

    def test_notaction_flagged(self):
        data = {'policies': [{'id': 'exclude', 'document': {'Statement': {'Effect': 'Allow', 'NotAction': 'iam:*', 'Resource': '*'}}}]}
        self.assertIn('IAM-NOTACTION-ALLOW', {x['rule'] for x in tool.audit(data, {}, NOW)})

    def test_ambiguous_action_rejected(self):
        data = copy.deepcopy(tool.DEMO)
        data['policies'][0]['document']['Statement'][0]['NotAction'] = 's3:*'
        with self.assertRaises(ValueError):
            tool.audit(data, {}, NOW)

    def test_principal_array(self):
        data = copy.deepcopy(tool.DEMO)
        data['policies'][0]['document']['Statement'] = [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': '*', 'Principal': {'AWS': ['*']}}]
        self.assertIn('IAM-PUBLIC-PRINCIPAL', {x['rule'] for x in tool.audit(data, {}, NOW)})


if __name__ == "__main__":
    unittest.main()
