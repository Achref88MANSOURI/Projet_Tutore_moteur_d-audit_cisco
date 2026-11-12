"""Execution policy overlay; the historical CIS catalogue is not rewritten."""
import json
from pathlib import Path

POLICY_PATH = Path(__file__).with_name('configuration_only_scope.json')


def policy():
    return json.loads(POLICY_PATH.read_text(encoding='utf-8'))


def exclusions(controls):
    indexed = {c['id']: c for c in controls}
    return [dict(control_id=item['control_id'], title=indexed[item['control_id']]['title'],
                 status=item['status'], reason=item['reason'])
            for item in policy()['excluded_controls'] if item['control_id'] in indexed]


def automatic_controls(controls):
    excluded_ids = {c['control_id'] for c in policy()['excluded_controls']}
    return [c for c in controls if c['id'] not in excluded_ids]
