import json
import re
from Data import config

def contains_vector(part: str, part_name: str):
    ruleset = json.loads(config['ruleset'].get('manual_rules').replace("'", '"'))
    for rule in ruleset:
        if re.compile(rule['regex'], re.I).search(part):
            return f"Trace of {rule['name']} detected in {part_name}"
    return None
