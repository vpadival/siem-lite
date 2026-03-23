import yaml
import re
import time
from collections import defaultdict
from typing import List, Dict, Any, Tuple

# Load detection rules from YAML file
def load_rules(file_path: str) -> List[Dict[str, Any]]:
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)

# Watch log file and process lines
def watch_log(file_path: str, rules: List[Dict[str, Any]]) -> None:
    cooldowns: Dict[int, Dict[Tuple[Tuple[str, str], ...], float]] = defaultdict(dict)  # Track cooldowns per rule and key

    with open(file_path, 'r') as log_file:
        while True:
            line = log_file.readline()
            if not line:
                time.sleep(1)  # Wait for new log entries
                continue

            for rule in rules:
                match = re.search(rule['pattern'], line)
                if match:
                    key: Tuple[Tuple[str, str], ...] = tuple(match.groupdict().items())  # Unique key for deduplication
                    now = time.time()

                    if key in cooldowns[rule['id']] and now - cooldowns[rule['id']][key] < rule['cooldown_seconds']:
                        continue  # Skip alert if within cooldown window

                    cooldowns[rule['id']][key] = now

                    alert_message: str = rule['alert_message_template']
                    for k, v in match.groupdict().items():
                        alert_message = alert_message.replace(f"{{{{ {k} }}}}", v)

                    print(f"[{rule['severity'].upper()}] {rule['name']} | Reason: {alert_message} | Score: {rule['score']}")

if __name__ == "__main__":
    rules = load_rules('../rules/detection-rules.yml')
    log_file_path = '/var/log/auth.log'  # Change this to the log file you want to monitor
    watch_log(log_file_path, rules)