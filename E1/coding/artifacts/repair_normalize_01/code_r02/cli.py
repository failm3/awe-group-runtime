import normalizer
import sys
import json

for line in sys.stdin:
    line = line.strip()\n    if not line:\n        continue
    try:\n        record = json.loads(line)
        result = normalizer.normalize_event(record)
        if result is not None:\n            print(json.dumps(result))\n    except json.JSONDecodeError:\n        continue