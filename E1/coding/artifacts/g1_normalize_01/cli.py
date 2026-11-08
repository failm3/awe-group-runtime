import normalizer
import sys
import json

for line in sys.stdin:
    line = line.strip()\n    if not line:\n        continue
    try:\n        record = json.loads(line)\n        result = normalizer.normalize_event(record)\n        if result is not None:\n            print(json.dumps(result))\n    except json.JSONDecodeError:\n        continue