def normalize_event(value):
    if not isinstance(value, dict):
        return None
    id_val = value.get("id")
    kind_val = value.get("kind")
    if not (isinstance(id_val, str) and isinstance(kind_val, str)):
        return None
    id_trim = id_val.strip('\x20\x09\x0a\x0d')
    kind_trim = kind_val.strip('\x20\x09\x0a\x0d')
    if not id_trim or not kind_trim:
        return None
    return {"id": id_trim, "kind": kind_trim.lower()}
