"""Portable credential reference validation; never handles secret values."""
import re

ENV_REF = re.compile(r"^env:([A-Z][A-Z0-9_]*)$")


def collect_references(value, path="$"):
    """Walk a generated configuration looking for *Ref fields."""
    found = []
    if isinstance(value, dict):
        for key, item in value.items():
            loc = f"{path}.{key}"
            if key.endswith("Ref"):
                if not isinstance(item, str) or not ENV_REF.fullmatch(item):
                    raise ValueError(f"Unsupported credential reference at {loc}: expected env:UPPERCASE_KEY")
                found.append((loc, ENV_REF.fullmatch(item).group(1)))
            else:
                found.extend(collect_references(item, loc))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            found.extend(collect_references(item, f"{path}[{i}]"))
    return found


def validate_references(configuration, spec):
    credentials = spec.get("credentials") if isinstance(spec, dict) else None
    if not isinstance(credentials, dict):
        raise ValueError("Credential spec requires credentials object")
    references = collect_references(configuration)
    missing = [(path, key) for path, key in references if key not in credentials]
    if missing:
        raise ValueError("Undeclared credentials: " + ", ".join(f"{key} at {path}" for path, key in missing))
    return {"referenceCount": len(references), "credentialKeys": sorted({key for _, key in references})}
