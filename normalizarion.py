from findingstruct import Finding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
 
 
def correlate_and_prioritize(findings: list[Finding]) -> list[Finding]:
    """Simple correlation: dedupe findings pointing at the same file+line+title
    across tools, then sort by severity."""
    seen = {}
    for f in findings:
        key = (f.file, f.line, f.title.lower())
        if key not in seen:
            seen[key] = f
        else:
            # merge: keep the more severe one, note the duplicate tool
            existing = seen[key]
            if SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[existing.severity]:
                seen[key] = f
 
    deduped = list(seen.values())
    deduped.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 5))
    return deduped
 
 