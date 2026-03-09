import json
import re
from pathlib import Path

REPORT = Path("/reports/mcp-analysis.report.json")

KEYWORDS = {
    "movement": ["move", "movement", "path", "position", "world transfer", "clientmovement"],
    "combat": ["combat", "target", "attack", "spell", "cast", "threat"],
    "input": ["mouse", "keyboard", "click", "key", "cursor"],
    "network": ["network", "socket", "send", "recv", "packet", "realm"],
    "anti_analysis": ["IsDebuggerPresent", "signature", "authenticate", "scan", "warden"],
    "ui_addon": ["reloadUI", "checkAddonVersion", "interface", "addon", "showToolsUI"],
}

def pull_text(report: dict, key: str) -> str:
    return report.get("calls", {}).get(key, {}).get("text", "")


def find_lines(text: str, terms: list[str]) -> list[str]:
    out = []
    lines = text.splitlines()
    for ln in lines:
        low = ln.lower()
        if any(t.lower() in low for t in terms):
            out.append(ln.strip())
    return out


def main() -> int:
    if not REPORT.exists():
        print(f"Report not found: {REPORT}")
        return 1

    report = json.loads(REPORT.read_text(encoding="utf-8"))
    strings_text = pull_text(report, "list_strings")
    imports_text = pull_text(report, "list_imports")
    funcs_text = pull_text(report, "list_functions")

    findings = {
        "program": report.get("program_name"),
        "function_count_hint": None,
        "categories": {},
    }

    m = re.search(r"Function Count:\s*(\d+)", pull_text(report, "get_program_info"))
    if m:
        findings["function_count_hint"] = int(m.group(1))

    corpus = {
        "strings": strings_text,
        "imports": imports_text,
        "functions": funcs_text,
    }

    for category, terms in KEYWORDS.items():
        cat_hits = {}
        for source, text in corpus.items():
            hits = find_lines(text, terms)
            if hits:
                cat_hits[source] = hits[:30]
        if cat_hits:
            findings["categories"][category] = cat_hits

    out = Path("/reports/bot-signals.json")
    out.write_text(json.dumps(findings, indent=2), encoding="utf-8")

    print("Bot signal extraction complete")
    print(f"Program: {findings['program']}")
    print(f"Function count: {findings['function_count_hint']}")
    for cat, data in findings["categories"].items():
        total = sum(len(v) for v in data.values())
        print(f"- {cat}: {total} hits")
    print(f"Saved: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
