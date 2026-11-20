import pathlib

p = pathlib.Path(r"D:\OpenAgent.Audit\src\openagent_audit\config.py")
text = p.read_text(encoding="utf-8")

print("== admin/用户 相关配置 ==")
for i, line in enumerate(text.split("\n"), 1):
    low = line.lower()
    if any(k in low for k in ("admin", "users", "user_entry", "test_username", "test_password")):
        if "def " in line or ":" in line or "=" in line or "AUDIT" in line or "env" in low:
            print(f"{i}: {line.strip()[:120]}")