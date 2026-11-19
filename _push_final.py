import subprocess

ENV = {**__import__("os").environ, "PYTHONIOENCODING": "utf-8",
       "GIT_AUTHOR_NAME": "OpenAgent Audit", "GIT_AUTHOR_EMAIL": "audit@openagent.local",
       "GIT_COMMITTER_NAME": "OpenAgent Audit", "GIT_COMMITTER_EMAIL": "audit@openagent.local"}

r = subprocess.run(["git", "add", "-A"], cwd=r"D:\OpenAgent.Audit",
                   capture_output=True, text=True, encoding="utf-8", errors="replace", env=ENV)
r = subprocess.run(["git", "commit", "-q", "-m",
                    "fix(console): plain datetime format and in-app routing for session opens\n\n"
                    "- timestamps render as 2026-11-19 16:19:39 (no ISO T/offset markers);\n"
                    "- opening a session uses router.push instead of a full page reload,\n"
                    "  which was reloading the whole bundle on every click and made\n"
                    "  production navigation feel sluggish."],
                   cwd=r"D:\OpenAgent.Audit", capture_output=True, text=True,
                   encoding="utf-8", errors="replace", env=ENV)
print("commit:", r.returncode)

r = subprocess.run(["git", "log", "--oneline", "-1"], cwd=r"D:\OpenAgent.Audit",
                   capture_output=True, text=True, encoding="utf-8", errors="replace", env=ENV)
print(r.stdout.strip())

r = subprocess.run(["git", "push", "origin", "main"], cwd=r"D:\OpenAgent.Audit",
                   capture_output=True, text=True, encoding="utf-8", errors="replace", env=ENV)
out = (r.stdout or "") + (r.stderr or "")
for line in out.split("\n"):
    if "ghp_" in line:
        import re
        line = re.sub(r"ghp_[A-Za-z0-9]+", "***", line)
    if line.strip():
        print(line.strip()[:120])
print("push exit:", r.returncode)