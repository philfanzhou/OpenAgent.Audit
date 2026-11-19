import pathlib
import subprocess

ENV = {**__import__("os").environ, "PYTHONIOENCODING": "utf-8"}
repo = r"D:\OpenAgent"
dockerfile = repo + r"\Backend\src\OpenAgent.Engine.Host\Dockerfile"

r = subprocess.run(
    ["docker", "build",
     "-f", dockerfile,
     "--build-arg", "OPENCODE_VERSION=1.19.3",
     "-t", "openagent-engine:latest",
     repo],
    capture_output=True, text=True, encoding="utf-8", errors="replace",
    env=ENV,
)
out = (r.stdout or "") + (r.stderr or "")
print(out.strip().splitlines()[-1] if out.strip() else "(none)", "| exit:", r.returncode)