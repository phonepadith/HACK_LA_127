#!/usr/bin/env python3
"""Agentic installer for a GeoAI edge sensor node (LangGraph + OpenAI).

Provisions a Raspberry Pi as a GeoAI FTTH edge sensor: checks the host, copies
pi_agent.py, installs a systemd unit so it survives reboots, then verifies the
sensor both serves its own UI and registers with the GeoAI server.

    export OPENAI_API_KEY=sk-...
    python3 install_sensor_agent.py --host kobi@192.168.0.110 \
        --geoai-url https://geoai-ftth-demo.laopadit.com --zone VTE --apply

Without --apply every mutating step is a dry run that prints the exact command
it would have executed, so you can read the plan before anything touches the Pi.

    python3 install_sensor_agent.py --check     # offline self-check, no API key
"""
import argparse
import json
import os
import shlex
import subprocess
import sys
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SENSOR_SRC = REPO / "pi_agent.py"
SERVICE = "geoai-sensor"

# Set by main(); while False every mutating tool reports its command instead of
# running it. Read-only probes always run — they cannot damage the node.
EXECUTE = False
TIMEOUT = 60


# --- shell plumbing ----------------------------------------------------------
def _run(argv, stdin=None):
    """Run a command, returning a short transcript the model can read."""
    try:
        p = subprocess.run(argv, input=stdin, capture_output=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return f"TIMEOUT after {TIMEOUT}s: {shlex.join(argv)}"
    except FileNotFoundError as e:
        return f"ERROR: {e}"
    out = (p.stdout or b"").decode(errors="replace").strip()
    err = (p.stderr or b"").decode(errors="replace").strip()
    return f"exit={p.returncode}\nstdout:\n{out or '(empty)'}\nstderr:\n{err or '(empty)'}"


def _ssh_argv(host, remote_cmd, port=22):
    return ["ssh", "-p", str(port), "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
            host, remote_cmd]


def _ssh(host, remote_cmd, port=22, mutating=True, stdin=None):
    argv = _ssh_argv(host, remote_cmd, port)
    if mutating and not EXECUTE:
        return "DRY RUN — not executed. Would run:\n" + shlex.join(argv)
    return _run(argv, stdin=stdin)


# --- tools -------------------------------------------------------------------
# Each tool is a fixed command template. There is deliberately no "run arbitrary
# shell" tool: the model chooses which step to take, never what to execute.
def check_host(host: str, ssh_port: int = 22) -> str:
    """Check the Pi is reachable over SSH and can run the sensor.

    Reports hostname, OS, architecture, python3 version and whether systemd and
    port 8080 are free. Read-only. host is user@address."""
    cmd = ("hostname; . /etc/os-release 2>/dev/null && echo \"os=$PRETTY_NAME\"; "
           "echo \"arch=$(uname -m)\"; python3 -V 2>&1 | sed 's/^/python=/'; "
           "command -v systemctl >/dev/null && echo systemd=yes || echo systemd=no; "
           "(ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | grep -q ':8080 ' "
           "&& echo port8080=busy || echo port8080=free")
    return _ssh(host, cmd, ssh_port, mutating=False)


def copy_sensor(host: str, target_dir: str = "/home/kobi/geoai-sensor",
                ssh_port: int = 22) -> str:
    """Copy pi_agent.py from this repo to target_dir on the Pi, creating it."""
    if not SENSOR_SRC.exists():
        return f"ERROR: {SENSOR_SRC} not found — run this from the geoai repo."
    argv = ["sh", "-c", f"tar cz -C {shlex.quote(str(REPO))} pi_agent.py | "
                        + shlex.join(_ssh_argv(host, f"mkdir -p {shlex.quote(target_dir)} && "
                                                     f"tar xz -C {shlex.quote(target_dir)}",
                                               ssh_port))]
    if not EXECUTE:
        return "DRY RUN — not executed. Would run:\n" + argv[2]
    return _run(argv)


def install_service(host: str, geoai_url: str, zone: str = "VTE",
                    site: str = "", lat: float = 17.8677045, lon: float = 102.6169395,
                    pi_port: int = 8080, target_dir: str = "/home/kobi/geoai-sensor",
                    user: str = "", ssh_port: int = 22) -> str:
    """Install and start the systemd unit so the sensor survives reboots.

    geoai_url is the GeoAI server the sensor reports to. user defaults to the
    SSH user in host. Replaces any existing unit and enables it."""
    user = user or (host.split("@")[0] if "@" in host else "pi")
    unit = f"""[Unit]
Description=GeoAI FTTH edge sensor agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={user}
WorkingDirectory={target_dir}
Environment=GEOAI_URL={geoai_url}
Environment=SENSOR_ZONE={zone}
Environment=SENSOR_SITE={site or zone + " site"}
Environment=SENSOR_LAT={lat}
Environment=SENSOR_LON={lon}
Environment=PI_PORT={pi_port}
ExecStart=/usr/bin/python3 {target_dir}/pi_agent.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    cmd = (f"cat > /tmp/{SERVICE}.service && "
           f"sudo install -m644 /tmp/{SERVICE}.service /etc/systemd/system/{SERVICE}.service && "
           f"sudo systemctl daemon-reload && "
           f"sudo systemctl enable --now {SERVICE} && "
           f"sleep 3 && systemctl is-active {SERVICE}")
    if not EXECUTE:
        return ("DRY RUN — not executed. Would pipe this unit file:\n" + unit
                + "\ninto:\n" + shlex.join(_ssh_argv(host, cmd, ssh_port)))
    return _ssh(host, cmd, ssh_port, stdin=unit.encode())


def service_status(host: str, lines: int = 20, ssh_port: int = 22) -> str:
    """Read the sensor service state and its most recent journal lines."""
    cmd = (f"systemctl is-enabled {SERVICE} 2>&1; systemctl is-active {SERVICE} 2>&1; "
           f"journalctl -u {SERVICE} -n {int(lines)} --no-pager 2>&1 | tail -{int(lines)}")
    return _ssh(host, cmd, ssh_port, mutating=False)


def check_sensor_ui(address: str, pi_port: int = 8080) -> str:
    """Fetch the sensor's own monitor UI state endpoint. address is host or IP."""
    url = f"http://{address.split('@')[-1]}:{pi_port}/pi/state"
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            body = json.load(r)
        return f"OK {url}\n" + json.dumps(body, indent=2)[:1200]
    except Exception as e:
        return f"UNREACHABLE {url}: {e}"


def check_registered(geoai_url: str, geoai_user: str = "admin",
                     geoai_pass: str = "") -> str:
    """Check the GeoAI server has received a heartbeat from a sensor.

    Lists every registered sensor with its online state and age in seconds."""
    geoai_pass = geoai_pass or os.environ.get("GEOAI_PASS", "geoai2026")
    geoai_user = os.environ.get("GEOAI_USER", geoai_user)
    base = geoai_url.rstrip("/")
    hdr = {"User-Agent": "geoai-install-agent/1.0", "Content-Type": "application/json"}
    try:
        body = json.dumps({"user": geoai_user, "pass": geoai_pass}).encode()
        req = urllib.request.Request(base + "/api/login", data=body, headers=hdr)
        with urllib.request.urlopen(req, timeout=20) as r:
            token = json.load(r)["token"]
        req = urllib.request.Request(base + "/api/state",
                                     headers={**hdr, "X-Auth": token})
        with urllib.request.urlopen(req, timeout=20) as r:
            sensors = json.load(r)["sensors"]
    except Exception as e:
        return f"ERROR talking to {base}: {e}"
    if not sensors:
        return f"No sensors registered on {base} yet."
    return "\n".join(f"{s['name']} site={s.get('site')} zone={s.get('zone')} "
                     f"online={s['online']} age={s['age']}s "
                     f"recovered={s.get('recovered')}" for s in sensors)


TOOLS = [check_host, copy_sensor, install_service, service_status,
         check_sensor_ui, check_registered]

SYSTEM = """You install GeoAI FTTH edge sensor nodes on Raspberry Pi hardware.

Work through this runbook, one tool call at a time, and read each result before
the next step:

1. check_host — confirm SSH works, python3 exists, systemd is present. If port
   8080 is busy, say so; an older sensor is probably still running.
2. copy_sensor — place pi_agent.py on the node.
3. install_service — install the systemd unit with the operator's GEOAI_URL,
   zone and site so the sensor restarts on boot.
4. check_sensor_ui — the node should serve its own state on port 8080.
5. check_registered — the GeoAI server should list the new sensor as online
   with a low age. This is the real success criterion: a sensor that runs but
   never registers is a failed install.

If a step fails, call service_status to read the journal, state the specific
cause, and stop. Do not retry the same failing command more than once. Never
claim the install succeeded unless check_registered shows the sensor online.

Results beginning with "DRY RUN" mean nothing was executed — the operator is
reviewing the plan. Continue through the remaining steps so they see the whole
sequence, and finish by telling them to re-run with --apply.

Finish with a short report: what was installed where, the sensor name the
server sees, and anything the operator still has to do."""


def build_agent(model=None):
    """Build the LangGraph ReAct agent. Imports live here so --check runs
    without the optional dependencies installed."""
    from langchain_openai import ChatOpenAI
    from langgraph.prebuilt import create_react_agent

    model = model or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    llm = ChatOpenAI(model=model, temperature=0)
    return create_react_agent(llm, TOOLS, prompt=SYSTEM)


def check():
    """Offline self-check: command construction and the dry-run guarantee."""
    global EXECUTE
    EXECUTE = False
    argv = _ssh_argv("kobi@10.0.0.5", "hostname", 2222)
    assert argv[:3] == ["ssh", "-p", "2222"] and argv[-2:] == ["kobi@10.0.0.5", "hostname"], argv
    assert "BatchMode=yes" in argv, "ssh must not hang on a password prompt"

    out = check_host("kobi@10.0.0.5")
    assert "DRY RUN" not in out, "read-only probe should execute, not dry-run"

    for call in (lambda: copy_sensor("kobi@10.0.0.5"),
                 lambda: install_service("kobi@10.0.0.5", "http://server:3030", zone="LPB")):
        r = call()
        assert r.startswith("DRY RUN"), f"mutating tool executed without --apply: {r[:80]}"

    unit = install_service("kobi@10.0.0.5", "http://server:3030", zone="LPB", site="Mekong")
    for expect in ("GEOAI_URL=http://server:3030", "SENSOR_ZONE=LPB", "SENSOR_SITE=Mekong",
                   "User=kobi", "Restart=always", "enable --now geoai-sensor"):
        assert expect in unit, f"unit file missing {expect!r}"

    assert SENSOR_SRC.exists(), f"{SENSOR_SRC} missing — agent must ship next to the repo"
    names = {t.__name__ for t in TOOLS}
    assert names == {"check_host", "copy_sensor", "install_service", "service_status",
                     "check_sensor_ui", "check_registered"}, names
    assert all(t.__doc__ for t in TOOLS), "every tool needs a docstring — it is the schema"
    graph = ""
    try:  # only when the optional deps are installed
        from langchain_core.messages import AIMessage
        from langgraph.prebuilt import ToolNode
        out = ToolNode(TOOLS).invoke({"messages": [AIMessage(content="", tool_calls=[
            {"name": "install_service", "id": "1",
             "args": {"host": "kobi@10.0.0.5", "geoai_url": "http://server:3030"}}])]})
        assert out["messages"][0].content.startswith("DRY RUN"), \
            "dry run must hold when the tool is called through LangGraph"
        graph = ", LangGraph tool node"
    except ImportError:
        graph = ", LangGraph not installed (skipped graph check)"
    print(f"self-check OK: {len(TOOLS)} tools, dry-run holds, unit file renders{graph}")


def main():
    global EXECUTE
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", help="SSH target for the Pi, e.g. kobi@192.168.0.110")
    ap.add_argument("--geoai-url", default=os.environ.get("GEOAI_URL",
                    "https://geoai-ftth-demo.laopadit.com"))
    ap.add_argument("--zone", default="VTE", help="province zone this sensor guards")
    ap.add_argument("--site", default="", help="human-readable site name")
    ap.add_argument("--dir", default="/home/kobi/geoai-sensor")
    ap.add_argument("--ssh-port", type=int, default=22)
    ap.add_argument("--model", default=None, help="OpenAI model (default gpt-4o-mini)")
    ap.add_argument("--apply", action="store_true",
                    help="actually execute; without it every mutating step is a dry run")
    ap.add_argument("--check", action="store_true", help="offline self-check and exit")
    a = ap.parse_args()

    if a.check:
        return check()
    if not a.host:
        ap.error("--host is required (or use --check)")
    if not os.environ.get("OPENAI_API_KEY"):
        sys.exit("OPENAI_API_KEY is not set — export it first.")

    EXECUTE = a.apply
    print(f"{'APPLYING' if EXECUTE else 'DRY RUN'} — install sensor on {a.host}, "
          f"reporting to {a.geoai_url}\n")
    task = (f"Install a GeoAI edge sensor on host {a.host} (ssh port {a.ssh_port}) into "
            f"{a.dir}. It must report to {a.geoai_url}, guarding zone {a.zone}"
            + (f' at site "{a.site}"' if a.site else "") + ".")

    agent = build_agent(a.model)
    for step in agent.stream({"messages": [("user", task)]}, stream_mode="values"):
        step["messages"][-1].pretty_print()


if __name__ == "__main__":
    main()
