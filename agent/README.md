# Sensor-node install agent (LangGraph + OpenAI)

An agentic installer for GeoAI FTTH edge sensor nodes. Give it a Raspberry Pi and a
GeoAI server; it works through the install runbook, reads each result, and stops with
a diagnosis if a step fails.

It is the automated form of [`deploy_pi.sh`](../deploy_pi.sh) plus
[`geoai-sensor.service`](../geoai-sensor.service), with the verification that script
never did: a sensor that runs but never registers with the server is a failed install,
and the agent is told to treat it as one.

## Install

```bash
pip install -r requirements.txt        # langgraph, langchain-openai
export OPENAI_API_KEY=sk-...
```

This is the only part of the platform with third-party dependencies. The SOC core
stays stdlib-only; the agent is a separate operator tool, not a runtime component.

## Use

```bash
# read the plan — nothing touches the Pi
python3 install_sensor_agent.py --host kobi@192.168.0.110 --zone VTE

# actually install
python3 install_sensor_agent.py --host kobi@192.168.0.110 \
    --geoai-url https://geoai-ftth-demo.laopadit.com \
    --zone LPB --site "Luang Prabang exchange" --apply
```

| Flag | Default | |
|---|---|---|
| `--host` | *(required)* | SSH target, `user@address` |
| `--geoai-url` | `https://geoai-ftth-demo.laopadit.com` | Server the sensor reports to |
| `--zone` / `--site` | `VTE` / *(derived)* | Province zone the sensor guards, and its site label |
| `--dir` | `/home/kobi/geoai-sensor` | Install directory on the Pi |
| `--ssh-port` | `22` | |
| `--model` | `gpt-4o-mini` (`OPENAI_MODEL`) | Any OpenAI chat model |
| `--apply` | off | **Without this every mutating step is a dry run** |
| `--check` | — | Offline self-check; no API key, no network |

SSH uses `BatchMode=yes`, so set up key auth first — the agent cannot answer a password
prompt:

```bash
ssh-copy-id kobi@192.168.0.110
```

`install_service` uses `sudo` on the Pi for the unit file; passwordless sudo or a
pre-authorised session is required.

## The runbook

```
check_host → copy_sensor → install_service → check_sensor_ui → check_registered
                                 ↓ on failure
                           service_status (journal)
```

| Tool | Mutates | What it does |
|---|---|---|
| `check_host` | no | SSH reachability, OS, arch, python3, systemd, whether port 8080 is busy |
| `copy_sensor` | **yes** | Ships `pi_agent.py` to the install directory |
| `install_service` | **yes** | Renders and installs the systemd unit with `GEOAI_URL`/zone/site/coords, enables and starts it |
| `service_status` | no | `is-enabled`, `is-active` and the last journal lines |
| `check_sensor_ui` | no | `GET http://pi:8080/pi/state` — the node's own monitor UI |
| `check_registered` | no | Logs into the GeoAI server and lists registered sensors with online state and heartbeat age |

## Design notes

**No arbitrary-shell tool.** Every tool is a fixed command template. The model decides
*which* step to take and with what parameters, never *what to execute* — so a bad
completion cannot turn into an arbitrary command on your infrastructure.

**Dry run is the default.** `EXECUTE` is false unless `--apply` is passed, and the two
mutating tools return the exact command they would have run. Read-only probes always
execute, since they cannot damage the node.

**Success is defined at the server, not the node.** The agent is instructed never to
report success unless `check_registered` shows the sensor online with a low heartbeat
age.

## Self-check

```bash
python3 install_sensor_agent.py --check
```

Verifies command construction, that `BatchMode=yes` is set, that the rendered unit file
carries the right environment, and that mutating tools refuse to execute without
`--apply`. With `langgraph` installed it also runs a tool through a real `ToolNode` to
confirm the dry-run guarantee survives the graph. Runs offline, no API key.
