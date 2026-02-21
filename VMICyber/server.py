"""
CTF Agent GUI — Flask + Socket.IO backend
Open http://localhost:7331 in your browser
"""

import io
import json
import os
import tarfile
import threading
import time
import uuid
from types import SimpleNamespace
from datetime import datetime
from pathlib import Path

import docker
from flask import Flask, jsonify, request, send_from_directory, render_template
from flask_socketio import SocketIO, emit
from openai import OpenAI
from werkzeug.utils import secure_filename

# ─── App setup ────────────────────────────────────────────────────────────────

BASE_DIR    = Path(__file__).parent
CONFIG_PATH = BASE_DIR / "config.json"
DB_PATH     = BASE_DIR / "challenges.json"
UPLOAD_DIR  = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "ctf-agent-secret"
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024 * 1024  # 256MB max upload
# Flask 3.x removed RequestContext.session setter; disable server-managed sessions
# to avoid Socket.IO setting ctx.session (not needed here).
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading", manage_session=False)

# ─── Config ───────────────────────────────────────────────────────────────────

def load_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    return json.load(open(CONFIG_PATH))

# ─── Challenge DB ─────────────────────────────────────────────────────────────

CATEGORIES = ["pwn", "web", "crypto", "forensics", "rev", "misc", "osint", "network"]

def load_challenges() -> list[dict]:
    if not DB_PATH.exists():
        return []
    return json.load(open(DB_PATH))

def save_challenges(challenges: list[dict]):
    json.dump(challenges, open(DB_PATH, "w"), indent=2)

def get_challenge(cid: str) -> dict | None:
    return next((c for c in load_challenges() if c["id"] == cid), None)

def update_challenge(cid: str, **kwargs):
    chals = load_challenges()
    for c in chals:
        if c["id"] == cid:
            c.update(kwargs)
    save_challenges(chals)

# ─── Docker ───────────────────────────────────────────────────────────────────

IMAGE_NAME       = "ctf-kali:latest"
CONTAINER_PREFIX = "ctf-agent-"
_docker_client   = None

def get_docker():
    global _docker_client
    if _docker_client is None:
        _docker_client = docker.from_env()
    return _docker_client

def image_exists() -> bool:
    try:
        get_docker().images.get(IMAGE_NAME)
        return True
    except:
        return False

class ContainerConnection:
    def __init__(self, challenge_id: str):
        self.cid       = challenge_id
        self._lock     = threading.Lock()
        self.container = None

    def start(self):
        name = f"{CONTAINER_PREFIX}{self.cid}"
        try:
            old = get_docker().containers.get(name)
            old.remove(force=True)
        except docker.errors.NotFound:
            pass
        self.container = get_docker().containers.run(
            IMAGE_NAME,
            name=name,
            command="sleep infinity",
            detach=True,
            remove=False,
            mem_limit="2g",
            cpu_period=100000,
            cpu_quota=200000,
            network_mode="bridge",
            privileged=False,
            security_opt=["no-new-privileges"],
            working_dir="/ctf",
        )
        self.run("mkdir -p /ctf")

    def run(self, cmd: str, timeout: int = 60) -> str:
        with self._lock:
            if not self.container:
                return "[container not running]"
            try:
                _, output = self.container.exec_run(
                    ["bash", "-c", cmd], workdir="/ctf",
                    demux=False
                )
                return (output or b"").decode("utf-8", errors="replace").strip()
            except Exception as e:
                return f"[exec error: {e}]"

    def run_gdb(self, binary: str, gdb_cmds: list, timeout: int = 30) -> str:
        batch = " ".join(f'-ex "{c}"' for c in gdb_cmds)
        return self.run(f"gdb -batch -nx {batch} {binary} 2>&1", timeout)

    def upload_file(self, local_path: str) -> str:
        local  = Path(local_path)
        fname  = local.name
        buf    = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            tar.add(str(local), arcname=fname)
        buf.seek(0)
        self.container.put_archive("/ctf", buf)
        ext = local.suffix.lower()
        if ext == ".zip":
            self.run(f"cd /ctf && unzip -o '{fname}' 2>&1")
        elif ext in (".tar", ".gz", ".tgz", ".bz2", ".xz"):
            self.run(f"cd /ctf && tar xf '{fname}' 2>&1")
        return f"/ctf/{fname}"

    def stop(self):
        if self.container:
            try:
                self.container.remove(force=True)
            except:
                pass
            self.container = None

    @property
    def running(self) -> bool:
        if not self.container:
            return False
        try:
            self.container.reload()
            return self.container.status == "running"
        except:
            return False

# Per-challenge container registry
_containers: dict[str, ContainerConnection] = {}

def get_container(cid: str) -> ContainerConnection:
    if cid not in _containers or not _containers[cid].running:
        _containers[cid] = ContainerConnection(cid)
        _containers[cid].start()
    return _containers[cid]

def sync_challenge_uploads(cid: str, container: ContainerConnection):
    # Rehydrate files from host uploads into a fresh container.
    chal_upload_dir = UPLOAD_DIR / cid
    if not chal_upload_dir.exists():
        return
    files = []
    for p in sorted(chal_upload_dir.iterdir()):
        if p.is_file():
            container.upload_file(str(p))
            files.append(p.name)
    if files:
        update_challenge(cid, files=files)

# ─── Category Prompts ─────────────────────────────────────────────────────────

BASE_RULES = """You are an elite CTF security researcher in a Kali Linux Docker container.
Working directory: /ctf/ (all challenge files are here)
Tools available: pwntools, gdb+pwndbg, checksec, ROPgadget, sqlmap, gobuster, RsaCtfTool, binwalk, steghide, zsteg, hashcat, john, and more.

RULES:
- Use run_command for bash commands
- Use run_gdb for binary debugging (isolated, won't hang)
- Use submit_flag the instant you find it
- Never guess. Find flags empirically.
- Don't repeat failed commands
"""

CATEGORY_PROMPTS = {
    "pwn": BASE_RULES + "\nBINARY EXPLOITATION EXPERT.\nStart: checksec, file, strings | grep flag. Then GDB with cyclic pattern for overflow offset. Use pwntools for exploits. Know: ret2libc, ROP chains, format strings, heap.\n",
    "web": BASE_RULES + "\nWEB EXPLOITATION EXPERT.\nStart: curl -sv URL, robots.txt, gobuster. Try: sqlmap --forms, JWT (alg:none), LFI, SSRF, command injection. Default creds: admin/admin.\n",
    "crypto": BASE_RULES + "\nCRYPTOGRAPHY EXPERT.\nFor RSA: RsaCtfTool -n N -e E --attack all --uncipher C. Know: small-e, Wiener, Fermat factoring, XOR key recovery, padding oracles, frequency analysis.\n",
    "forensics": BASE_RULES + "\nFORENSICS EXPERT.\nStart: file *, strings * | grep -i flag, binwalk *, exiftool *. Steg: steghide extract -sf img -p '', zsteg img -a. PCAP: tshark -r file -qz io,phs.\n",
    "rev": BASE_RULES + "\nREVERSE ENGINEERING EXPERT.\nStart: file, strings (look for flag directly), ltrace (catches strcmp!), strace, objdump -d. GDB for dynamic analysis. upx -d for packed binaries.\n",
    "misc": BASE_RULES + "\nMISC EXPERT.\nTry all encodings: base64 -d, xxd -r -p, ROT13, binary, morse. Check steg even on non-images. Scripting challenges: find logic flaws.\n",
    "osint": BASE_RULES + "\nOSINT EXPERT.\nExtract names/usernames from description. GitHub API: curl api.github.com/users/X. Wayback: archive.org. DNS: whois, dig. exiftool for GPS metadata.\n",
    "network": BASE_RULES + "\nNETWORK EXPERT.\nPCAP first: tshark -r file -qz io,phs. Extract creds: filter ftp/http. Follow streams: -qz follow,tcp,ascii,0. Live target: nmap -sV -sC.\n",
}

CTF_TOOLS = [
    {"type": "function", "function": {
        "name": "run_command",
        "description": "Run a bash command in the Kali container at /ctf/",
        "parameters": {"type": "object", "properties": {
            "command":      {"type": "string", "description": "Bash command to run"},
            "reasoning":    {"type": "string", "description": "Why you're running this"},
            "long_running": {"type": "boolean", "description": "True for hashcat/sqlmap/gobuster (120s timeout)"}
        }, "required": ["command", "reasoning"]}
    }},
    {"type": "function", "function": {
        "name": "run_gdb",
        "description": "Run GDB in batch mode on a binary. Never hangs.",
        "parameters": {"type": "object", "properties": {
            "binary_path":  {"type": "string", "description": "Path like /ctf/vuln"},
            "gdb_commands": {"type": "array", "items": {"type": "string"},
                             "description": "GDB commands: ['checksec', 'info functions', 'run <<< $(python3 -c \"print(chr(65)*200)\")']"}
        }, "required": ["binary_path", "gdb_commands"]}
    }},
    {"type": "function", "function": {
        "name": "submit_flag",
        "description": "Submit the flag immediately when found.",
        "parameters": {"type": "object", "properties": {
            "flag":     {"type": "string", "description": "The flag value"},
            "how_found":{"type": "string", "description": "How you found it"}
        }, "required": ["flag", "how_found"]}
    }},
]

MODEL_COSTS = {
    "gpt-4o": (5.00, 15.00), "gpt-4o-mini": (0.15, 0.60),
    "gpt-4.1": (2.00, 8.00), "gpt-4.1-mini": (0.40, 1.60),
    "o1": (15.00, 60.00), "o1-mini": (3.00, 12.00),
}

# ─── CTF Agent ─────────────────────────────────────────────────────────────────

class CTFAgent:
    def __init__(self, cid, category, container, room):
        cfg          = load_config()
        self.cid     = cid
        self.category= category
        self.container = container
        self.room    = room  # socket.io room = challenge id
        self.client  = OpenAI(api_key=cfg.get("openai_api_key") or os.environ.get("OPENAI_API_KEY"))
        self.model   = cfg.get("model", "gpt-4o")
        self.messages= []
        self.running = False
        self.step    = 0
        self.total_in= 0
        self.total_out=0

    def emit(self, event, data):
        socketio.emit(event, data, room=self.room)

    def start(self, challenge_desc: str, prior_summary: str | None = None):
        self.running = True
        threading.Thread(
            target=self._run,
            args=(challenge_desc, prior_summary),
            daemon=True
        ).start()

    def stop(self):
        self.running = False

    def _system_prompt(self):
        return CATEGORY_PROMPTS.get(self.category, BASE_RULES)

    def _token_limit_kw(self, max_tokens: int) -> dict:
        # Newer reasoning models (e.g., o1/o3/gpt-5) use max_completion_tokens.
        model = (self.model or "").lower()
        if model.startswith(("o1", "o3", "gpt-5")):
            return {"max_completion_tokens": max_tokens}
        return {"max_tokens": max_tokens}

    def _sanitize_messages(self, messages: list[dict]) -> list[dict]:
        # Ensure tool role messages only appear after a matching assistant tool_calls message.
        out = []
        expected_tool_ids = set()
        for m in messages:
            role = m.get("role")
            if role == "assistant" and m.get("tool_calls"):
                expected_tool_ids = {tc.get("id") for tc in m.get("tool_calls", []) if tc.get("id")}
                out.append(m)
                continue
            if role == "tool":
                if expected_tool_ids and m.get("tool_call_id") in expected_tool_ids:
                    out.append(m)
                # else drop orphan tool message
                continue
            # normal user/assistant/system
            expected_tool_ids = set()
            out.append(m)
        return out

    def _emit_stream_delta(self, stream_id: str, text: str, msg_type: str):
        self.emit("thought_stream_delta", {"id": stream_id, "text": text, "type": msg_type})

    def _call(self, force_text=False):
        msg_list = self._sanitize_messages(self.messages)
        kwargs = dict(
            model=self.model,
            **self._token_limit_kw(2048),
            messages=[{"role": "system", "content": self._system_prompt()}] + msg_list,
            stream=True,
            stream_options={"include_usage": True},
        )
        if not force_text:
            kwargs["tools"] = CTF_TOOLS
            kwargs["tool_choice"] = "auto"

        stream = self.client.chat.completions.create(**kwargs)
        content_parts = []
        tool_calls = {}
        usage = None
        stream_id = uuid.uuid4().hex
        msg_type = "reasoning"
        started = False

        for chunk in stream:
            if getattr(chunk, "usage", None):
                usage = chunk.usage
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta
            if not delta:
                continue
            if getattr(delta, "content", None):
                if not started:
                    self.emit("thought_stream_start", {"id": stream_id, "type": msg_type})
                    started = True
                text = delta.content
                content_parts.append(text)
                self._emit_stream_delta(stream_id, text, msg_type)
            if getattr(delta, "tool_calls", None):
                for tc in delta.tool_calls:
                    idx = tc.index
                    if idx not in tool_calls:
                        tool_calls[idx] = {"id": tc.id, "type": tc.type, "function": {"name": "", "arguments": ""}}
                    if tc.id:
                        tool_calls[idx]["id"] = tc.id
                    if tc.function:
                        if tc.function.name:
                            tool_calls[idx]["function"]["name"] = tc.function.name
                        if tc.function.arguments:
                            tool_calls[idx]["function"]["arguments"] += tc.function.arguments

        if started:
            self.emit("thought_stream_end", {"id": stream_id})

        if usage:
            self.total_in  += usage.prompt_tokens
            self.total_out += usage.completion_tokens
            key = self.model.split("-20")[0]
            ir, or_ = MODEL_COSTS.get(key, (10.0, 30.0))
            cost = (self.total_in * ir + self.total_out * or_) / 1_000_000
            self.emit("cost", {"cost": f"${cost:.4f}", "tokens_in": self.total_in, "tokens_out": self.total_out})

        content = "".join(content_parts) if content_parts else None
        tc_objs = None
        tc_raw = None
        if tool_calls:
            ordered = [tool_calls[i] for i in sorted(tool_calls.keys())]
            tc_objs = []
            tc_raw = []
            for t in ordered:
                fn = SimpleNamespace(name=t["function"]["name"], arguments=t["function"]["arguments"])
                tc_objs.append(SimpleNamespace(id=t["id"], type=t.get("type", "function"), function=fn))
                tc_raw.append({
                    "id": t["id"],
                    "type": t.get("type", "function"),
                    "function": {
                        "name": t["function"]["name"],
                        "arguments": t["function"]["arguments"],
                    },
                })

        return SimpleNamespace(content=content, tool_calls=tc_objs, tool_calls_raw=tc_raw)

    def _summarize(self):
        self.emit("thought", {"text": "── Summarizing context ──", "type": "system"})
        try:
            # Avoid tool messages in the summary prompt to prevent invalid tool-call pairing.
            tail = [m for m in self.messages[-12:] if m.get("role") != "tool"]
            r = self.client.chat.completions.create(
                model=self.model, **self._token_limit_kw(400),
                messages=[{"role": "user", "content":
                    "Summarize this CTF session: files found, tried, failed, theory, next steps.\n\n"
                    + json.dumps(tail, indent=2)}]
            )
            summary = r.choices[0].message.content or ""
            # Keep only summary + last few non-tool messages to avoid invalid tool history.
            tail2 = [m for m in self.messages[-3:] if m.get("role") != "tool"]
            self.messages = self.messages[:2] + [
                {"role": "user", "content": f"[SESSION SUMMARY]\n{summary}"}
            ] + tail2
        except:
            pass

    def _save_retry_summary(self):
        try:
            r = self.client.chat.completions.create(
                model=self.model, **self._token_limit_kw(500),
                messages=[{"role": "user", "content":
                    "Summarize this FAILED CTF attempt for a retry: files, tried, failed, unexplored, next approach.\n\n"
                    + json.dumps(self.messages[-20:], indent=2)}]
            )
            update_challenge(self.cid, retry_summary=r.choices[0].message.content)
        except:
            pass

    def _run(self, challenge_desc, prior_summary):
        # Auto recon
        recon = self.container.run("ls -la /ctf/ && echo '---' && file /ctf/* 2>/dev/null")
        self.emit("output", {"text": f"[auto-recon]\n{recon}"})

        prior_ctx = f"\n\n[PRIOR ATTEMPT]\n{prior_summary}" if prior_summary else ""
        initial = (
            f"{challenge_desc}\n\nFiles in container:\n{recon}{prior_ctx}\n\n"
            f"First, write a numbered attack plan for this {self.category.upper()} challenge."
        )
        self.messages.append({"role": "user", "content": initial})

        # Planning turn
        self.emit("thought", {"text": "Building attack plan...", "type": "system"})
        plan_msg = self._call(force_text=True)
        plan_text = plan_msg.content or ""
        self.messages.append({"role": "assistant", "content": plan_text})
        self.emit("plan", {"text": plan_text})
        self.messages.append({"role": "user", "content": "Good. Execute your plan using the tools."})

        for self.step in range(60):
            if not self.running:
                break

            if self.step > 0 and self.step % 10 == 0:
                self._summarize()

            if self.step == 6:
                self.emit("thought", {"text": "Mid-session re-plan...", "type": "system"})
                self.messages.append({"role": "user", "content":
                    "Pause. Reflect on what you've found. Update your attack plan. What's confirmed, ruled out, most promising? Continue."
                })
                rp = self._call(force_text=True)
                rp_text = rp.content or ""
                self.messages.append({"role": "assistant", "content": rp_text})
                self.emit("plan", {"text": f"[Re-plan @ step 6]\n{rp_text}", "replan": True})
                self.messages.append({"role": "user", "content": "Continue executing."})

            try:
                msg = self._call()
            except Exception as e:
                self.emit("thought", {"text": f"API error: {e}", "type": "error"})
                break

            if msg.content:
                self.emit("thought", {"text": msg.content, "type": "reasoning"})

            if not msg.tool_calls:
                self.messages.append({"role": "assistant", "content": msg.content or ""})
                self.messages.append({"role": "user", "content": "Use a tool. Run a command or submit the flag."})
                continue

            self.messages.append({
                "role": "assistant",
                "content": msg.content or "",
                "tool_calls": msg.tool_calls_raw or [],
            })

            for tc in msg.tool_calls:
                fn   = tc.function.name
                args = json.loads(tc.function.arguments)
                result = self._dispatch(fn, args)
                self.messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
                if fn == "submit_flag":
                    return

        if self.running:
            self.emit("done", {"status": "unsolved", "message": "Max steps reached without finding the flag."})
            self._save_retry_summary()
            update_challenge(self.cid, status="unsolved")
        self.running = False

    def _dispatch(self, fn, args):
        if fn == "run_command":
            cmd      = args["command"]
            reason   = args.get("reasoning", "")
            timeout  = 120 if args.get("long_running") else 60
            self.emit("thought", {"text": reason, "type": "reasoning"})
            self.emit("command", {"cmd": cmd})
            out = self.container.run(cmd, timeout=timeout)
            self.emit("output", {"text": out})
            return out or "(no output)"

        elif fn == "run_gdb":
            binary = args["binary_path"]
            cmds   = args["gdb_commands"]
            label  = f"gdb {binary} [{', '.join(cmds[:2])}{'…' if len(cmds)>2 else ''}]"
            self.emit("command", {"cmd": label, "gdb": True})
            out = self.container.run_gdb(binary, cmds)
            self.emit("output", {"text": out})
            return out or "(no output)"

        elif fn == "submit_flag":
            flag = args["flag"]
            how  = args.get("how_found", "")
            update_challenge(self.cid, status="solved", flag=flag)
            self.emit("flag", {"flag": flag, "how": how})
            self.emit("done", {"status": "solved"})
            self.running = False
            return f"Flag: {flag}"

        return f"Unknown: {fn}"


# Active agents registry
_agents: dict[str, CTFAgent] = {}

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

# Challenges CRUD
@app.route("/api/challenges", methods=["GET"])
def get_challenges():
    return jsonify(load_challenges())

@app.route("/api/challenges", methods=["POST"])
def create_challenge():
    data = request.json
    chal = {
        "id":            str(uuid.uuid4())[:8],
        "name":          data.get("name", "Untitled"),
        "category":      data.get("category", "misc"),
        "flag_format":   data.get("flag_format", ""),
        "description":   data.get("description", ""),
        "files":         [],
        "status":        "unsolved",
        "flag":          None,
        "retry_summary": None,
        "created_at":    datetime.now().isoformat(),
        "cost_usd":      0.0,
    }
    chals = load_challenges()
    chals.append(chal)
    save_challenges(chals)
    return jsonify(chal)

@app.route("/api/challenges/<cid>", methods=["GET"])
def get_challenge_route(cid):
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    return jsonify(chal)

@app.route("/api/challenges/<cid>", methods=["PUT"])
def update_challenge_route(cid):
    data = request.json
    update_challenge(cid, **data)
    return jsonify(get_challenge(cid))

@app.route("/api/challenges/<cid>", methods=["DELETE"])
def delete_challenge(cid):
    if cid in _containers:
        threading.Thread(target=_containers[cid].stop, daemon=True).start()
        del _containers[cid]
    if cid in _agents:
        _agents[cid].stop()
        del _agents[cid]
    save_challenges([c for c in load_challenges() if c["id"] != cid])
    return jsonify({"ok": True})

# File upload
@app.route("/api/challenges/<cid>/upload", methods=["POST"])
def upload_file(cid):
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Challenge not found"}), 404

    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400

    f     = request.files["file"]
    fname = secure_filename(f.filename)
    if not fname:
        return jsonify({"error": "Invalid filename"}), 400

    # Use per-challenge subdirectory to prevent filename collisions across challenges
    chal_upload_dir = UPLOAD_DIR / cid
    chal_upload_dir.mkdir(exist_ok=True)
    local = chal_upload_dir / fname
    f.save(str(local))

    try:
        container = get_container(cid)
        remote    = container.upload_file(str(local))
        listing   = container.run("ls -lh /ctf/")
        files     = chal.get("files", [])
        if fname not in files:
            files.append(fname)
        update_challenge(cid, files=files)
        socketio.emit("file_uploaded", {"name": fname, "listing": listing}, room=cid)
        return jsonify({"ok": True, "name": fname, "remote": remote, "listing": listing})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Agent control
@app.route("/api/challenges/<cid>/launch", methods=["POST"])
def launch_agent(cid):
    data  = request.json or {}
    retry = data.get("retry", False)
    chal  = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    if not image_exists():
        return jsonify({"error": "Docker image not built"}), 400

    if cid in _agents and _agents[cid].running:
        return jsonify({"error": "Agent already running"}), 400

    try:
        container = get_container(cid)
        sync_challenge_uploads(cid, container)
    except Exception as e:
        return jsonify({"error": f"Container failed: {e}"}), 500

    flag_fmt  = chal.get("flag_format", "")
    extra     = data.get("extra_context", "")
    full_desc = (
        f"Challenge: {chal['name']}\n"
        f"Category: {chal['category'].upper()}\n"
        f"Working directory: /ctf/\n"
        + (f"Flag format: {flag_fmt}\n" if flag_fmt else "")
        + (f"\n{chal.get('description', '')}\n" if chal.get("description") else "")
        + (f"\nAdditional context: {extra}\n" if extra else "")
    )

    prior = chal.get("retry_summary") if retry else None
    update_challenge(cid, status="solving")

    agent = CTFAgent(cid, chal.get("category", "misc"), container, room=cid)
    _agents[cid] = agent
    agent.start(full_desc, prior_summary=prior)

    return jsonify({"ok": True})

@app.route("/api/challenges/<cid>/stop", methods=["POST"])
def stop_agent(cid):
    if cid in _agents:
        _agents[cid].stop()
    update_challenge(cid, status="unsolved")
    return jsonify({"ok": True})

@app.route("/api/challenges/<cid>/reset", methods=["POST"])
def reset_container(cid):
    if cid in _agents:
        _agents[cid].stop()
    if cid in _containers:
        _containers[cid].stop()
        del _containers[cid]
    update_challenge(cid, files=[], status="unsolved", flag=None, retry_summary=None)
    return jsonify({"ok": True})

# Docker management
@app.route("/api/docker/status", methods=["GET"])
def docker_status():
    try:
        get_docker().ping()
        has_image = image_exists()
        return jsonify({"running": True, "image": has_image})
    except Exception as e:
        return jsonify({"running": False, "error": str(e)})

@app.route("/api/docker/build", methods=["POST"])
def build_image():
    def _build():
        try:
            socketio.emit("build_log", {"line": "Starting build...", "done": False})
            client = get_docker()
            for log in client.api.build(
                path=str(BASE_DIR),
                tag=IMAGE_NAME,
                rm=True,
                platform="linux/amd64",
                decode=True,
            ):
                if "stream" in log:
                    line = log["stream"].strip()
                    if line:
                        socketio.emit("build_log", {"line": line, "done": False})
                elif "error" in log:
                    socketio.emit("build_log", {"line": f"ERROR: {log['error']}", "done": True, "error": True})
                    return
            socketio.emit("build_log", {"line": "✓ Image built successfully!", "done": True, "error": False})
        except Exception as e:
            socketio.emit("build_log", {"line": f"Build failed: {e}", "done": True, "error": True})

    threading.Thread(target=_build, daemon=True).start()
    return jsonify({"ok": True})

# Socket.IO — join challenge room for real-time updates
@socketio.on("join")
def on_join(data):
    from flask_socketio import join_room
    cid = data.get("cid")
    if cid:
        join_room(cid)

if __name__ == "__main__":
    print("\n  CTF Agent GUI")
    print("  ─────────────────────────────")
    print("  Open http://localhost:7331\n")
    socketio.run(app, host="0.0.0.0", port=7331, debug=False, allow_unsafe_werkzeug=True)
