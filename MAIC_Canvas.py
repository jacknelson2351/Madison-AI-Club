#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════╗
║        MAIC  ·  Canvas AI Chat               ║
║   Chat with an AI about your real courses    ║
╚══════════════════════════════════════════════╝

  HOW TO USE — 3 steps:
  1. Paste your Canvas token  →  CANVAS_TOKEN  (line 20)
  2. Paste your Gemini key    →  GEMINI_KEY     (line 21)
  3. Run:  python canvas_ai_chat.py

  Get Canvas token:  canvas.jmu.edu → Account → Settings → New Access Token
  Get Gemini key:    aistudio.google.com → Get API Key
"""

# ── PASTE YOUR KEYS HERE ──────────────────────────────────────────
CANVAS_TOKEN = "Canvas_Key"
GEMINI_KEY   = "Gemini_Key"
# ─────────────────────────────────────────────────────────────────

# ── CONFIG ────────────────────────────────────────────────────────
CANVAS_BASE  = "https://canvas.jmu.edu/api/v1"
GEMINI_MODEL = "gemini-2.5-flash"
# ─────────────────────────────────────────────────────────────────

import os, re, sys, subprocess
from html import unescape
from datetime import datetime, timezone

# ── Auto-install missing packages ─────────────────────────────────
def _install(pkg):
    for flags in [[], ["--break-system-packages"], ["--user"]]:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "-q", pkg] + flags,
                stderr=subprocess.DEVNULL
            )
            return True
        except subprocess.CalledProcessError:
            pass
    return False

try:
    from google import genai
    from google.genai import types
except ImportError:
    print("  Installing google-genai (one-time, ~5 seconds)...")
    if not _install("google-genai"):
        print("  Could not auto-install. Run manually:  pip install google-genai")
        sys.exit(1)
    from google import genai
    from google.genai import types

try:
    import requests
except ImportError:
    print("  Installing requests...")
    _install("requests")
    import requests

# ── ANSI colors ───────────────────────────────────────────────────
class C:
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    ORANGE = "\033[38;5;208m"
    RED    = "\033[91m"
    PURPLE = "\033[95m"
    RESET  = "\033[0m"
    CLEAR  = "\033[2J\033[H"

def c(color, text):
    return f"{color}{text}{C.RESET}"

def banner():
    print(C.CLEAR, end="")
    print(c(C.CYAN, C.BOLD + """
  ╔══════════════════════════════════════════════════════╗
  ║          MAIC  ·  Canvas AI Chat  🎓                 ║
  ║     Ask anything about your real courses             ║
  ╚══════════════════════════════════════════════════════╝
""" + C.RESET))

# ── Canvas helpers ─────────────────────────────────────────────────
HTML_TAG = re.compile(r"<[^>]+>")

def strip_html(text):
    return unescape(HTML_TAG.sub("", text or "")).strip()

def canvas_get(endpoint, params=None):
    headers = {"Authorization": f"Bearer {CANVAS_TOKEN}"}
    url = f"{CANVAS_BASE}/{endpoint.lstrip('/')}"
    r = requests.get(url, headers=headers, params=params, timeout=20)
    r.raise_for_status()
    return r.json()

def current_term_name():
    now = datetime.now(timezone.utc)
    m, y = now.month, now.year
    if m <= 5:  return f"Spring Semester {y}"
    if m <= 7:  return f"Summer {y}"
    return f"Fall Semester {y}"

def load_canvas_data():
    print(c(C.DIM, "  Connecting to Canvas..."), end="", flush=True)

    target_term = current_term_name()
    now = datetime.now(timezone.utc)

    raw_courses = canvas_get("courses", params={
        "enrollment_state": "active",
        "per_page": 100,
        "include[]": "term"
    })

    courses = []
    for course in raw_courses:
        if course.get("workflow_state") != "available":
            continue
        term = course.get("term") or {}
        name = term.get("name", "")
        if not name or name.lower() in ("default term", ""):
            continue
        if target_term.lower() not in name.lower():
            continue
        ts, te = term.get("start_at"), term.get("end_at")
        try:
            if ts and datetime.fromisoformat(ts.replace("Z", "+00:00")) > now:
                continue
            if te and datetime.fromisoformat(te.replace("Z", "+00:00")) < now:
                continue
        except Exception:
            pass
        courses.append(course)

    print(c(C.GREEN, f" ✓  ({len(courses)} courses found)"))

    if not courses:
        return [], "", {"courses": 0, "total": 0, "urgent": 0}

    print(c(C.DIM, "  Loading assignments..."), end="", flush=True)

    all_assignments = []
    for course in courses:
        try:
            assignments = canvas_get(
                f"courses/{course['id']}/assignments",
                params={
                    "per_page": 100,
                    "include[]": "submission",
                    "order_by": "due_at",
                    "bucket": "future"
                }
            )
            for a in assignments:
                if not a.get("published") or a.get("locked_for_user"):
                    continue
                sub = a.get("submission") or {}
                submitted = (
                    sub.get("submitted_at") is not None or
                    sub.get("workflow_state") in {"submitted", "graded", "pending_review"}
                )
                if submitted:
                    continue
                all_assignments.append({
                    "course":       course.get("name", "Unknown"),
                    "course_code":  course.get("course_code", ""),
                    "name":         a.get("name", "Unnamed"),
                    "due_at":       a.get("due_at", ""),
                    "points":       a.get("points_possible"),
                    "url":          a.get("html_url", ""),
                    "desc":         strip_html(a.get("description", ""))[:300],
                })
        except Exception:
            pass

    all_assignments.sort(key=lambda x: x["due_at"] or "9999")

    urgent_count = 0
    lines = []
    lines.append(f"STUDENT CANVAS DATA — {target_term}")
    lines.append(f"Loaded: {datetime.now().strftime('%A, %B %d %Y at %I:%M %p')}")
    lines.append(f"Courses: {len(courses)}  |  Unsubmitted assignments: {len(all_assignments)}")
    lines.append("")

    for course in courses:
        lines.append(f"COURSE: {course.get('name')} ({course.get('course_code', '')})")

    lines.append("")
    lines.append("UPCOMING UNSUBMITTED ASSIGNMENTS (sorted by due date):")
    lines.append("")

    for a in all_assignments:
        due_raw = a["due_at"]
        if due_raw:
            try:
                dt = datetime.fromisoformat(due_raw.replace("Z", "+00:00"))
                days_left = (dt - now).days
                due_str = dt.strftime("%b %d, %Y %I:%M %p")
                if days_left < 0:
                    tag = f"OVERDUE by {abs(days_left)} day(s)"
                    urgent_count += 1
                elif days_left == 0:
                    tag = "DUE TODAY"
                    urgent_count += 1
                elif days_left <= 3:
                    tag = f"Due in {days_left} day(s) — URGENT"
                    urgent_count += 1
                else:
                    tag = f"Due in {days_left} day(s)"
                due_display = f"{due_str} [{tag}]"
            except Exception:
                due_display = due_raw
        else:
            due_display = "No due date"

        pts = f"{a['points']} pts" if a['points'] is not None else "ungraded"
        lines.append(f"- [{a['course_code']}] {a['name']}")
        lines.append(f"  Link: {a['url']}")
        lines.append(f"  Due: {due_display}")
        lines.append(f"  Points: {pts}")
        if a["desc"]:
            lines.append(f"  Description: {a['desc'][:150]}")
        lines.append("")

    summary = "\n".join(lines)
    stats = {"courses": len(courses), "total": len(all_assignments), "urgent": urgent_count}

    print(c(C.GREEN, f" ✓  ({len(all_assignments)} unsubmitted assignments)"))
    return courses, summary, stats

# ── Pretty-print the assignment list ──────────────────────────────
def show_assignments(summary):
    print()
    for line in summary.split("\n"):
        if line.startswith("COURSE:"):
            print("  " + c(C.PURPLE, c(C.BOLD, line.replace("COURSE: ", ""))))
        elif line.startswith("- ["):
            print("  " + c(C.BOLD, line))
        elif line.strip().startswith("Due:"):
            raw = line.strip()
            if "OVERDUE" in raw or "DUE TODAY" in raw:
                print("    " + c(C.RED, raw))
            elif "URGENT" in raw:
                print("    " + c(C.YELLOW, raw))
            else:
                print("    " + c(C.DIM, raw))
        elif line.strip().startswith("Points:"):
            print("    " + c(C.DIM, line.strip()))
        elif line.strip().startswith("Description:"):
            trimmed = line.strip()
            print("    " + c(C.DIM, trimmed[:100] + ("..." if len(trimmed) > 100 else "")))
    print()

# ── Gemini setup ──────────────────────────────────────────────────
SYSTEM_PROMPT = """You are StudyBot — a sharp, friendly academic coach for a JMU (James Madison University) student.

You have been given the student's LIVE Canvas LMS data: their current courses and all upcoming unsubmitted assignments with due dates and point values.

Your job is to help them:
- Prioritize what to work on
- Build a study plan
- Understand what's coming up
- Manage their time and stress
- do not output in markdown, simple outputs that appear in terminal
- give links to the assignment if asked

Formatting rules:
- Be CONCISE and direct. Students are busy.
- Use emoji sparingly but effectively (🚨 for urgent, ✅ for done, 📅 for dates)
- When listing assignments, always use the actual assignment name and course code
- Flag anything due in < 48 hours with 🚨
- Keep responses to 10 lines max unless the student asks for detail
- NEVER say "I don't have access to" — you have their full Canvas data right here"""

def setup_gemini():
    print(c(C.DIM, "  Connecting to Gemini..."), end="", flush=True)
    try:
        client = genai.Client(api_key=GEMINI_KEY)
        print(c(C.GREEN, " ✓  Ready!"))
        return client
    except Exception as e:
        print(c(C.RED, f" ✗  Gemini error: {e}"))
        sys.exit(1)

def ask_gemini(client, canvas_summary, history, user_input):
    """Send message with full conversation history."""
    contents = [
        types.Content(
            role="user",
            parts=[types.Part(text=f"Here is my current Canvas data:\n\n{canvas_summary}\n\nYou now have full context. Acknowledge briefly.")]
        ),
        types.Content(
            role="model",
            parts=[types.Part(text="Got it! Canvas data loaded — I can see all your courses and upcoming assignments. Ready to help 🎓")]
        ),
    ]

    # Append conversation history
    for role, text in history:
        contents.append(types.Content(role=role, parts=[types.Part(text=text)]))

    # Append latest user message
    contents.append(types.Content(role="user", parts=[types.Part(text=user_input)]))

    response = client.models.generate_content(
        model=GEMINI_MODEL,
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
        ),
        contents=contents
    )
    return response.text

# ── Chat loop ─────────────────────────────────────────────────────
HELP_TEXT = c(C.DIM, """
  Commands:
    /list     — Show all your upcoming assignments
    /urgent   — Show only urgent items (due ≤ 3 days)
    /plan     — Ask AI for a full study plan
    /refresh  — Re-fetch Canvas data
    /clear    — Clear the screen
    /quit     — Exit
  Or just type any question naturally!
""")

def print_ai_response(text):
    print()
    print(c(C.CYAN, "  StudyBot"))
    print(c(C.DIM, "  " + "─" * 52))
    for line in text.strip().split("\n"):
        print("  " + line)
    print()

def run_chat(client, courses, summary, stats):
    history = []  # list of (role, text) tuples

    print()
    print(c(C.CYAN, c(C.BOLD, "  Ready! Your Canvas data is loaded.")))
    print(c(C.DIM, f"  {stats['courses']} courses  ·  {stats['total']} upcoming assignments  ·  {stats['urgent']} urgent"))
    print()
    print(c(C.DIM, "  Try asking:"))
    for p in [
        '"What should I work on tonight?"',
        '"What\'s due this week?"',
        '"Help me build a study schedule"',
        '"What\'s my most urgent assignment?"',
    ]:
        print(c(C.DIM, f"    • {p}"))
    print()
    print(c(C.DIM, "  Type /help for commands  ·  /quit to exit"))
    print(c(C.DIM, "  " + "─" * 54))

    while True:
        try:
            print()
            user_input = input(c(C.BOLD, "  You: ")).strip()
        except (EOFError, KeyboardInterrupt):
            print(c(C.DIM, "\n\n  Goodbye! Good luck with your assignments! 👋\n"))
            break

        if not user_input:
            continue

        if user_input.lower() in ("/quit", "/exit", "/q"):
            print(c(C.DIM, "\n  Goodbye! Good luck with your assignments! 👋\n"))
            break

        elif user_input.lower() == "/clear":
            banner()
            continue

        elif user_input.lower() == "/help":
            print(HELP_TEXT)
            continue

        elif user_input.lower() == "/list":
            show_assignments(summary)
            continue

        elif user_input.lower() == "/urgent":
            user_input = "List ONLY the assignments due in the next 3 days or overdue. Be brief and use 🚨 for each."

        elif user_input.lower() == "/plan":
            user_input = "Give me a full study plan for this week. Include all assignments, suggested hours, and which days to work on each."

        elif user_input.lower() == "/refresh":
            print()
            nonlocal_summary = load_canvas_data()
            courses, summary, stats = nonlocal_summary
            history = []  # reset history after refresh
            print(c(C.GREEN, "  Canvas data refreshed! Conversation history cleared."))
            continue

        print(c(C.DIM, "\n  StudyBot is thinking..."), end="", flush=True)
        try:
            reply = ask_gemini(client, summary, history, user_input)
            print("\r" + " " * 35 + "\r", end="")
            print_ai_response(reply)

            # Store in history for context
            history.append(("user", user_input))
            history.append(("model", reply))

            # Keep history from growing too large (last 10 exchanges)
            if len(history) > 20:
                history = history[-20:]

        except Exception as e:
            print(c(C.RED, f"\n  Error: {e}"))
            print(c(C.DIM, "  (Try again or type /quit to exit)"))

# ── Main ──────────────────────────────────────────────────────────
def main():
    banner()

    if len(CANVAS_TOKEN) < 10 or "YOUR_" in CANVAS_TOKEN:
        print(c(C.RED, "  ✗  Paste your Canvas token on line 20!"))
        print(c(C.DIM, "     canvas.jmu.edu → Account → Settings → New Access Token\n"))
        sys.exit(1)

    if len(GEMINI_KEY) < 10 or "YOUR_" in GEMINI_KEY:
        print(c(C.RED, "  ✗  Paste your Gemini API key on line 21!"))
        print(c(C.DIM, "     aistudio.google.com → Get API Key\n"))
        sys.exit(1)

    print(c(C.DIM, "  Loading your Canvas data...\n"))

    try:
        courses, summary, stats = load_canvas_data()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            print(c(C.RED, "\n  ✗  Canvas token is invalid or expired."))
            print(c(C.DIM, "     Generate a new one: canvas.jmu.edu → Account → Settings\n"))
        else:
            print(c(C.RED, f"\n  ✗  Canvas error: {e}\n"))
        sys.exit(1)
    except Exception as e:
        print(c(C.RED, f"\n  ✗  Error: {e}\n"))
        sys.exit(1)

    if not courses:
        print(c(C.YELLOW, "\n  No current semester courses found."))
        sys.exit(0)

    client = setup_gemini()
    run_chat(client, courses, summary, stats)

if __name__ == "__main__":
    main()
