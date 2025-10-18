#!/usr/bin/env python3
import os, json, re, requests
from openai import OpenAI
import dspy

# --- ENV ---
GH_BOT_TOKEN = os.getenv("GH_BOT_TOKEN")
OPENAI_KEY   = os.getenv("OPENAI_API_KEY")
REPO         = os.getenv("GITHUB_REPOSITORY")
EVENT_PATH   = os.getenv("GITHUB_EVENT_PATH")
BOT_NAME     = "agentic-ai-reviewer"

HEADERS = {
    "Authorization": f"token {GH_BOT_TOKEN}",
    "Accept": "application/vnd.github+json"
}

with open(EVENT_PATH) as f:
    event = json.load(f)
pr = event.get("pull_request", {})
pr_number = pr.get("number")

print(f"🔍 Running Agentic Reviewer on PR #{pr_number} in {REPO}")

# --- FETCH FILES + EXISTING COMMENTS ---
files = requests.get(
    f"https://api.github.com/repos/{REPO}/pulls/{pr_number}/files",
    headers=HEADERS).json()
existing = requests.get(
    f"https://api.github.com/repos/{REPO}/pulls/{pr_number}/comments",
    headers=HEADERS).json()

existing_lines = {(c["path"], c["line"])
                  for c in existing
                  if c.get("user", {}).get("login", "").lower() == BOT_NAME.lower()}

# --- INIT LLM + DSPy ---
client = OpenAI(api_key=OPENAI_KEY)

class CodeReviewReasoner(dspy.Module):
    def forward(self, filename, diff):
        prompt = f"""
        You are an expert code reviewer.
        Review this Git diff for issues or improvements.
        Respond *only* in valid JSON list format:
        [{{"line": <number>, "comment": "<feedback>"}}]
        File: {filename}
        Diff:
        {diff}
        """
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role":"user","content":prompt}],
            temperature=0.3)
        raw = resp.choices[0].message.content.strip()

        # --- Strip code-block fences like ```json ... ```
        cleaned = re.sub(r"^```[a-zA-Z]*\n?", "", raw)
        cleaned = re.sub(r"```$", "", cleaned).strip()

        try:
            data = json.loads(cleaned)
            return data if isinstance(data, list) else []
        except Exception as e:
            print(f"⚠️ Could not parse JSON for {filename}: {e}\n{cleaned[:200]}")
            return []

reviewer = CodeReviewReasoner()

# --- RUN REVIEW ---
new_comments = []
for f in files:
    filename, patch = f["filename"], f.get("patch", "")
    if not patch: continue
    print(f"\n📄 Reviewing {filename}")
    for s in reviewer(filename, patch):     # ✅ dspy preferred call style
        line, comment = s.get("line"), s.get("comment","").strip()
        if not line or not comment: continue
        if (filename, line) in existing_lines: continue
        new_comments.append({"path":filename,"line":line,"side":"RIGHT","body":f"💡 {comment}"})

print(f"\n🧠 New comments: {len(new_comments)}")

# --- POST INLINE COMMENTS ---
for c in new_comments:
    r = requests.post(
        f"https://api.github.com/repos/{REPO}/pulls/{pr_number}/comments",
        headers=HEADERS, json=c)
    print("✅" if r.ok else f"❌ {r.status_code}: {r.text[:200]}")

# --- POST / UPDATE SUMMARY COMMENT ---
summary_body = (
    f"### 🤖 Agentic Reviewer Summary\n"
    f"**Mode:** Incremental (diff-based)\n"
    f"**Files Reviewed:** {len(files)}\n"
    f"**New Comments Added:** {len(new_comments)}\n\n"
    "Agentic Reviewer automatically analyzes diffs using OpenAI + DSPy reasoning."
)

# use /issues/:number/comments, not /issues/comments
resp = requests.post(
    f"https://api.github.com/repos/{REPO}/issues/{pr_number}/comments",
    headers=HEADERS, json={"body": summary_body})
print(f"📝 Summary status: {resp.status_code} {resp.text[:120]}")

print("✅ Agentic Reviewer finished.")
