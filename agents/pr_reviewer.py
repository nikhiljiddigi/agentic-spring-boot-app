import os, json, re, requests
from openai import OpenAI
import dspy

# --- SETUP ENV ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
OPENAI_KEY = os.getenv("OPENAI_API_KEY")
REPO = os.getenv("GITHUB_REPOSITORY")
EVENT_PATH = os.getenv("GITHUB_EVENT_PATH")
BOT_NAME = "agentic-ai-reviewer"
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github+json"}

# --- LOAD EVENT ---
with open(EVENT_PATH, "r") as f:
    event = json.load(f)
pr = event.get("pull_request", {})
pr_number = pr.get("number")

# --- FETCH FILE DIFFS ---
files = requests.get(f"https://api.github.com/repos/{REPO}/pulls/{pr_number}/files", headers=HEADERS).json()

# --- FETCH EXISTING COMMENTS ---
existing_comments = requests.get(f"https://api.github.com/repos/{REPO}/pulls/{pr_number}/comments", headers=HEADERS).json()
existing_lines = {(c["path"], c["line"]) for c in existing_comments if c["user"]["login"] == BOT_NAME}

# --- INIT LLM ---
client = OpenAI(api_key=OPENAI_KEY)

class IncrementalReviewer(dspy.Module):
    def forward(self, filename, diff):
        prompt = f"""
        You are an expert code reviewer (like GitHub Copilot).
        Analyze this Git diff for potential bugs, anti-patterns, or improvements.
        Respond only for changed lines that introduce or modify logic.

        Diff (file: {filename}):
        {diff}

        Respond in JSON as:
        [
          {{"line": <line_number>, "comment": "<clear feedback>"}},
          ...
        ]
        Only include changed lines that genuinely need review.
        """
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.4,
        )
        try:
            return json.loads(response.choices[0].message.content)
        except Exception:
            return []

reviewer = IncrementalReviewer()

# --- PROCESS EACH FILE ---
new_comments = []
for f in files:
    filename = f["filename"]
    patch = f.get("patch", "")
    if not patch:
        continue

    # Run model
    review_suggestions = reviewer.forward(filename, patch)

    # Filter already-commented lines
    for r in review_suggestions:
        line = r.get("line")
        if (filename, line) not in existing_lines:
            new_comments.append({
                "path": filename,
                "line": line,
                "body": f"💡 {r['comment']}"
            })

# --- POST COMMENTS ---
for c in new_comments:
    requests.post(
        f"https://api.github.com/repos/{REPO}/pulls/{pr_number}/comments",
        headers=HEADERS,
        data=json.dumps(c),
    )

# --- POST / UPDATE SUMMARY COMMENT ---
summary = f"""
### 🤖 Agentic Reviewer Summary
Reviewed {len(files)} file(s), posted {len(new_comments)} new comments.
Mode: Incremental (diff-based)
"""
requests.post(
    f"https://api.github.com/repos/{REPO}/issues/{pr_number}/comments",
    headers=HEADERS,
    data=json.dumps({"body": summary}),
)
