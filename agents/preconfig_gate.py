import os, glob, yaml, json, requests
from dspy import LM

repo   = os.getenv("GITHUB_REPOSITORY")
token  = os.getenv("GITHUB_TOKEN")
event  = json.load(open(os.getenv("GITHUB_EVENT_PATH")))
pr_num = event["number"]
lm     = LM(model="gpt-5", api_key=os.getenv("OPENAI_API_KEY"), temperature=1.0, max_tokens=16000)

def comment(msg):
    url = f"https://api.github.com/repos/{repo}/issues/{pr_num}/comments"
    requests.post(url, headers={"Authorization": f"token {token}"}, json={"body": msg})

def main():
    files = glob.glob("**/*.yaml", recursive=True)
    if not files:
        comment("✅ No YAML/Helm files to validate.")
        return
    for f in files:
        text = open(f).read()
        prompt = f"Check this Kubernetes/Helm YAML for missing limits, bad labels or risky configs:\n{text}"
        review = lm(prompt)
        comment(f"🛡 **Pre-Config Gate:** `{f}`\n\n{review}")

if __name__ == "__main__":
    main()
