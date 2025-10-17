import os, json, requests
from dspy import LM

repo  = os.getenv("GITHUB_REPOSITORY")
sha   = os.getenv("GITHUB_SHA")
token = os.getenv("GITHUB_TOKEN")
lm    = LM(model="gpt-5", api_key=os.getenv("OPENAI_API_KEY"), temperature=1.0, max_tokens=16000)

def comment(msg):
    url = f"https://api.github.com/repos/{repo}/commits/{sha}/comments"
    requests.post(url, headers={"Authorization": f"token {token}"}, json={"body": msg})

def main():
    if not os.path.exists("trivy-report.json"):
        print("No Trivy report found")
        return
    report = json.load(open("trivy-report.json"))
    prompt = ("Given this Trivy scan JSON, list only critical and high CVEs, "
              "affected packages, and recommended fix versions in bullet points.")
    summary = lm(prompt + "\n\n" + json.dumps(report)[:12000])
    comment(f"🔐 **Security Watcher:**\n\n{summary}")

if __name__ == "__main__":
    main()
