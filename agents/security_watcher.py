from dspy import ChainOfThought
import json, os, requests

repo = os.getenv("GITHUB_REPOSITORY")
ref = os.getenv("GITHUB_REF")
gh_token = os.getenv("GITHUB_TOKEN")

class CVEExplain(ChainOfThought):
    def forward(self, cve_json: str) -> str:
        self.think("Summarize critical and high CVEs and suggest upgrade paths.")
        return self.call("Output short table with package, CVE, fix version.")

def comment(body):
    url = f"https://api.github.com/repos/{repo}/commits/{ref}/comments"
    requests.post(url, headers={"Authorization": f"token {gh_token}"}, json={"body": body})

def main():
    if not os.path.exists("trivy-report.json"):
        return
    data = json.load(open("trivy-report.json"))
    agent = CVEExplain()
    result = agent(json.dumps(data))
    comment(f"🔐 **Security Watcher:**\n\n{result}")

if __name__ == "__main__":
    main()
