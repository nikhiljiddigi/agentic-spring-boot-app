from dspy import ChainOfThought
from openai import OpenAI
import os, glob, requests, json

repo = os.getenv("GITHUB_REPOSITORY")
pr_number = os.getenv("GITHUB_REF").split('/')[-1]
gh_token = os.getenv("GITHUB_TOKEN")
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

class PreConfigCheck(ChainOfThought):
    def forward(self, yaml_text: str) -> str:
        self.think(f"Check this K8s/Helm YAML for missing limits, labels, or obvious misconfigs:\n{yaml_text}")
        result = self.call("Summarize only real problems.")
        return result

def comment_on_pr(body: str):
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    requests.post(url, headers={"Authorization": f"token {gh_token}"}, json={"body": body})

def main():
    files = glob.glob("**/*.yaml", recursive=True)
    if not files:
        comment_on_pr("✅ No YAML/Helm files to validate.")
        return
    agent = PreConfigCheck()
    for f in files:
        with open(f) as fp:
            out = agent(fp.read())
            comment_on_pr(f"🛡 **Pre-Config Gate:** findings in `{f}`\n\n{out}")

if __name__ == "__main__":
    main()
