from dspy import ChainOfThought
from openai import OpenAI
import os, subprocess, requests

repo = os.getenv("GITHUB_REPOSITORY")
pr_number = os.getenv("GITHUB_REF").split('/')[-1]
gh_token = os.getenv("GITHUB_TOKEN")
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

class PRReview(ChainOfThought):
    def forward(self, diff: str) -> str:
        self.think("Review the PR diff for style, logging, error handling, and security best practices.")
        return self.call("Give short actionable comments with bullet points.")

def comment(body):
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    requests.post(url, headers={"Authorization": f"token {gh_token}"}, json={"body": body})

def main():
    diff = subprocess.check_output(["git", "diff", "HEAD~1..HEAD"]).decode()
    agent = PRReview()
    review = agent(diff)
    comment(f"🧠 **AI PR Review:**\n\n{review}")

if __name__ == "__main__":
    main()
