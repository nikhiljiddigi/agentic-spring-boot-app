from dspy import ChainOfThought
from openai import OpenAI
import os, requests, pathlib

repo = os.getenv("GITHUB_REPOSITORY")
run_id = os.getenv("GITHUB_RUN_ID")
gh_token = os.getenv("GITHUB_TOKEN")

class PipelineRCA(ChainOfThought):
    def forward(self, log_text: str) -> str:
        self.think("Find the root cause of this Gradle/Maven build failure.")
        return self.call("Explain cause and possible fix in plain English.")

def comment(body):
    url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/comments"
    # fallback: post to PR if run_id endpoint unavailable
    requests.post(f"https://api.github.com/repos/{repo}/issues/comments",
                  headers={"Authorization": f"token {gh_token}"}, json={"body": body})

def main():
    log_file = pathlib.Path("build.log")
    if not log_file.exists():
        print("No build.log found")
        return
    with open(log_file) as fp:
        text = fp.read()[-6000:]  # last few KB for token limit
    agent = PipelineRCA()
    summary = agent(text)
    comment(f"🚀 **Pipeline RCA Agent:**\n\n{summary}")

if __name__ == "__main__":
    main()
