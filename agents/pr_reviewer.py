import os, subprocess, requests, json
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
    diff = subprocess.check_output(["git", "diff", "HEAD~1..HEAD"]).decode()
    prompt = ("You are a senior code reviewer. Review this diff for readability, "
              "logging, exception handling, and security best practices. "
              "Provide concise bullet points.")
    review = lm(prompt + "\n\n" + diff)
    comment(f"🧠 **AI PR Review:**\n\n{review}")

if __name__ == "__main__":
    main()
