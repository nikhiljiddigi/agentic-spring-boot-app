import os, pathlib, requests
from dspy import LM

repo  = os.getenv("GITHUB_REPOSITORY")
sha   = os.getenv("GITHUB_SHA")
token = os.getenv("GITHUB_TOKEN")
lm    = LM(model="gpt-5", api_key=os.getenv("OPENAI_API_KEY"))

def comment(msg):
    url = f"https://api.github.com/repos/{repo}/commits/{sha}/comments"
    requests.post(url, headers={"Authorization": f"token {token}"}, json={"body": msg})

def main():
    log = pathlib.Path("build.log")
    if not log.exists():
        print("No build.log found")
        return
    text = log.read_text()[-8000:]
    prompt = "Analyze this Gradle build output. Identify the root cause and suggest a one-line fix."
    summary = lm(prompt + "\n\n" + text)
    comment(f"🚀 **Pipeline RCA Agent:**\n\n{summary}")

if __name__ == "__main__":
    main()
