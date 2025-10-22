import os
import re
import json
import requests
from github import Github
import dspy

# --------------------------------------
# DSPy Signature + File Review Module
# --------------------------------------
class ReviewFileContent(dspy.Signature):
    file_content = dspy.InputField(desc="The complete file content to review.")
    filename = dspy.InputField(desc="The name of the file being reviewed.")
    patch_diff = dspy.InputField(desc="The git patch showing what changed.")
    review_comments = dspy.OutputField(desc="JSON array of review comments with line numbers, format: [{'line': number, 'comment': 'suggestion text'}]")


class FileReviewer(dspy.Module):
    def __init__(self):
        super().__init__()
        self.predict = dspy.Predict(ReviewFileContent)

    def forward(self, file_content, filename, patch_diff):
        result = self.predict(file_content=file_content, filename=filename, patch_diff=patch_diff)
        return result.review_comments or []


# --------------------------------------
# Security Scanner Functions
# --------------------------------------
def parse_requirements_content(content):
    """Parse requirements from string content"""
    deps = []
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" in line:
            name, version = line.split("==", 1)
            deps.append((name.strip(), version.strip()))
    return deps


def fetch_cves(name, version):
    """Fetch CVE information for a package from OSV"""
    OSV_API = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
    try:
        r = requests.post(OSV_API, json=payload, timeout=8)
        if r.status_code == 200:
            vulns = r.json().get("vulns", [])
            results = []
            for v in vulns:
                desc = v.get("summary") or v.get("details") or "No description"
                sev = v.get("severity", [{}])[0].get("score", "N/A") if v.get("severity") else "N/A"
                results.append((v.get("id", "Unknown"), sev, desc))
            return results
    except Exception as e:
        print(f"⚠️  Failed CVE lookup for {name}: {e}")
    return []


def scan_content_for_secrets(content, filename):
    """Scan file content for hardcoded secrets"""
    patterns = [
        (r"AKIA[0-9A-Z]{16}", "AWS access key"),
        (r"(?i)token\s*=\s*['\"][A-Za-z0-9\-_\.]{8,}['\"]", "Token detected"),
        (r"(?i)password\s*=\s*['\"][^'\"]+['\"]", "Hardcoded password"),
        (r"Bearer\s+[A-Za-z0-9\-_\.]+", "Bearer token"),
        (r"(?i)api[_-]?key\s*=\s*['\"][A-Za-z0-9\-_\.]{8,}['\"]", "API key detected"),
        (r"(?i)secret[_-]?key\s*=\s*['\"][A-Za-z0-9\-_\.]{8,}['\"]", "Secret key detected"),
    ]
    findings = []
    lines = content.split('\n')
    for i, line in enumerate(lines, 1):
        for pat, msg in patterns:
            if re.search(pat, line):
                findings.append({
                    'line': i,
                    'message': msg,
                    'content': line.strip()
                })
    return findings


def check_security_vulnerabilities(file_obj, file_content):
    """Check for dependency & secret vulnerabilities"""
    security_comments = []

    # Dependency CVEs
    if file_obj.filename.endswith(('requirements.txt', 'requirements-dev.txt', 'requirements-test.txt')):
        deps = parse_requirements_content(file_content)
        for name, version in deps:
            vulns = fetch_cves(name, version)
            for vuln_id, severity, desc in vulns:
                for i, line in enumerate(file_content.split('\n'), 1):
                    if f"{name}==" in line:
                        security_comments.append({
                            'line': i,
                            'comment': (
                                f"🚨 **Security Vulnerability**: {vuln_id}\n"
                                f"**Package**: {name} {version}\n"
                                f"**Severity**: {severity}\n"
                                f"**Description**: {desc}\n"
                                f"**Recommendation**: Upgrade to a newer version."
                            )
                        })
                        break
    return security_comments

    # Hardcoded secrets
    secrets = scan_content_for_secrets(file_content, file_obj.filename)
    for secret in secrets:
        security_comments.append({
            'line': secret['line'],
            'comment': (
                f"🔐 **Security Risk**: {secret['message']}\n"
                f"**Found**: `{secret['content']}`\n"
                f"**Recommendation**: Remove hardcoded credentials and use environment variables."
            )
        })

    return security_comments


# --------------------------------------
# Review Logic
# --------------------------------------
reviewer = FileReviewer()


def get_file_content(file_obj, repo, commit_id):
    try:
        file_content = repo.get_contents(file_obj.filename, ref=commit_id)
        return file_content.decoded_content.decode('utf-8')
    except Exception as e:
        print(f"⚠️ Could not fetch {file_obj.filename}: {e}")
        return ""


def get_changed_lines(patch):
    changed_lines = []
    lines = patch.split('\n')
    current_line = 0

    for line in lines:
        if line.startswith('@@'):
            parts = line.split(' ')
            if len(parts) >= 3:
                new_info = parts[2]
                new_start = new_info.split(',')[0][1:] if ',' in new_info else new_info[1:]
                current_line = int(new_start) if new_start.isdigit() else 1
        elif line.startswith('+') and not line.startswith('+++'):
            changed_lines.append(current_line)
            current_line += 1
        elif not line.startswith('-') and not line.startswith('@@'):
            current_line += 1

    return changed_lines


def parse_review_comments(review_output, filename, patch):
    comments = []
    changed_lines = get_changed_lines(patch)

    try:
        review_data = (
            json.loads(review_output)
            if isinstance(review_output, str) and review_output.strip().startswith('[')
            else review_output
        )

        for item in review_data:
            if isinstance(item, dict) and 'line' in item and 'comment' in item:
                if int(item['line']) in changed_lines:
                    comments.append({
                        'body': f"💡 **Agentic AI Bot Review**:\n{item['comment']}",
                        'path': filename,
                        'line': int(item['line'])
                    })
    except Exception as e:
        print(f"⚠️ Error parsing review comments: {e}")
    return comments

import concurrent.futures
def delete_previous_bot_comments(pr):
    print("🧹 Cleaning up previous bot comments...")
    """
    ⚡ Deletes all previous bot comments (review + issue)
    using concurrent threads for speed.
    """
    marker = "🤖 Automated Code Review"
    bot_usernames = {"agentic-ai-bot", "github-bot", "action-bot"}

    review_comments = list(pr.get_review_comments())
    issue_comments = list(pr.get_issue_comments())

    all_comments = [
        c for c in (review_comments + issue_comments)
        if (marker in (c.body or "")) or (c.user.login in bot_usernames)
    ]

    if not all_comments:
        print("✅ No old bot comments found.")
        return

    print(f"🧹 Found {len(all_comments)} bot comments to delete...")

    def delete_comment(c):
        try:
            c.delete()
            return f"✅ Deleted comment {c.id}"
        except Exception as e:
            return f"⚠️ Failed to delete {c.id}: {e}"

    # Run deletes concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        for result in executor.map(delete_comment, all_comments):
            print(result)

    print("✅ All previous bot comments deleted.")


# --------------------------------------
# PR Agent Runner (with Gemini Model)
# --------------------------------------
def run_pr_agent():
    gemini_key = os.getenv('GEMINI_API_KEY')
    github_token = os.getenv('GITHUB_TOKEN')
    repo_name = os.getenv('GITHUB_REPOSITORY')
    pr_number = int(os.getenv('PR_NUMBER', '1'))

    if not gemini_key or not github_token:
        raise EnvironmentError("❌ Missing required environment variables: GEMINI_API_KEY and GITHUB_TOKEN")
    
    if not pr_number:
        raise EnvironmentError("❌ Missing PR_NUMBER. Ensure you export it in your GitHub Action.")
    if not repo_name:
        raise EnvironmentError("❌ Missing GITHUB_REPOSITORY. Ensure you export it in your GitHub Action.")

    # ✅ DSPy configured with Gemini LLM
    gemini_lm = dspy.LM("gemini/gemini-2.5-flash", api_key=gemini_key)
    dspy.configure(lm=gemini_lm)

    g = Github(github_token)
    repo = g.get_repo(repo_name)
    pr = repo.get_pull(pr_number)

    all_comments = []
    security_summary = []

    for file in pr.get_files():
        if not file.patch:
            continue

        print(f"🔍 Reviewing {file.filename}...")
        file_content = get_file_content(file, repo, pr.head.sha)
        if not file_content:
            continue

        # --- Security scan ---
        sec_comments = check_security_vulnerabilities(file, file_content)
        for sc in sec_comments:
            all_comments.append({'path': file.filename, 'line': sc['line'], 'body': sc['comment']})
        if sec_comments:
            security_summary.append(f"{file.filename}: {len(sec_comments)} issues found")

        # --- AI Review ---
        if not file.filename.endswith(('.md', '.txt', '.json', '.yml', '.yaml')):
            review_output = reviewer(file_content, file.filename, file.patch)
            comments = parse_review_comments(review_output, file.filename, file.patch)
            all_comments.extend(comments)

    # --- Post PR Review ---
    if all_comments:
        body = "🤖 **Automated Code Review Summary**\n\n"
        if security_summary:
            body += "🚨 **Security Issues Found**:\n" + "\n".join(f"- {s}" for s in security_summary) + "\n\n"
        body += "🧠 **Code Quality Suggestions** are posted inline below.\n"

        try:
            delete_previous_bot_comments(pr)
            pr.create_review(body=body, event="COMMENT", comments=all_comments)
            return "✅ PR Review posted successfully!"
        except Exception as e:
            print(f"⚠️ PR review failed: {e}")
            pr.create_issue_comment(body=body + "\n\n" + json.dumps(all_comments, indent=2))
            return "✅ Posted as general PR comment."
    else:
        return "✅ No issues found in PR diff."
    
if __name__ == "__main__":
    result = run_pr_agent()
    print(result)
