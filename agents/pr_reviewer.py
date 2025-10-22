import os
import re
import json
import time
import requests
import concurrent.futures
from github import Github, Auth
import dspy


# --------------------------------------
# DSPy Signature + File Review Module
# --------------------------------------
class ReviewFileContent(dspy.Signature):
    """
    You are an expert **AI DevSecOps and Code Review Assistant**.

    Review the provided file comprehensively — it can be:
    - Application code (Java, Python, Go, JS, etc.)
    - Infrastructure-as-Code (Terraform, Kubernetes, Helm, Docker)
    - Configuration or security files (.env, .yaml, .json, .properties)
    - CI/CD definitions (GitHub Actions, Jenkins, GitLab CI, etc.)

    Perform a holistic review focusing on:
    🧱 **Code Quality & Maintainability**
      - Logical or structural issues
      - Unused variables or functions
      - Poor naming, missing comments, or hardcoded constants
      - Anti-patterns, performance or readability issues

    🔒 **Security & DevSecOps**
      - Hardcoded secrets, tokens, or credentials
      - Insecure API usage, missing input validation, weak encryption
      - Misconfigured authentication, open endpoints, or lack of sanitization
      - Known dependency or supply-chain risks (e.g., old Log4j, vulnerable libs)
      - Missing security headers or proper error handling

    ☁️ **Infra & Deployment (IaC)**
      - Kubernetes: missing liveness/readiness probes, no resource limits, running as root
      - Terraform: public S3, open ingress (0.0.0.0/0), unencrypted RDS/S3
      - Dockerfile: using `latest` tag, running as root, missing non-root user
      - CI/CD: secrets in YAML, unscoped tokens, or unpinned dependencies
      - Helm/Cloud configs: insecure defaults, lack of parameterization

    ⚙️ **Expected Output**
      Respond ONLY with a **valid JSON array** of review suggestions.
      Each object must include:
      [
        {
          "line": number,
          "comment": "specific actionable feedback"
        }
      ]

    The goal is to produce **actionable**, **line-specific**, and **security-aware**
    review feedback across application code, infrastructure, and DevSecOps configuration.
    """
    file_content = dspy.InputField(desc="Full source code of the file.")
    filename = dspy.InputField(desc="File name including extension (e.g., .java, .py, .go).")
    patch_diff = dspy.InputField(desc="Git patch showing what changed in this file.")
    review_comments = dspy.OutputField(
        desc="JSON array of review suggestions with line numbers. Format: [{'line': number, 'comment': 'suggestion text'}]"
    )


class FileReviewer(dspy.Module):
    def __init__(self):
        super().__init__()
        self.predict = dspy.Predict(ReviewFileContent)

    def forward(self, file_content, filename, patch_diff):
        result = self.predict(
            file_content=file_content,
            filename=filename,
            patch_diff=patch_diff
        )
        return result.review_comments or []


# --------------------------------------
# Security Scanner Functions
# --------------------------------------
def fetch_cves(name, version, ecosystem):
    """Fetch CVE info for any supported ecosystem via OSV.dev"""
    OSV_API = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}

    try:
        r = requests.post(OSV_API, json=payload, timeout=8)
        if r.status_code == 200:
            vulns = r.json().get("vulns", [])
            results = []
            for v in vulns:
                desc = v.get("summary") or v.get("details") or "No description"
                sev = (
                    v.get("severity", [{}])[0].get("score", "N/A")
                    if v.get("severity") else "N/A"
                )
                results.append((v.get("id", "Unknown"), sev, desc))
            return results
        else:
            print(f"⚠️ OSV returned {r.status_code} for {name}@{version} ({ecosystem})")
    except Exception as e:
        print(f"⚠️ Failed CVE lookup for {name}@{version}: {e}")
    return []


def scan_content_for_secrets(content, filename):
    """Scan file content for hardcoded secrets or sensitive keys across code and config files."""
    patterns = [
        (r"(?i)(?:api|access|auth|secret|token|key)[-_]?(?:id|code)?\s*[:=]\s*['\"]?[A-Za-z0-9/\+=_\-\.]{10,}['\"]?", "Potential API/Access Key"),
        (r"(?i)password\s*[:=]\s*['\"]?[^'\"]+['\"]?", "Hardcoded Password Detected"),
        (r"(?i)bearer\s+[A-Za-z0-9_\-\.]+", "Bearer/OAuth Token Detected"),
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
        (r"-----BEGIN (?:RSA|DSA|EC|PGP|OPENSSH|PRIVATE) KEY-----", "Private Key Detected"),
        (r"(?i)^[A-Z0-9_]*SECRET[A-Z0-9_]*\s*=\s*.+", "Secret Variable in Env/Properties File"),
        (r"(?i)^[A-Z0-9_]*PASSWORD[A-Z0-9_]*\s*=\s*.+", "Password Variable in Env/Properties File"),
        (r"(?i)^[A-Z0-9_]*TOKEN[A-Z0-9_]*\s*=\s*.+", "Token Variable in Env/Properties File"),
    ]

    findings = []
    lines = content.split("\n")

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue

        for pat, msg in patterns:
            if re.search(pat, stripped):
                findings.append({
                    "line": i,
                    "message": msg,
                    "content": stripped
                })

    return findings


def check_security_vulnerabilities(file_obj, file_content):
    """Check for dependency & secret vulnerabilities."""
    security_comments = []
    ecosystem = None
    deps = []

    # Dependency detection
    if file_obj.filename.endswith(("requirements.txt", "requirements-dev.txt", "requirements-test.txt")):
        ecosystem = "PyPI"
        for line in file_content.splitlines():
            if "==" in line and not line.strip().startswith("#"):
                name, version = line.strip().split("==", 1)
                deps.append((name.strip(), version.strip()))

    elif file_obj.filename.endswith(("build.gradle", "build.gradle.kts", "pom.xml")):
        ecosystem = "Maven"
        pattern = re.compile(r"([a-zA-Z0-9_.-]+):([a-zA-Z0-9_.-]+):([\w.\-]+)")
        for match in pattern.finditer(file_content):
            group, artifact, version = match.groups()
            deps.append((f"{group}:{artifact}", version))

    elif file_obj.filename.endswith(("package.json",)):
        ecosystem = "npm"
        try:
            data = json.loads(file_content)
            for pkg, version in data.get("dependencies", {}).items():
                deps.append((pkg, version.lstrip("^~")))
            for pkg, version in data.get("devDependencies", {}).items():
                deps.append((pkg, version.lstrip("^~")))
        except json.JSONDecodeError:
            pass

    elif file_obj.filename.endswith(("go.mod",)):
        ecosystem = "Go"
        pattern = re.compile(r"^\s*([\w.\-/]+)\s+v([\d.]+)", re.MULTILINE)
        for match in pattern.finditer(file_content):
            deps.append((match.group(1), match.group(2)))

    # CVEs
    if ecosystem and deps:
        for name, version in deps:
            vulns = fetch_cves(name, version, ecosystem)
            if not vulns:
                continue

            vuln_details = "\n".join([
                f"- **{vuln_id}** — {desc.split('.')[0]}."
                for vuln_id, _, desc in vulns
            ])
            cve_count = len(vulns)
            collapsed_block = (
            f"<details>\n"
            f"<summary>{cve_count} vulnerabilities found</summary>\n\n"
            f"{vuln_details}\n\n"
            f"</details>"
        )

            for i, line in enumerate(file_content.splitlines(), 1):
                if name in line:
                    security_comments.append({
                        "line": i,
                        "comment": (
                            f"🚨 **Vulnerabilities detected in dependency**\n"
                            f"**Package:** `{name}` `{version}`\n"
                            f"**Ecosystem:** {ecosystem}\n\n"
                            f"{collapsed_block}\n\n"
                            f"**Recommendation:** Update to a secure version or check upstream advisories."
                        ),
                        "kind": "vuln",
                        "package": name,
                        "version": version
                    })
                    break

    # Secrets
    secrets = scan_content_for_secrets(file_content, file_obj.filename)
    for secret in secrets:
        security_comments.append({
            'line': secret['line'],
            'comment': (
                f"🔐 **Security Risk:** {secret['message']}\n"
                f"**Recommendation:** Remove hardcoded credentials and use environment variables or a secret manager."
            ),
            'kind': 'secret'
        })

    return security_comments


# --------------------------------------
# Helpers
# --------------------------------------
def get_file_content(file_obj, repo, commit_id):
    try:
        file_content = repo.get_contents(file_obj.filename, ref=commit_id)
        return file_content.decoded_content.decode('utf-8')
    except Exception as e:
        print(f"⚠️ Could not fetch {file_obj.filename}: {e}")
        return ""


def get_changed_lines(file):
    """Return all line numbers safe for commenting."""
    if file.status == "added":
        try:
            content = file.patch or ""
            total_lines = len(content.splitlines())
            return list(range(1, total_lines + 1))
        except Exception:
            return []

    patch = file.patch or ""
    changed_lines = set()
    current_line = 0
    for line in patch.split("\n"):
        if line.startswith("@@"):
            m = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if m:
                start = int(m.group(1))
                length = int(m.group(2)) if m.group(2) else 1
                current_line = start
                for i in range(length):
                    changed_lines.add(start + i)
        elif line.startswith("+") and not line.startswith("+++"):
            changed_lines.add(current_line)
            current_line += 1
        elif not line.startswith("-"):
            current_line += 1
    return sorted(list(changed_lines))


def parse_review_comments(review_output, filename, patch):
    comments = []
    changed_lines = get_changed_lines(type("obj", (), {"patch": patch, "status": "modified"}))
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
                        'body': item['comment'],
                        'path': filename,
                        'line': int(item['line'])
                    })
    except Exception as e:
        print(f"⚠️ Error parsing review comments: {e}")
    return comments


def merge_or_add_comment(all_comments, new_comment):
    for existing in all_comments:
        if existing["path"] == new_comment["path"] and existing["line"] == new_comment["line"]:
            if new_comment["body"] not in existing["body"]:
                existing["body"] += f"\n\n💡 **Additional Context:**\n{new_comment['body']}"
            return
    all_comments.append(new_comment)


def delete_previous_bot_comments(pr):
    print("🧹 Cleaning up previous bot comments...")
    marker = "🤖 Agentic AI Review Summary"
    bot_usernames = {"agentic-ai-bot", "github-actions", "action-bot"}
    review_comments = list(pr.get_review_comments())
    issue_comments = list(pr.get_issue_comments())
    all_comments = [
        c for c in (review_comments + issue_comments)
        if (marker in (c.body or "")) or (c.user.login in bot_usernames)
    ]
    if not all_comments:
        print("✅ No old bot comments found.")
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        for result in executor.map(lambda c: (c.delete(), f"Deleted {c.id}"), all_comments):
            print(result)
    print("✅ Cleanup completed.")


def safe_post_review(pr, body, all_comments):
    try:
        pr.create_review(body=body, event="COMMENT", comments=all_comments)
        print("✅ Inline PR review posted successfully.")
    except Exception as e:
        error_str = str(e)
        if "422" in error_str or "Unprocessable Entity" in error_str:
            print("⚠️ Inline comment rejected (not in diff). Posting fallback general PR comment instead.")
            fallback_body = body + "\n\n### 🧩 Inline Comments (Fallback)\n"
            for c in all_comments:
                fallback_body += f"\n**{c['path']}** (line {c['line']}):\n> {c['body']}\n"
            pr.create_issue_comment(body=fallback_body)
            print("✅ Fallback general comment posted.")
        else:
            print(f"⚠️ Review posting failed: {e}")


# --------------------------------------
# Main Logic
# --------------------------------------
def run_pr_agent():
    gemini_key = os.getenv('GEMINI_API_KEY')
    github_token = os.getenv('GITHUB_TOKEN')
    repo_name = os.getenv('GITHUB_REPOSITORY')
    pr_number = int(os.getenv('PR_NUMBER', '1'))

    if not gemini_key or not github_token:
        raise EnvironmentError("❌ Missing GEMINI_API_KEY or GITHUB_TOKEN")
    if not pr_number or not repo_name:
        raise EnvironmentError("❌ Missing PR_NUMBER or GITHUB_REPOSITORY")

    gemini_lm = dspy.LM("gemini/gemini-2.5-flash", api_key=gemini_key)
    dspy.configure(lm=gemini_lm)

    g = Github(auth=Auth.Token(github_token))
    repo = g.get_repo(repo_name)
    pr = repo.get_pull(pr_number)
    commit_sha = pr.head.sha[:7]
    reviewer = FileReviewer()
    all_comments, security_summary = [], []

    print(f"🔍 Reviewing PR #{pr_number} in {repo_name}")

    for file in pr.get_files():
        if not file.patch:
            continue
        print(f"📄 Reviewing {file.filename}...")
        file_content = get_file_content(file, repo, pr.head.sha)
        if not file_content:
            continue
        changed_lines = get_changed_lines(file)
        sec_comments = check_security_vulnerabilities(file, file_content)
        vuln_comments = [s for s in sec_comments if s.get('kind') == 'vuln']
        secret_comments = [s for s in sec_comments if s.get('kind') == 'secret']

        for sc in vuln_comments + secret_comments:
            if file.status == "added" or sc['line'] in changed_lines:
                merge_or_add_comment(all_comments, {
                    'path': file.filename,
                    'line': sc['line'],
                    'body': sc['comment']
                })
            else:
                print(f"⚠️ Skipped {file.filename} line {sc['line']} (not in diff)")

        total_issues = len(sec_comments)
        if total_issues:
            security_summary.append((file.filename, total_issues, sec_comments))

        if not file.filename.endswith(('.md', '.txt', '.json')):
            review_output = reviewer(file_content, file.filename, file.patch)
            comments = parse_review_comments(review_output, file.filename, file.patch)
            for c in comments:
                merge_or_add_comment(all_comments, c)

    if all_comments:
        body = f"🤖 **Agentic AI Review Summary (commit `{commit_sha}`)**\n\n"
        if security_summary:
            body += f"🚨 **Detected potential security risks.**\n\n"
        body += "🧠 **Code quality and best practice suggestions are provided below.**  \n"
        delete_previous_bot_comments(pr)
        safe_post_review(pr, body, all_comments)
    else:
        print("✅ No issues found in PR diff.")


if __name__ == "__main__":
    result = run_pr_agent()
    print(result)
