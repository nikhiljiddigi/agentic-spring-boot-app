import os
import re
import json
import requests
from github import Github
import dspy

# =========================================================
# DSPy Signatures for Code Review and Security Reasoning
# =========================================================

class ReviewFileContent(dspy.Signature):
    """AI signature for file-level code review"""
    file_content = dspy.InputField(desc="Full file content to review.")
    filename = dspy.InputField(desc="The name of the file being reviewed.")
    patch_diff = dspy.InputField(desc="Git patch showing changed lines.")
    review_comments = dspy.OutputField(desc="JSON array of comments [{'line': int, 'comment': str}].")

class SecurityAdvisor(dspy.Signature):
    """AI signature for reasoning about detected vulnerabilities"""
    findings = dspy.InputField(desc="List of detected security issues, CVEs, or secrets.")
    file_context = dspy.InputField(desc="Relevant code or dependency snippet.")
    review_recommendations = dspy.OutputField(desc="AI-generated security analysis and recommendations.")

# =========================================================
# DSPy Modules
# =========================================================

class FileReviewer(dspy.Module):
    def __init__(self):
        super().__init__()
        self.predict = dspy.Predict(ReviewFileContent)

    def forward(self, file_content, filename, patch_diff):
        result = self.predict(file_content=file_content, filename=filename, patch_diff=patch_diff)
        return result.review_comments

class SecurityReviewer(dspy.Module):
    def __init__(self):
        super().__init__()
        self.analyze = dspy.Predict(SecurityAdvisor)

    def forward(self, findings, file_context):
        result = self.analyze(findings=findings, file_context=file_context)
        return result.review_recommendations

# =========================================================
# Security Scanning Logic (Gradle, Maven, Python)
# =========================================================

def parse_dependencies(file_obj, content):
    """Parse Gradle, Maven, and Python dependencies."""
    deps = []

    # Python (requirements.txt)
    if file_obj.filename.endswith(('requirements.txt', 'requirements-dev.txt', 'requirements-test.txt')):
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '==' in line:
                name, version = line.split('==', 1)
                deps.append((name.strip(), version.strip(), 'PyPI'))

    # Gradle / Kotlin DSL
    elif file_obj.filename.endswith(('build.gradle', 'build.gradle.kts')):
        pattern = r'(?:implementation|api|compile|runtimeOnly|testImplementation)\s+["\']([^:"\']+):([^:"\']+):([^:"\']+)["\']'
        for match in re.findall(pattern, content):
            group, artifact, version = match
            name = f"{group}:{artifact}"
            deps.append((name, version, 'Maven'))

    # Maven (pom.xml)
    elif file_obj.filename.endswith('pom.xml'):
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(content)
            ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
            for dep in root.findall('.//m:dependency', ns):
                group = dep.find('m:groupId', ns)
                artifact = dep.find('m:artifactId', ns)
                version = dep.find('m:version', ns)
                if group is not None and artifact is not None and version is not None:
                    name = f"{group.text}:{artifact.text}"
                    deps.append((name, version.text, 'Maven'))
        except Exception as e:
            print(f"⚠️ Error parsing pom.xml: {e}")

    return deps

def fetch_cves(name, version, ecosystem='Maven'):
    """Fetch CVE info from OSV.dev"""
    OSV_API = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
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
        print(f"⚠️ Failed CVE lookup for {name}: {e}")
    return []

def scan_content_for_secrets(content, filename):
    """Detect hardcoded secrets or tokens"""
    patterns = [
        (r"AKIA[0-9A-Z]{16}", "AWS access key"),
        (r"(?i)token\s*=\s*['\"][A-Za-z0-9\-_\.]{8,}['\"]", "Token detected"),
        (r"(?i)password\s*=\s*['\"][^'\"]+['\"]", "Hardcoded password"),
        (r"Bearer\s+[A-Za-z0-9\-_\.]+", "Bearer token"),
        (r"(?i)api[_-]?key\s*=\s*['\"][A-Za-z0-9\-_\.]{8,}['\"]", "API key detected"),
        (r"(?i)secret[_-]?key\s*=\s*['\"][A-Za-z0-9\-_\.]{8,}['\"]", "Secret key detected"),
    ]
    findings = []
    for i, line in enumerate(content.split('\n'), 1):
        for pat, msg in patterns:
            if re.search(pat, line):
                findings.append({'line': i, 'message': msg, 'content': line.strip()})
    return findings

def check_security_vulnerabilities(file_obj, file_content, security_reviewer=None):
    """Hybrid rule-based + AI security scanner."""
    security_comments = []

    # Step 1: Dependency CVEs
    deps = parse_dependencies(file_obj, file_content)
    for name, version, ecosystem in deps:
        vulns = fetch_cves(name, version, ecosystem)
        for vuln_id, severity, desc in vulns:
            for i, line in enumerate(file_content.splitlines(), 1):
                if name.split(':')[-1] in line and version in line:
                    base_comment = (
                        f"🚨 **Security Vulnerability Detected**\n"
                        f"**Ecosystem**: {ecosystem}\n"
                        f"**Package**: {name} {version}\n"
                        f"**Vulnerability ID**: {vuln_id}\n"
                        f"**Severity**: {severity}\n"
                        f"**Description**: {desc}\n"
                    )
                    if security_reviewer:
                        ai_context = [{'package': name, 'version': version, 'vuln_id': vuln_id, 'desc': desc}]
                        ai_feedback = security_reviewer(findings=ai_context, file_context=line)
                        base_comment += f"\n🤖 **AI Insight**: {ai_feedback}"
                    security_comments.append({'line': i, 'comment': base_comment})
                    break

    # Step 2: Secret Detection
    secrets = scan_content_for_secrets(file_content, file_obj.filename)
    for secret in secrets:
        comment = (
            f"🔐 **Security Risk**: {secret['message']}\n"
            f"**Found**: `{secret['content']}`\n"
            f"**Recommendation**: Remove hardcoded credentials and use env vars."
        )
        if security_reviewer:
            ai_feedback = security_reviewer(findings=[secret], file_context=secret['content'])
            comment += f"\n\n🤖 **AI Insight**: {ai_feedback}"
        security_comments.append({'line': secret['line'], 'comment': comment})

    return security_comments

# =========================================================
# Review Parsing Utils
# =========================================================

def get_file_content(file_obj, repo, commit_id):
    try:
        content = repo.get_contents(file_obj.filename, ref=commit_id)
        return content.decoded_content.decode('utf-8')
    except Exception as e:
        print(f"⚠️ Could not fetch content for {file_obj.filename}: {e}")
        return ""

def get_changed_lines(patch):
    changed = []
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
            changed.append(current_line)
            current_line += 1
        elif not line.startswith('-') and not line.startswith('@@'):
            current_line += 1
    return changed

def parse_review_comments(review_output, filename, patch):
    comments = []
    changed_lines = get_changed_lines(patch)
    try:
        review_data = json.loads(review_output) if review_output.strip().startswith('[') else []
        for item in review_data:
            if isinstance(item, dict) and 'line' in item and 'comment' in item:
                if int(item['line']) in changed_lines:
                    comments.append({'body': item['comment'], 'path': filename, 'line': int(item['line'])})
    except Exception:
        pass
    return comments

# =========================================================
# Main Agent Runner
# =========================================================

def run_review(repo_name, github_token, openai_key, pr_number):
    print("🚀 Starting Agentic PR Review...")

    # DSPy setup
    gemini_lm = dspy.LM("gemini/gemini-2.5-flash", api_key=openai_key)
    dspy.configure(lm=gemini_lm)

    reviewer = FileReviewer()
    security_reviewer = SecurityReviewer()

    # GitHub setup
    g = Github(github_token)
    repo = g.get_repo(repo_name)
    pr = repo.get_pull(pr_number)
    commit_id = pr.head.sha
    files = pr.get_files()

    all_comments = []
    security_summary = []

    for file in files:
        if not file.patch:
            continue

        print(f"🔍 Reviewing {file.filename}...")
        file_content = get_file_content(file, repo, commit_id)
        if not file_content:
            continue

        # Security scan
        sec_comments = check_security_vulnerabilities(file, file_content, security_reviewer)
        if sec_comments:
            security_summary.append(f"**{file.filename}**: {len(sec_comments)} issues")
            all_comments.extend([{'body': c['comment'], 'path': file.filename, 'line': c['line']} for c in sec_comments])

        # Code review (skip docs/config)
        if not file.filename.endswith(('.md', '.txt', '.yml', '.yaml', '.json')):
            review_output = reviewer(file_content=file_content, filename=file.filename, patch_diff=file.patch)
            parsed_comments = parse_review_comments(review_output, file.filename, file.patch)
            all_comments.extend(parsed_comments)

    # Post to GitHub
    if all_comments:
        summary = "🤖 **Agentic PR Review Summary**\n\n"
        if security_summary:
            summary += "🚨 **Security Findings:**\n" + "\n".join(f"- {s}" for s in security_summary) + "\n\n"
        summary += "🧠 AI-driven feedback and recommendations added inline."

        try:
            pr.create_review(body=summary, event="COMMENT", comments=all_comments)
            print("✅ Review posted successfully!")
        except Exception as e:
            print(f"⚠️ Inline review failed: {e}")
            fallback = summary + "\n\n**Comments:**\n" + "\n".join([f"- {c['path']} (L{c['line']}): {c['body']}" for c in all_comments])
            pr.create_issue_comment(fallback)
            print("✅ Posted as general PR comment instead.")
    else:
        print("✅ No issues found!")

# =========================================================
# Entrypoint (GitHub Actions Compatible)
# =========================================================

def run_pr_agent():
    print("⚙️ Detecting GitHub environment...")

    repo_name = os.getenv("GITHUB_REPOSITORY")
    github_token = os.getenv("GITHUB_TOKEN")
    openai_key = os.getenv("OPENAI_API_KEY")
    event_path = os.getenv("GITHUB_EVENT_PATH")

    if not all([repo_name, github_token, openai_key, event_path]):
        raise ValueError("❌ Missing one of required env vars: GITHUB_REPOSITORY, GITHUB_TOKEN, OPENAI_API_KEY, GITHUB_EVENT_PATH")

    with open(event_path, "r") as f:
        event = json.load(f)
        pr_number = event.get("number") or event.get("pull_request", {}).get("number")

    if not pr_number:
        raise ValueError("❌ Could not detect PR number from GITHUB_EVENT_PATH")

    print(f"📦 Repo: {repo_name}")
    print(f"🔢 PR Number: {pr_number}")
    run_review(repo_name, github_token, openai_key, pr_number)

if __name__ == "__main__":
    run_pr_agent()
