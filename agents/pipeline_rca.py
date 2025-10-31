#!/usr/bin/env python3
"""
Agentic Pipeline Failure Analyzer (fixed)

- Reads text files from artifacts/ci
- Concatenates compact CI log context
- Calls Gemini via DSPy for reasoning (root cause + fix suggestions)
- Falls back to heuristics if LLM unavailable or invalid response
- Writes pipeline_report.md

Usage:
  GEMINI_API_KEY=<key> python agents/pipeline_analyzer.py \
      --artifacts artifacts/ci --output pipeline_report.md
"""

from pathlib import Path
import os
import argparse
import textwrap
from datetime import datetime, timezone
import dspy
import json, re

# --------------------------
# DSPy Signature
# --------------------------
class SimpleAnalyze(dspy.Signature):
    """Simple failure analyzer signature."""
    raw_text = dspy.InputField(desc="Concatenated CI artifact text (logs, junit, etc.)")
    analysis = dspy.OutputField(desc="Short analysis: root cause guess + actionable steps")

# --------------------------
# Helpers
# --------------------------
TEXT_EXTS = {".log", ".txt", ".out", ".err", ".json", ".xml"}

def collect_text_from_dir(root: Path, max_bytes: int = 2_000_000) -> str:
    """Read and concatenate small text artifact files under root."""
    if not root.exists():
        return ""
    parts = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        try:
            if p.suffix.lower() in TEXT_EXTS or p.stat().st_size < 200_000:
                txt = p.read_text(errors="replace")
                header = f"\n\n===== FILE: {p.relative_to(root.parent)} =====\n"
                parts.append(header + txt[:200_000])
        except Exception as e:
            parts.append(f"\n\n===== FILE: {p.name} READ ERROR =====\n{e}\n")
    full = "\n".join(parts)
    return full[:max_bytes]

def build_prompt(short_context: str) -> str:
    now = datetime.now(timezone.utc).isoformat()
    prompt = textwrap.dedent(f"""
    You are an expert CI/CD pipeline failure analyst.

    Produce:
     1. A 2–4 line concise summary of the most likely root cause.
     2. Confidence level (high / medium / low).
     3. 3 short reproducible steps to verify locally.
     4. 1–2 short fix suggestions.

    Timestamp: {now}

    Context (truncated logs below):
    {short_context}

    Respond in plain text. Keep it short and actionable.
    """)
    return prompt.strip()

# --------------------------
# Main Analysis Logic
# --------------------------
def run_analysis(artifacts_dir: Path,
                 output_path: Path,
                 gemini_model: str = "gemini/gemini-1.5-pro"):

    print(f"[🔍] Starting pipeline analysis using model={gemini_model}")

    text = collect_text_from_dir(artifacts_dir)
    if not text.strip():
        print(f"[⚠️] No artifact text found under {artifacts_dir}")
        text = "NO_ARTIFACTS_FOUND"

    prompt = build_prompt(text[:15000])
    analysis_text = None

    # --------------------------
    # Try DSPy + Gemini reasoning
    # --------------------------
    gemini_key = os.environ.get("GEMINI_API_KEY")
    if not gemini_key:
        print("[⚠️] GEMINI_API_KEY not present; skipping Gemini reasoning.")
    else:
        try:
            print(f"[info] Calling Gemini reasoning via DSPy (model={gemini_model})...")
            lm = dspy.LM(gemini_model, api_key=gemini_key)
            dspy.configure(lm=lm)

            # Call LLM directly to avoid schema enforcement
            response = lm(prompt)

            # Extract readable text from different possible response types
            if isinstance(response, str):
                analysis_text = response.strip()
            elif hasattr(response, "text"):
                analysis_text = getattr(response, "text", "").strip()
            elif hasattr(response, "content"):
                analysis_text = getattr(response, "content", "").strip()
            elif isinstance(response, dict):
                # Gemini sometimes returns {'content': [{'text': '...'}]}
                if "analysis" in response:
                    analysis_text = response["analysis"]
                elif "content" in response and isinstance(response["content"], list):
                    texts = []
                    for c in response["content"]:
                        if isinstance(c, dict) and "text" in c:
                            texts.append(c["text"])
                    analysis_text = "\n".join(texts).strip()
            else:
                analysis_text = str(response).strip()

            if analysis_text:
                print("[✅] Gemini returned valid text for analysis.")
            else:
                print("[⚠️] Gemini response was empty — fallback will apply.")

        except Exception as e:
            print("[error] DSPy/Gemini call failed:", e)



    # --------------------------
    # Fallback Heuristic Analysis
    # --------------------------
    if not analysis_text:
        print("[info] Using fallback heuristic summary.")
        guessed = "Could not run Gemini. Fallback heuristic analysis:\n"

        if "ModuleNotFoundError" in text or "No module named" in text:
            guessed += "- Missing Python dependency (ModuleNotFoundError).\n  ➤ Check requirements or install dependencies in CI.\n"
        elif "SyntaxError" in text:
            guessed += "- Syntax error detected.\n  ➤ Run `python -m py_compile` locally to verify.\n"
        elif "pytest: command not found" in text or "No module named 'pytest'" in text:
            guessed += "- pytest missing in runner.\n  ➤ Add `pip install pytest` or requirements step.\n"
        elif "BUILD FAILED" in text and "error:" in text and ".java" in text:
            guessed += "- Java compilation failed.\n  ➤ Fix syntax or missing braces. Run `./gradlew compileJava --stacktrace`.\n"
        elif text.strip() == "NO_ARTIFACTS_FOUND":
            guessed += "- No artifacts found.\n  ➤ Ensure logs are uploaded as CI artifacts.\n"
        else:
            guessed += "- General failure: review top of logs for Traceback or 'exit code'.\n"

        guessed += "\nConfidence: low\n"
        guessed += "Repro Steps (example):\n1. Inspect `artifacts/ci` logs for errors.\n2. Re-run locally with verbose logging.\n3. Validate dependencies and environment.\n"
        analysis_text = guessed

    # --------------------------
    # Write Markdown Report
    # --------------------------

    if not analysis_text or analysis_text.strip() == "":
        print("[ℹ️] No analysis generated; skipping report creation.")
        return
    
    analysis_text = normalize_analysis_text(analysis_text)
    
    md = (
        f"# Pipeline Analysis Report\n\n"
        f"## Analysis\n\n{analysis_text}\n\n"
    )

    output_path.write_text(md, encoding="utf-8")
    print(f"[📝] Wrote report to {output_path}")


def normalize_analysis_text(text: str) -> str:
    """Unwrap Gemini list/JSON responses and clean formatting for plain Markdown output."""
    if not text:
        return text

    stripped = text.strip()

    # Unwrap JSON-like lists: ["..."] or ['...']
    if (stripped.startswith("[") and stripped.endswith("]")) or (stripped.startswith("['") and stripped.endswith("']")):
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, list):
                text = "\n".join(str(p) for p in parsed)
        except Exception:
            # Fallback: manually strip brackets and quotes
            text = re.sub(r"^\[+['\"]?|['\"]?\]+$", "", stripped)

    # Remove Markdown bold (**text**) and italic (*text*)
    text = re.sub(r"\*\*(.*?)\*\*", r"\1", text)
    text = re.sub(r"\*(.*?)\*", r"\1", text)

    # Replace escaped sequences with actual newlines/tabs
    text = text.replace("\\n", "\n").replace("\\t", "\t")

    # Remove stray quotes and whitespace
    text = text.strip(" '\"\n")

    # Add spacing before numbered items for readability
    text = re.sub(r"(?m)^(\d+\.)", r"\n\1", text)

    # Collapse multiple blank lines
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


# --------------------------
# CLI Entrypoint
# --------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts", "-a", type=Path, default=Path("artifacts/ci"), help="Artifacts dir")
    ap.add_argument("--output", "-o", type=Path, default=Path("pipeline_report.md"))
    ap.add_argument("--model", "-m", type=str, default="gemini/gemini-2.5-flash", help="Gemini model id")
    args = ap.parse_args()

    run_analysis(args.artifacts, args.output, args.model)

if __name__ == "__main__":
    main()
