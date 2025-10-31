#!/usr/bin/env python3
"""
Minimal Pipeline Failure Analyzer (demo)

- Reads text files from artifacts/ci
- Concatenates a compact context
- Calls Gemini via dspy for a short reasoning summary + suggested fixes
- Writes pipeline_report.md

Usage:
  GEMINI_API_KEY=<key> python agents/pipeline_analyzer.py --artifacts artifacts/ci --output pipeline_report.md
"""

from pathlib import Path
import os
import argparse
import textwrap
import datetime

# DSPy / Gemini (required for reasoning)
try:
    import dspy
    DSPY_AVAILABLE = True
except Exception:
    DSPY_AVAILABLE = False

# --------------------------
# Minimal DSPy Signature
# --------------------------
if DSPY_AVAILABLE:
    class SimpleAnalyze(dspy.Signature):
        """
        Simple failure analyzer signature:
        Input: raw_text (string) - concatenated artifacts/logs
        Output: analysis (string) - concise summary + suggested fix
        """
        raw_text = dspy.InputField(desc="Concatenated CI artifact text (logs, junit, etc.)")
        analysis = dspy.OutputField(desc="Short analysis: root cause guess + 2-3 actionable steps")

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
        # basic extension filter or small files
        try:
            if p.suffix.lower() in TEXT_EXTS or p.stat().st_size < 200_000:
                txt = p.read_text(errors="replace")
                header = f"\n\n===== FILE: {p.relative_to(root.parent)} =====\n"
                parts.append(header + txt[:200_000])  # clamp file content
        except Exception as e:
            parts.append(f"\n\n===== FILE: {p.name} READ ERROR =====\n{e}\n")
    full = "\n".join(parts)
    # clamp overall size to ~200k chars for prompt safety
    return full[:200_000]

def build_prompt(short_context: str, n_examples: int = 0) -> str:
    now = datetime.datetime.utcnow().isoformat() + "Z"
    prompt = textwrap.dedent(f"""
    You are an expert CI pipeline failure analyst. Produce:
     1) A 2-4 line concise summary describing the most likely root cause.
     2) Confidence (high/medium/low).
     3) 3 short reproducible steps to verify locally.
     4) 1-2 short fix suggestions.

    Timestamp: {now}

    Context (logs and artifacts, truncated):
    {short_context}

    Answer in plain text. Keep it short and actionable.
    """)
    return prompt

# --------------------------
# Main (DSPy call + fallback)
# --------------------------
def run_analysis(artifacts_dir: Path, output_path: Path, gemini_model: str = "gemini/gemini-2.5-flash"):
    text = collect_text_from_dir(artifacts_dir)
    if not text.strip():
        print("[info] no artifact text found under", artifacts_dir)
        text = "NO_ARTIFACTS_FOUND"

    prompt = build_prompt(text[:15000])

    analysis_text = None

    # try DSPy/Gemini reasoning if available
    if DSPY_AVAILABLE:
        gemini_key = os.environ.get("GEMINI_API_KEY")
        if not gemini_key:
            print("[warning] GEMINI_API_KEY not present; skipping Gemini reasoning.")
        else:
            try:
                lm = dspy.LM(gemini_model, api_key=gemini_key)
                dspy.configure(lm=lm)
                sig = SimpleAnalyze()
                predict = dspy.Predict(sig)
                print("[info] calling Gemini via dspy...")
                resp = predict(raw_text=prompt)
                analysis_text = getattr(resp, "analysis", None)
            except Exception as e:
                print("[error] dspy/Gemini call failed:", e)

    # Fallback: very short heuristic fallback summary
    if not analysis_text:
        print("[info] using fallback heuristic summary.")
        # super-simple heuristics for demo only
        guessed = "Could not run Gemini. Fallback heuristic analysis:\n"
        if "ModuleNotFoundError" in text or "No module named" in text:
            guessed += "- Likely missing Python dependency (ModuleNotFoundError).\n  Steps: check requirements, install dependencies in CI.\n"
        elif "SyntaxError" in text:
            guessed += "- Likely a syntax error in code.\n  Steps: run python -m py_compile locally on repo.\n"
        elif "pytest: command not found" in text or "No module named 'pytest'" in text:
            guessed += "- pytest not installed in runner.\n  Steps: add pytest to test dependencies or ensure 'pip install -r requirements.txt' step runs.\n"
        elif text.strip() == "NO_ARTIFACTS_FOUND":
            guessed += "- No artifacts found to analyze.\n  Steps: ensure the failing job uploads logs as artifacts (use actions/upload-artifact in on-failure step).\n"
        else:
            guessed += "- General failure: inspect the top of the failing job logs and look for Traceback or 'exit code'.\n"
        guessed += "\nConfidence: low\n"
        guessed += "Repro Steps (example):\n1. Check the failing job logs in artifacts/ci for the 'Traceback' or 'ERROR' blocks.\n2. Run tests locally: `pytest -q` or `python -m pytest`.\n3. Re-run CI with more verbose logging or with `set -x` for shell steps.\n"
        analysis_text = guessed

    # write report
    md = f"# Pipeline Analysis Report\n\nGenerated: {datetime.datetime.utcnow().isoformat()}Z\n\n## Analysis\n\n{analysis_text}\n\n---\n\n## Raw context (truncated)\n\n```\n{text[:10000]}\n```\n"
    output_path.write_text(md, encoding="utf-8")
    print("[info] Wrote report to", output_path)

# --------------------------
# CLI
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
