#!/usr/bin/env python3
"""Analyst agent: question + CSV → LLM → pandas code → exec → answer."""

import csv
import json
import os
import sys
import urllib.request
import urllib.error

MAAS_URL = os.environ.get("MAAS_URL")
MAAS_MODEL = os.environ.get("MAAS_MODEL", "granite-3.3-8b-instruct")

CSV_PATH = os.environ.get("CSV_PATH", "/data/sales.csv")

SYSTEM_PROMPT = """You are a data analyst. You receive a user question about a CSV dataset.
The CSV is already loaded as a list of dicts called `rows`. Each dict has keys: date, region, product, units, revenue.
units and revenue are integers.

Reply with ONLY a Python code block that computes and prints the answer. No explanation, no markdown fences.
Use only the Python standard library (no pandas, no numpy). The `rows` variable is already available.
Print a clear, human-readable answer."""


def load_csv(path):
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        return [
            {**row, "units": int(row["units"]), "revenue": int(row["revenue"])}
            for row in reader
        ]


def ask_llm(question, csv_sample):
    if not MAAS_URL:
        print("ERROR: MAAS_URL not set", file=sys.stderr)
        sys.exit(1)

    user_msg = f"Dataset sample (first 3 rows):\n{json.dumps(csv_sample[:3], indent=2)}\n\nQuestion: {question}"

    payload = json.dumps({
        "model": MAAS_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        "temperature": 0,
        "max_tokens": 512,
    }).encode()

    headers = {"Content-Type": "application/json"}
    api_key = os.environ.get("MAAS_API_KEY")
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    req = urllib.request.Request(MAAS_URL, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"LLM API error: {e.code} {e.read().decode()}", file=sys.stderr)
        sys.exit(1)

    return body["choices"][0]["message"]["content"].strip()


def execute_code(code, rows):
    code = code.removeprefix("```python").removeprefix("```").removesuffix("```").strip()
    print(f"\n--- Generated Code ---\n{code}\n--- Executing ---\n")
    exec(code, {"rows": rows, "__builtins__": __builtins__})


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <question>")
        sys.exit(1)

    question = " ".join(sys.argv[1:])
    print(f"Question: {question}")

    rows = load_csv(CSV_PATH)
    print(f"Loaded {len(rows)} rows from {CSV_PATH}")

    code = ask_llm(question, rows)
    execute_code(code, rows)


if __name__ == "__main__":
    main()
