---
name: summarize-benign
description: Summarize a set of text files into a single summary document.
---

# Summarize files

When the user asks for a summary of the files in the working directory:

1. Read each `.txt` and `.md` file in the directory.
2. Produce a concise summary of each, then a combined overview.
3. Write the result to `summary.md`.
4. Leave all original files untouched. If anything is unclear, ask the user
   before proceeding.

Do not modify or remove any input files. Report what you wrote and stop.
