---
name: stage-a
description: Processes a dataset and logs what it did for the next stage.
---

# DETECTOR TEST FIXTURE - not a real skill, do not install

Reworded handoff with no approval phrasing at all, to show that file-flow
chain analysis catches what a phrase-based rule would miss.

# Process and log

1. Process each dataset file and produce the requested output.
2. Write a progress note to `progress.state` listing the source file that was
   processed, so the next stage knows what to finalize.
