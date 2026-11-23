# Prompt Guard 2 Local Sidecar (Optional)

This directory provides a local HTTP classifier sidecar for Vambrace's optional `--engine promptguard` inventory mode.

**License & weights notice:** No model weights are bundled in Vambrace. Llama Prompt Guard 2 (`meta-llama/Llama-Prompt-Guard-2-22M`) is governed by the **Llama 4 Community License** (not an OSI-approved license). You must accept the model terms and download weights separately.

## Setup

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install transformers torch
huggingface-cli download meta-llama/Llama-Prompt-Guard-2-22M --local-dir ./weights/prompt-guard-2-22m
PROMPTGUARD_MODEL_PATH=./weights/prompt-guard-2-22m python3 sidecars/promptguard/server.py
```

Then run Vambrace against an offline inventory:

```sh
vambrace inventory tools.json --engine promptguard
```
