#!/usr/bin/env python3
"""Optional local sidecar for Llama Prompt Guard 2 (weights downloaded by user)."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os


def load_classifier():
    model_path = os.environ.get("PROMPTGUARD_MODEL_PATH", "")
    if not model_path:
        raise RuntimeError(
            "Set PROMPTGUARD_MODEL_PATH to your local Llama-Prompt-Guard-2-22M weights directory."
        )
    from transformers import pipeline  # lazy import so sidecar stays optional

    return pipeline("text-classification", model=model_path, local_files_only=True)


def create_handler(clf):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/classify":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            items = payload.get("items", [])
            results = []
            for item in items:
                out = clf(item.get("text", ""), truncation=True)[0]
                label = str(out.get("label", "BENIGN")).upper()
                score = float(out.get("score", 0.0))
                results.append(
                    {
                        "pointer": item.get("pointer"),
                        "label": label,
                        "score": score,
                        "malicious": label in ("INJECTION", "MALICIOUS", "LABEL_1"),
                    }
                )
            body = json.dumps({"results": results}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            return

    return Handler


if __name__ == "__main__":
    port = int(os.environ.get("PROMPTGUARD_PORT", "8787"))
    classifier = load_classifier()
    server = HTTPServer(("127.0.0.1", port), create_handler(classifier))
    print(f"Prompt Guard sidecar listening on http://127.0.0.1:{port}", flush=True)
    server.serve_forever()
