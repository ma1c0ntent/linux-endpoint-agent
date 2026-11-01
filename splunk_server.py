#!/usr/bin/env python3

import os
import json
import hmac
import logging
import threading

from pathlib import Path
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.getenv("HEC_HOST", "127.0.0.1")
PORT = int(os.getenv("HEC_PORT", "8088"))
TOKEN = os.environ.get("HEC_TOKEN")

DATA_FILE = Path(os.getenv("HEC_DATA_FILE", "./hec_events.jsonl"))

MAX_BODY_SIZE = 5 * 1024 * 1024  # 5 MB

# Print each request's headers and pretty-printed events (HEC_SHOW_EVENTS=0 to disable).
SHOW_EVENTS = os.getenv("HEC_SHOW_EVENTS", "1") != "0"

WRITE_LOCK = threading.Lock()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

if not TOKEN:
    logging.error("HEC_TOKEN environment variable is not set. Exiting.")
    exit(1)

def save_event(payload):
    """Save the event payload to a file in JSON Lines format."""
    record = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "payload": payload
    }
    with WRITE_LOCK:
        new_file = not DATA_FILE.exists()
        with DATA_FILE.open("a", encoding="utf-8") as f:
            if new_file:
                logging.info(f"Creating new data file: {DATA_FILE}")
            f.write(json.dumps(record) + "\n")
            f.flush()

    if new_file:
        logging.info(f"Saved event to new data file: {DATA_FILE}")
    else:
        logging.info(f"Saved event to existing data file: {DATA_FILE}")


class HECHandler(BaseHTTPRequestHandler):
    """HTTP handler for Splunk HEC events."""
    
    def send_json(self, status, data):
        """Send a JSON response with the given status and data."""
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authenticate(self):
        """Authenticate the request using the HEC token."""
        authorization = self.headers.get("Authorization", "")

        if not authorization.startswith("Splunk "):
            logging.warning("Missing or invalid Authorization header.")
            return False

        supplied_token = authorization[7:]  # Remove "Splunk " prefix
        return hmac.compare_digest(supplied_token, TOKEN)

    def do_GET(self):
        """Handkle GET requests for health checks."""
        if self.path == "/health":
            return self.send_json(200, {
                "status": "ok",
                "service": "Splunk HEC Mock Server",
                "version": "1.0.0"
                })
        if self.path == "/events":
            if not self.authenticate():
                return self.send_json(401, {
                    "error": "Unauthorized",
                    "code": 4
                    })
            events = []
            if DATA_FILE.exists():
                with DATA_FILE.open(encoding="utf-8") as f:
                    for line in f:
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            logging.error("Failed to decode JSON line: %s", line)
                            continue
            return self.send_json(200, {
                "count": len(events), 
                "events": events[-100:]
            })
        self.send_json(404, {"error": "Not Found"})

    def do_POST(self):
        """Handle POST requests for HEC events."""
        if self.path != "/services/collector/event":
            return self.send_json(404, {"text": "Not Found", "code": 6})

        if not self.authenticate():
            return self.send_json(401, {
                "text": "Unauthorized",
                "code": 4
            })

        try:
            content_length = int(
                self.headers.get("Content-Length", 0)
            )
            if content_length <= 0:
                raise ValueError("Content-Length must be greater than 0")

            if content_length > MAX_BODY_SIZE:
                return self.send_json(413, {
                    "text": "Request too large",
                    "code": 6
                })
            body = self.rfile.read(content_length).decode("utf-8")

            try:
                payloads = [json.loads(body)]
            except json.JSONDecodeError:
                # Batched requests are newline-delimited JSON objects.
                payloads = [
                    json.loads(line)
                    for line in body.splitlines()
                    if line.strip()
                ]
            if not payloads:
                raise ValueError("No valid JSON payloads found in request body.")

            if SHOW_EVENTS:
                self.show_request(payloads)

            for payload in payloads:
                if not isinstance(payload, dict):
                    raise ValueError("Each payload must be a JSON object.")

                if "event" not in payload:
                    raise ValueError("Missing 'event' field in payload.")
                
                save_event(payload)
            logging.info("Accepted %d event(s)", len(payloads))
            return self.send_json(200, {"text": "Success", "code": 0})
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as e:
            logging.warning("Rejected request: %s", e)

            return self.send_json(400, {
                "text": "Invalid event payload",
                "code": 6
            })
        except OSError:
            logging.exception("Failed to persist event")
            return self.send_json(500, {
                "text": "Internal server error",
                "code": 6
            })
    def show_request(self, payloads):
        """Print the request line, headers (token masked) and each event."""
        lines = [f"{self.command} {self.path} {self.request_version}"]
        for name, value in self.headers.items():
            if name.lower() == "authorization":
                value = "Splunk ****"
            lines.append(f"{name}: {value}")
        lines.append("")
        for index, payload in enumerate(payloads, 1):
            lines.append(f"--- event {index}/{len(payloads)} ---")
            lines.append(json.dumps(payload, indent=2, sort_keys=True))
        print("=" * 72 + "\n" + "\n".join(lines) + "\n" + "=" * 72, flush=True)

    def log_message(self, format, *args):
        """Override to prevent default logging to stderr."""
        logging.info("%s - %s", self.client_address[0], format % args)

if __name__ == "__main__":

    server = ThreadingHTTPServer((HOST, PORT), HECHandler)
    logging.info("Starting Splunk HEC Mock Server on %s:%s", HOST, PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down Splunk HEC Mock Server")
    finally:
        server.server_close()