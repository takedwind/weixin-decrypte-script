import csv
import io
import json
import os
import queue
import re
import sys
import threading
import time
from flask import Flask, request, jsonify, Response
from flask_cors import CORS

from db_service import DBService
from decrypt_engine import ensure_decrypted, scan_keys_from_memory

app = Flask(__name__)
CORS(app)

PAY_TALKERS = {
    "gh_f0a92aa7146c",          # WeChat payment assistant
    "gh_e087bb5b95e6",          # WeChat merchant assistant
    "brandservicesessionholder",
}
PAY_NAMES = {
    "\u5fae\u4fe1\u6536\u6b3e\u52a9\u624b",
    "\u5fae\u4fe1\u652f\u4ed8\u5546\u5bb6\u52a9\u624b",
}
PAY_KEYWORDS = [
    "\u5fae\u4fe1\u652f\u4ed8\u6536\u6b3e",
    "\u6536\u6b3e\u5230\u8d26",
    "\u5fae\u4fe1\u6536\u6b3e",
    "\u4ed8\u6b3e\u65b9\u5907\u6ce8",
]

db_service = None
data_root_dir = None
db_storage_dir = None
decrypt_keys_hex = None
auto_decrypt_enabled = True

state_lock = threading.RLock()
event_queue = queue.Queue(maxsize=200)
seen_pay_keys = set()
last_file_signature = {}
last_refresh_time = 0.0
last_seen_pay_seq = 0
watcher_started = False
watcher_stop = threading.Event()


def get_db() -> DBService | None:
    with state_lock:
        return db_service


def find_db_storage_dir(data_dir):
    if os.path.exists(os.path.join(data_dir, "db_storage")):
        return os.path.join(data_dir, "db_storage")

    for root, dirs, files in os.walk(data_dir):
        for d in dirs:
            candidate = os.path.join(root, d, "db_storage")
            if os.path.exists(candidate):
                return candidate

    return data_dir


def find_active_db_storage(base_dir):
    if not base_dir:
        return None
    if os.path.basename(base_dir).lower() == "db_storage":
        return base_dir
    if os.path.exists(os.path.join(base_dir, "db_storage")):
        return os.path.join(base_dir, "db_storage")

    candidates = []
    for name in os.listdir(base_dir):
        account_dir = os.path.join(base_dir, name)
        db_storage = os.path.join(account_dir, "db_storage")
        if not os.path.isdir(db_storage):
            continue
        latest = 0.0
        for path in watched_paths_for_storage(db_storage):
            if os.path.exists(path):
                latest = max(latest, os.path.getmtime(path))
        if latest > 0:
            candidates.append((latest, db_storage))

    if not candidates:
        return find_db_storage_dir(base_dir)

    candidates.sort(reverse=True)
    return candidates[0][1]


def watched_paths_for_storage(storage_dir):
    return [
        os.path.join(storage_dir, "message", "biz_message_0.db"),
        os.path.join(storage_dir, "message", "biz_message_0.db-wal"),
        os.path.join(storage_dir, "message", "biz_message_0.db-shm"),
        os.path.join(storage_dir, "message", "message_0.db"),
        os.path.join(storage_dir, "message", "message_0.db-wal"),
        os.path.join(storage_dir, "session", "session.db"),
        os.path.join(storage_dir, "session", "session.db-wal"),
    ]


def get_file_signature(storage_dir):
    signature = {}
    for path in watched_paths_for_storage(storage_dir):
        if os.path.exists(path):
            try:
                stat = os.stat(path)
                signature[path] = (stat.st_mtime_ns, stat.st_size)
            except OSError:
                pass
    return signature


def refresh_database_if_needed(force=False):
    global db_service, db_storage_dir, last_file_signature, last_refresh_time

    with state_lock:
        active_storage = find_active_db_storage(data_root_dir or db_storage_dir)
        if not active_storage:
            return False

        if active_storage != db_storage_dir:
            db_storage_dir = active_storage
            db_service = DBService(db_storage_dir)
            force = True

        signature = get_file_signature(db_storage_dir)
        changed = force or signature != last_file_signature
        if not changed:
            return False

        now = time.time()
        if not force and now - last_refresh_time < 0.6:
            return False

        if auto_decrypt_enabled and decrypt_keys_hex:
            ensure_decrypted(db_storage_dir, decrypt_keys_hex)

        if db_service is None:
            db_service = DBService(db_storage_dir)
        db_service.init()

        last_file_signature = signature
        last_refresh_time = now
        return True


def parse_pay_from_message(message):
    content = message.content or ""
    title = _extract_xml_value(content, "title") or content
    desc = _extract_xml_value(content, "des") or ""
    text = f"{title}\n{desc}"
    amount = _extract_pay_amount(text)
    if not amount:
        return None
    if not any(k in text for k in PAY_KEYWORDS):
        return None

    return {
        "channel": "wechat",
        "amount": amount,
        "title": title,
        "desc": desc,
        "content": content,
        "time": message.time,
        "seq": message.seq,
        "talker": message.talker,
        "sender": message.sender,
        "dedupe_key": build_pay_dedupe_key(amount, title, desc, message.time),
    }


def get_latest_pay_messages(limit=20, since_seq=0):
    db = get_db()
    if db is None:
        return []

    pay_items = []
    talkers = ",".join(PAY_TALKERS)
    messages, _ = db.get_messages(talker=talkers, limit=limit * 3, offset=0, order="desc")
    for message in messages:
        if since_seq and message.seq <= since_seq:
            continue
        item = parse_pay_from_message(message)
        if item:
            pay_items.append(item)

    if len(pay_items) < limit and since_seq == 0:
        pay_items.extend(get_pay_sessions(limit=limit))

    deduped = []
    seen = set()
    for item in pay_items:
        key = item.get("dedupe_key") or (item.get("time"), item.get("title") or item.get("content"), item.get("amount"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    deduped.sort(key=lambda item: item.get("seq") or 0, reverse=True)
    return deduped[:limit]


def get_current_max_pay_seq():
    items = get_latest_pay_messages(limit=20, since_seq=0)
    seq_values = [int(item.get("seq") or 0) for item in items if int(item.get("seq") or 0) > 0]
    return max(seq_values, default=0)


def get_pay_sessions(limit=20):
    db = get_db()
    if db is None:
        return []

    result = []
    sessions = db.get_sessions(limit=200, offset=0).items
    for session in sessions:
        content = session.content or ""
        is_pay_user = session.username in PAY_TALKERS or session.nick_name in PAY_NAMES
        is_pay_content = any(k in content for k in PAY_KEYWORDS)
        if not is_pay_user and not is_pay_content:
            continue
        amount = _extract_pay_amount(content)
        result.append({
            "channel": "wechat",
            "amount": amount,
            "title": content,
            "desc": "",
            "content": content,
            "time": session.time,
            "seq": 0,
            "talker": session.username,
            "sender": "",
            "nick_name": session.nick_name,
            "username": session.username,
            "dedupe_key": build_pay_dedupe_key(amount, content, "", session.time),
        })
    return result[:limit]


def publish_new_pay_events(items):
    for item in items:
        if not item.get("amount"):
            continue
        if item.get("seq", 0) <= 0:
            continue
        key = item.get("dedupe_key") or (item.get("time"), item.get("title"), item.get("amount"))
        if key in seen_pay_keys:
            continue
        seen_pay_keys.add(key)
        try:
            event_queue.put_nowait(item)
        except queue.Full:
            try:
                event_queue.get_nowait()
            except queue.Empty:
                pass
            event_queue.put_nowait(item)


def watcher_loop():
    global last_seen_pay_seq
    while not watcher_stop.is_set():
        try:
            changed = refresh_database_if_needed()
            if changed:
                items = get_latest_pay_messages(limit=5, since_seq=last_seen_pay_seq)
                publish_new_pay_events(items)
                max_seq = max([int(item.get("seq") or 0) for item in items], default=last_seen_pay_seq)
                last_seen_pay_seq = max(last_seen_pay_seq, max_seq)
        except Exception as exc:
            print(f"[Watcher] {exc}")
        watcher_stop.wait(0.5)


def start_watcher():
    global watcher_started, last_seen_pay_seq
    if watcher_started:
        return
    last_seen_pay_seq = get_current_max_pay_seq()
    print(f"[Watcher] Baseline pay seq: {last_seen_pay_seq}")
    watcher_started = True
    thread = threading.Thread(target=watcher_loop, name="wechat-pay-db-watcher", daemon=True)
    thread.start()


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "db_storage": db_storage_dir,
        "watcher": watcher_started,
    })


@app.route("/api/v1/chatlog", methods=["GET"])
def handle_chatlog():
    refresh_database_if_needed()
    db = get_db()
    if db is None:
        return jsonify({"error": "database not initialized"}), 503

    talker = request.args.get("talker", "")
    sender = request.args.get("sender", "")
    keyword = request.args.get("keyword", "")
    start_time = request.args.get("time", "")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    fmt = request.args.get("format", "json").lower()
    order = request.args.get("order", "desc").lower()

    if not talker:
        return jsonify({"error": "talker parameter is required"}), 400

    messages, total = db.get_messages(
        talker=talker,
        start_time=start_time if start_time else None,
        end_time=None,
        sender=sender,
        keyword=keyword,
        limit=max(limit, 0),
        offset=max(offset, 0),
        order=order,
    )

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Time", "SenderName", "Sender", "TalkerName", "Talker", "Content"])
        for m in messages:
            writer.writerow([m.time, m.sender_name, m.sender, m.talker_name, m.talker, m.content])
        return Response(output.getvalue(), mimetype="text/csv; charset=utf-8")

    if fmt == "text":
        lines = [m.to_plain_text(show_chatroom="," in talker) for m in messages]
        return Response("\n".join(lines), mimetype="text/plain; charset=utf-8")

    return jsonify({
        "total": total,
        "limit": limit,
        "offset": offset,
        "order": order,
        "items": [m.to_dict() for m in messages],
    })


@app.route("/api/v1/contact", methods=["GET"])
def handle_contacts():
    db = get_db()
    if db is None:
        return jsonify({"error": "database not initialized"}), 503

    keyword = request.args.get("keyword", "")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    result = db.get_contacts(keyword=keyword, limit=limit, offset=offset)
    return jsonify(result.to_dict())


@app.route("/api/v1/chatroom", methods=["GET"])
def handle_chatrooms():
    db = get_db()
    if db is None:
        return jsonify({"error": "database not initialized"}), 503

    keyword = request.args.get("keyword", "")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    result = db.get_chatrooms(keyword=keyword, limit=limit, offset=offset)
    return jsonify(result.to_dict())


@app.route("/api/v1/session", methods=["GET"])
def handle_sessions():
    refresh_database_if_needed()
    db = get_db()
    if db is None:
        return jsonify({"error": "database not initialized"}), 503

    keyword = request.args.get("keyword", "")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    result = db.get_sessions(keyword=keyword, limit=limit, offset=offset)
    return jsonify(result.to_dict())


@app.route("/api/v1/pay-session", methods=["GET"])
def handle_pay_session():
    refresh_database_if_needed()
    limit = int(request.args.get("limit", 20))
    items = get_pay_sessions(limit=limit)
    deduped = []
    seen = set()
    for item in items:
        key = (item.get("time"), item.get("content"), item.get("amount"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return jsonify({"total": len(deduped), "items": deduped})


@app.route("/api/v1/pay-latest", methods=["GET"])
def handle_pay_latest():
    refresh_database_if_needed()
    limit = int(request.args.get("limit", 20))
    new_only = request.args.get("new_only", "0") in ("1", "true", "yes")
    since_seq = int(request.args.get("since_seq", last_seen_pay_seq if new_only else 0))
    items = get_latest_pay_messages(limit=limit, since_seq=since_seq)
    return jsonify({
        "total": len(items),
        "since_seq": since_seq,
        "last_seen_pay_seq": last_seen_pay_seq,
        "items": items,
    })


@app.route("/api/v1/pay-events", methods=["GET"])
def handle_pay_events():
    def stream():
        yield ": connected\n\n"
        while True:
            try:
                item = event_queue.get(timeout=15)
                yield f"event: pay\ndata: {json.dumps(item, ensure_ascii=False)}\n\n"
            except queue.Empty:
                yield ": heartbeat\n\n"

    return Response(stream(), mimetype="text/event-stream")


@app.route("/api/v1/search", methods=["GET"])
def handle_search():
    refresh_database_if_needed()
    db = get_db()
    if db is None:
        return jsonify({"error": "database not initialized"}), 503

    keyword = request.args.get("keyword", "")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    if not keyword:
        return jsonify({"error": "keyword parameter is required"}), 400

    messages, total = db.search_messages(keyword=keyword, limit=limit, offset=offset)
    return jsonify({"total": total, "items": messages})


def _extract_xml_value(xml_str, key):
    if not xml_str:
        return None
    pattern = rf"<{key}>\s*<!\[CDATA\[(.*?)\]\]>\s*</{key}>"
    match = re.search(pattern, xml_str, re.DOTALL)
    if match:
        return match.group(1).strip()
    pattern = rf"<{key}>(.*?)</{key}>"
    match = re.search(pattern, xml_str, re.DOTALL)
    return match.group(1).strip() if match else None


def _extract_pay_amount(content):
    if not content:
        return None
    patterns = [
        r"\u5fae\u4fe1\u652f\u4ed8\u6536\u6b3e\s*([0-9]+(?:\.[0-9]{1,2})?)\s*\u5143",
        r"\u6536\u6b3e\u91d1\u989d\s*\uffe5?\s*([0-9]+(?:\.[0-9]{1,2})?)",
        r"\u6536\u6b3e(?:\u5230\u8d26)?\s*([0-9]+(?:\.[0-9]{1,2})?)\s*\u5143",
    ]
    for pattern in patterns:
        match = re.search(pattern, content)
        if match:
            return match.group(1)
    return None


def build_pay_dedupe_key(amount, title, desc, pay_time):
    text = f"{title or ''}\n{desc or ''}"
    count_match = re.search(r"\u4eca\u65e5\u7b2c\s*([0-9]+)\s*\u7b14\u6536\u6b3e", text)
    total_match = re.search(r"\u5171\u8ba1\s*\uffe5?\s*([0-9]+(?:\.[0-9]{1,2})?)", text)
    count = count_match.group(1) if count_match else ""
    total = total_match.group(1) if total_match else ""
    return "|".join([
        str(pay_time or ""),
        str(amount or ""),
        str(count),
        str(total),
    ])


def main():
    global db_service, data_root_dir, db_storage_dir, decrypt_keys_hex, auto_decrypt_enabled

    import argparse
    parser = argparse.ArgumentParser(description="WeChat Chat Record JSON API Server")
    parser.add_argument("data_dir", nargs="?", default=None,
                        help="Path to xwechat_files, account directory, or db_storage directory")
    parser.add_argument("--key", default=None, help="Database decryption key (hex)")
    parser.add_argument("--key-file", default=None, help="File containing decryption keys")
    parser.add_argument("--no-decrypt", action="store_true", help="Skip auto-decryption")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5050)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.data_dir is None:
        args.data_dir = os.path.join(os.environ.get("USERPROFILE", ""), "Documents", "xwechat_files")

    if not os.path.exists(args.data_dir):
        print(f"Error: Directory not found: {args.data_dir}")
        sys.exit(1)

    data_root_dir = args.data_dir
    db_storage_dir = find_active_db_storage(data_root_dir)
    print(f"[API] Active data directory: {db_storage_dir}")

    if not args.no_decrypt:
        if args.key:
            decrypt_keys_hex = [args.key]
        elif args.key_file:
            with open(args.key_file, "r", encoding="utf-8") as f:
                decrypt_keys_hex = [line.strip().split("\t")[-1] for line in f if line.strip()]
        else:
            print("[API] No key provided, attempting auto-scan from WeChat memory...")
            decrypt_keys_hex = scan_keys_from_memory()
    else:
        auto_decrypt_enabled = False

    refresh_database_if_needed(force=True)
    start_watcher()

    print(f"\n[API] Starting server on http://{args.host}:{args.port}")
    print("API Endpoints:")
    print("  GET /api/v1/pay-latest?since_seq=0")
    print("  GET /api/v1/pay-events")
    print("  GET /api/v1/pay-session")
    print("  GET /api/v1/chatlog?talker=<id>")
    print("  GET /api/v1/session")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
