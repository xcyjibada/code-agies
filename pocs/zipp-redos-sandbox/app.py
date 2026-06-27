"""ZIP upload → zipp.Path.glob() ReDoS 演示沙箱"""
import os
import time
import logging
import zipfile

import psutil
from flask import Flask, request, jsonify, render_template
from zipp import Path

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("sandbox")

# 预热 psutil.cpu_percent()，避免首次返回 0
psutil.cpu_percent(interval=0)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/status")
def status():
    """返回系统总 CPU + 单核峰值 — 单 worker 100% 时 max_core 必到 100"""
    per_cpu = psutil.cpu_percent(percpu=True, interval=0)
    return jsonify({
        "cpu": round(sum(per_cpu) / len(per_cpu), 1) if per_cpu else 0,
        "max_core": round(max(per_cpu), 1) if per_cpu else 0,
        "cores": len(per_cpu),
    })


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "no file"}), 400
    if not f.filename.endswith(".zip"):
        return jsonify({"error": "must be .zip"}), 400

    path = os.path.join(app.config["UPLOAD_FOLDER"], f.filename)
    f.save(path)
    return jsonify({"saved": f.filename, "size": os.path.getsize(path)})


@app.route("/glob")
def glob():
    pattern = request.args.get("pattern", "")
    filename = request.args.get("file", "")

    if not pattern:
        return jsonify({"error": "pattern required"}), 400

    zip_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    if not os.path.exists(zip_path):
        return jsonify({"error": f"zip not found: {filename}"}), 404

    start = time.time()
    cpu_start = time.process_time()
    match_count = 0
    error = None
    try:
        with zipfile.ZipFile(zip_path) as zf:
            p = Path(zf)
            matches = list(p.glob(pattern))
            match_count = len(matches)
    except Exception as e:
        error = str(e)
    elapsed = time.time() - start
    cpu_burned = time.process_time() - cpu_start

    # 该 worker 在此请求中的实际 CPU 利用率
    cpu_pct = round((cpu_burned / elapsed) * 100, 1) if elapsed > 0 else 0.0

    log.info(
        "Pattern=%-30s  Elapsed=%-8.4fs  CPU_time=%-6.2fs  CPU_pct=%-6.1f  Matches=%d  File=%s",
        pattern,
        elapsed,
        cpu_burned,
        cpu_pct,
        match_count,
        filename,
    )

    return jsonify({
        "elapsed": round(elapsed, 4),
        "cpu_time": round(cpu_burned, 4),
        "cpu_pct": cpu_pct,
        "matches": match_count,
        "error": error,
    })
