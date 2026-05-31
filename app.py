#!/usr/bin/env python3
"""
CF Scanner - Web Interface
Supports: VLESS + Trojan
https://t.me/Net4All_None
https://github.com/rohanprotapsingh
"""

import os
import sys
import time
import asyncio
import threading
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.vless_parser import parse_config_url
from scanner.cloudflare_ips import generate_random_ips, parse_custom_ranges
from scanner.core import VlessScanner
from scanner.config import OPERATORS
from telegram_bot.bot import (
    TelegramBot, save_telegram_settings,
    load_telegram_settings, delete_telegram_settings,
)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cf-scanner-secret-2024'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

scan_should_stop = False


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/telegram/test', methods=['POST'])
def telegram_test():
    data = request.json
    token = data.get('token', '')
    if not token:
        return jsonify({"success": False, "error": "Token is empty"})
    bot = TelegramBot(token)
    if bot.test_connection():
        return jsonify({"success": True, "bot_name": bot.bot_username})
    return jsonify({"success": False, "error": bot.last_error})


@app.route('/api/telegram/save', methods=['POST'])
def telegram_save():
    data = request.json
    save_telegram_settings(data.get('token', ''), data.get('chat_id', ''))
    return jsonify({"success": True})


@app.route('/api/telegram/load', methods=['GET'])
def telegram_load():
    return jsonify(load_telegram_settings())


@app.route('/api/telegram/delete', methods=['POST'])
def telegram_delete():
    delete_telegram_settings()
    return jsonify({"success": True})


@app.route('/api/telegram/send', methods=['POST'])
def telegram_send():
    data = request.json
    token = data.get('token', '')
    chat_id = data.get('chat_id', '')
    results = data.get('results', [])
    operator_key = data.get('operator', 'all')
    total_scanned = data.get('total_scanned', 0)
    total_found = data.get('total_found', 0)

    if not token or not chat_id:
        return jsonify({"success": False, "error": "Token or Chat ID empty"})

    if operator_key in OPERATORS:
        op_name = OPERATORS[operator_key]["name_en"]
    elif operator_key == "custom":
        op_name = "Custom Range"
    else:
        op_name = "All Operators"

    bot = TelegramBot(token, chat_id)
    msg = bot.format_results_clean(
        results=results, operator_name=op_name,
        total_scanned=total_scanned, total_found=total_found,
    )

    if bot.send_message(msg, chat_id):
        try:
            ip_list = '\n'.join([r.get('ip', '') for r in results if r.get('ip')])
            tmp = '/tmp/cf_clean_ips.txt'
            with open(tmp, 'w') as f:
                f.write(ip_list)
            bot.send_document(tmp, f"📎 {len(results)} Clean IPs", chat_id)
            os.remove(tmp)

            configs = '\n'.join([r.get('vless_url', '') for r in results if r.get('vless_url')])
            if configs:
                tmp2 = '/tmp/cf_configs.txt'
                with open(tmp2, 'w') as f:
                    f.write(configs)
                bot.send_document(tmp2, f"📎 {len(results)} Configs", chat_id)
                os.remove(tmp2)
        except Exception:
            pass
        return jsonify({"success": True})
    return jsonify({"success": False, "error": bot.last_error})


@socketio.on('start_scan')
def handle_start_scan(data):
    global scan_should_stop
    scan_should_stop = False
    thread = threading.Thread(target=run_scan_thread, args=(data,), daemon=True)
    thread.start()


@socketio.on('stop_scan')
def handle_stop_scan():
    global scan_should_stop
    scan_should_stop = True


def run_scan_thread(data):
    global scan_should_stop

    mode = data.get('mode', 'clean')
    ip_count = min(data.get('ip_count', 300), 50000)
    concurrent = min(data.get('concurrent', 50), 200)
    top_count = data.get('top_count', 20)
    sort_by = data.get('sort_by', 'score')
    operator = data.get('operator', 'all')
    custom_ranges_text = data.get('custom_ranges', '')

    start_time = time.time()

    vless_config = None
    if mode == 'vless':
        config_str = data.get('config', '')
        if not config_str:
            socketio.emit('scan_error', {"error": "Config is empty"})
            return
        try:
            vless_config = parse_config_url(config_str)
        except ValueError as e:
            socketio.emit('scan_error', {"error": f"Parse error: {str(e)}"})
            return

    custom_ranges = None
    if operator == 'custom' and custom_ranges_text:
        custom_ranges = parse_custom_ranges(custom_ranges_text)
        if not custom_ranges:
            custom_ranges = None

    try:
        ips = generate_random_ips(ip_count, custom_ranges, operator)
    except Exception as e:
        socketio.emit('scan_error', {"error": f"IP error: {str(e)}"})
        return

    scanner = VlessScanner(vless_config, concurrent)

    if mode == 'clean':
        scanner.no_config_mode = True
        scanner.scan_port = data.get('scan_port', 443)
        scanner.scan_sni = data.get('scan_sni', 'speed.cloudflare.com')
        scanner.test_tls = data.get('test_tls', True)
        scanner.test_speed = data.get('test_speed', True)

    def progress_cb(scanned, total, alive, last_result):
        if scan_should_stop:
            return
        socketio.emit('scan_progress', {
            "scanned": scanned, "total": total, "alive": alive,
            "last_result": last_result.to_dict() if last_result else None,
        })

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(scanner.scan_batch(ips, progress_cb))
    except Exception as e:
        socketio.emit('scan_error', {"error": str(e)})
        return
    finally:
        loop.close()

    elapsed = round(time.time() - start_time, 1)
    top_results = scanner.get_top_results(top_count, sort_by)

    socketio.emit('scan_complete', {
        "results": [r.to_dict() for r in top_results],
        "total_scanned": len(ips),
        "total_alive": len(scanner.get_alive_results()),
        "elapsed": elapsed,
    })


if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════╗
    ║       CF Scanner - VLESS + Trojan                ║
    ║                                                  ║
    ║  📡  http://localhost:5000                       ║
    ║                                                  ║
    ║  📱  Telegram: @Net4All_None                     ║
    ║  💻  GitHub: rohanprotapsingh                    ║
    ╚══════════════════════════════════════════════════╝
    """)
    socketio.run(app, host='0.0.0.0', port=5000,
                 debug=False, allow_unsafe_werkzeug=True)
