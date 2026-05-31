import os
import json
import requests as req

SETTINGS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    '.telegram_settings.json'
)

TELEGRAM_API_URLS = [
    "https://api.telegram.org",
    "https://tg.bahmanpg.com",
    "https://api.telegram.dog",
    "https://telegram.caoy.top",
    "https://api.telegram.vision",
]


def find_working_api() -> str:
    for api_url in TELEGRAM_API_URLS:
        try:
            resp = req.get(f"{api_url}/bot0:test/getMe", timeout=5)
            if resp.status_code in (200, 401, 404):
                return api_url
        except Exception:
            continue
    return TELEGRAM_API_URLS[0]


class TelegramBot:
    def __init__(self, token: str = "", chat_id: str = ""):
        self.token = token
        self.chat_id = chat_id
        self.is_connected = False
        self.last_error = ""
        self.bot_username = ""
        self.api_base = find_working_api()
        self.base_url = f"{self.api_base}/bot{token}" if token else ""

    def test_connection(self) -> bool:
        try:
            resp = req.get(f"{self.base_url}/getMe", timeout=15)
            data = resp.json()
            if data.get("ok"):
                self.is_connected = True
                self.bot_username = data.get('result', {}).get('username', '')
                self.last_error = ""
                return True
            else:
                self.last_error = data.get("description", "Unknown error")
                return False
        except req.exceptions.ConnectionError:
            for api_url in TELEGRAM_API_URLS:
                if api_url == self.api_base:
                    continue
                try:
                    url = f"{api_url}/bot{self.token}/getMe"
                    resp = req.get(url, timeout=10)
                    data = resp.json()
                    if data.get("ok"):
                        self.api_base = api_url
                        self.base_url = f"{api_url}/bot{self.token}"
                        self.is_connected = True
                        self.bot_username = data.get('result', {}).get('username', '')
                        self.last_error = ""
                        return True
                except Exception:
                    continue
            self.last_error = "All Telegram APIs are blocked. Please use VPN."
            return False
        except Exception as e:
            self.last_error = str(e)
            return False

    def send_message(self, text: str, chat_id: str = None, parse_mode: str = "HTML") -> bool:
        target = chat_id or self.chat_id
        if not target:
            self.last_error = "Chat ID not set"
            return False
        try:
            if len(text) > 4000:
                chunks = self._split_message(text, 4000)
                for chunk in chunks:
                    resp = req.post(
                        f"{self.base_url}/sendMessage",
                        json={"chat_id": target, "text": chunk, "parse_mode": parse_mode},
                        timeout=15,
                    )
                    if not resp.json().get("ok"):
                        self.last_error = resp.json().get("description", "")
                        return False
                return True
            else:
                resp = req.post(
                    f"{self.base_url}/sendMessage",
                    json={"chat_id": target, "text": text, "parse_mode": parse_mode},
                    timeout=15,
                )
                data = resp.json()
                if not data.get("ok"):
                    self.last_error = data.get("description", "")
                return data.get("ok", False)
        except Exception as e:
            self.last_error = str(e)
            return False

    def send_document(self, file_path: str, caption: str = "", chat_id: str = None) -> bool:
        target = chat_id or self.chat_id
        if not target:
            return False
        try:
            with open(file_path, 'rb') as f:
                resp = req.post(
                    f"{self.base_url}/sendDocument",
                    data={"chat_id": target, "caption": caption, "parse_mode": "HTML"},
                    files={"document": f},
                    timeout=30,
                )
            return resp.json().get("ok", False)
        except Exception as e:
            self.last_error = str(e)
            return False

    def _split_message(self, text: str, max_len: int) -> list:
        chunks = []
        while text:
            if len(text) <= max_len:
                chunks.append(text)
                break
            split_pos = text.rfind('\n', 0, max_len)
            if split_pos == -1:
                split_pos = max_len
            chunks.append(text[:split_pos])
            text = text[split_pos:].lstrip('\n')
        return chunks

    def format_results_clean(self, results: list, operator_name: str = "All Operators",
                             total_scanned: int = 0, total_found: int = 0) -> str:
        msg = "🔍 <b>لیست آی پی های تمیز</b>\n\n"
        msg += f"📶 <b>Operator:</b> {operator_name}\n\n"
        msg += f"📊 <b>Results:</b>\n"
        msg += f"• Scanned: {total_scanned:,}\n"
        msg += f"• Found: {total_found}\n\n"
        if len(results) >= 1:
            msg += "🏆 <b>Top 3 Fastest IPs:</b>\n\n"
            medals = ['🥇', '🥈', '🥉']
            for i, r in enumerate(results[:3]):
                ip = r.get('ip', '') if isinstance(r, dict) else r.ip
                msg += f"{medals[i]} <code>{ip}</code>\n"
            msg += "\n"
        msg += "✨ <b>لیست کامل آی‌پی :</b>\n\n"
        for r in results:
            ip = r.get('ip', '') if isinstance(r, dict) else r.ip
            msg += f"<code>{ip}</code>\n"
        return msg


def save_telegram_settings(token: str, chat_id: str):
    import base64
    data = {
        "token": base64.b64encode(token.encode()).decode(),
        "chat_id": base64.b64encode(chat_id.encode()).decode(),
    }
    try:
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(data, f)
        os.chmod(SETTINGS_FILE, 0o600)
    except Exception:
        pass


def load_telegram_settings() -> dict:
    import base64
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, 'r') as f:
                data = json.load(f)
            return {
                "token": base64.b64decode(data.get("token", "")).decode(),
                "chat_id": base64.b64decode(data.get("chat_id", "")).decode(),
            }
    except Exception:
        pass
    return {"token": "", "chat_id": ""}


def delete_telegram_settings():
    try:
        if os.path.exists(SETTINGS_FILE):
            os.remove(SETTINGS_FILE)
    except Exception:
        pass
