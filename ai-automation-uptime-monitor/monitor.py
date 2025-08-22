import asyncio, csv, os, time
from datetime import datetime
from typing import List, Optional

import aiohttp
from dotenv import load_dotenv

load_dotenv()

URLS = [u.strip() for u in os.getenv("URLS", "https://example.com").split(",") if u.strip()]
TIMEOUT_SECONDS = int(os.getenv("TIMEOUT_SECONDS", "5"))
SLOW_MS = int(os.getenv("SLOW_MS", "1200"))
TG_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or ""
TG_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID") or ""
CSV_PATH = os.getenv("CSV_PATH", "uptime_log.csv")
HTTP_METHOD = os.getenv("HTTP_METHOD", "GET").upper()
MAX_CONNECTIONS = int(os.getenv("MAX_CONNECTIONS", "20"))
HEADERS = {"User-Agent": os.getenv("USER_AGENT", "uptime-monitor/1.0 (+https://example.org)")}


async def send_telegram(message: str):
    if not TG_TOKEN or not TG_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
    payload = {"chat_id": TG_CHAT_ID, "text": message}
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        try:
            async with session.post(url, json=payload) as resp:
                await resp.read()
        except Exception:
            pass  # don't crash monitoring on alert issues


async def check_url(session: aiohttp.ClientSession, url: str):
    t0 = time.perf_counter()
    status = None
    ok = False
    error: Optional[str] = None
    try:
        if HTTP_METHOD == "HEAD":
            async with session.head(url, headers=HEADERS) as resp:
                status = resp.status
                ok = 200 <= resp.status < 400
        else:
            async with session.get(url, headers=HEADERS) as resp:
                status = resp.status
                ok = 200 <= resp.status < 400
                await resp.read()
    except Exception as e:
        error = str(e)
    ms = int((time.perf_counter() - t0) * 1000)
    return {"url": url, "status": status, "ok": ok, "ms": ms, "error": error}


async def run_once(urls: List[str]):
    timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS + 1)
    connector = aiohttp.TCPConnector(limit=MAX_CONNECTIONS)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        results = await asyncio.gather(*(check_url(session, u) for u in urls))
    # log to CSV
    fresh = not os.path.exists(CSV_PATH)
    with open(CSV_PATH, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if fresh:
            w.writerow(["ts","url","status","ok","ms","error"])
        for r in results:
            ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
            w.writerow([ts, r["url"], r["status"], r["ok"], r["ms"], r["error"] or ""])
    # alerts
    alerts = []
    for r in results:
        if not r["ok"] or r["ms"] >= SLOW_MS:
            alerts.append(f"{'SLOW' if r['ok'] else 'DOWN'}: {r['url']} | status={r['status']} ms={r['ms']} err={r['error']}")
    if alerts:
        await send_telegram("\n".join(alerts))
    # print summary to console
    for r in results:
        print(f"{r['url']}: status={r['status']} ok={r['ok']} {r['ms']}ms")


if __name__ == "__main__":
    asyncio.run(run_once(URLS))
