import sqlite3
import time

def netscape_to_chromium(cookies_txt_path, chromium_cookies_path):
    conn = sqlite3.connect(chromium_cookies_path)
    cursor = conn.cursor()

    with open(cookies_txt_path, 'r') as f:
        for line in f:
            if line.startswith('#') or line.strip() == '':
                continue

            parts = line.strip().split('\t')
            if len(parts) != 7:
                continue

            domain, include_subdomains, path, secure, expiry, name, value = parts

            # Parse expiry which may be a float (e.g. '1776768493.926')
            try:
                expiry_ts = int(float(expiry))
            except Exception:
                # Treat invalid expiry as session cookie (no expiry)
                expiry_ts = 0

            # Chromium stores time as microseconds since 1601-01-01
            chrome_expiry = (expiry_ts + 11644473600) * 1000000 if expiry_ts > 0 else 0
            now = (int(time.time()) + 11644473600) * 1000000

            # Normalize secure field
            secure_flag = 1 if str(secure).upper() == 'TRUE' else 0

            cursor.execute('''
                INSERT OR REPLACE INTO cookies
                (creation_utc, host_key, top_frame_site_key, name, value,
                 encrypted_value, path, expires_utc, is_secure, is_httponly,
                 last_access_utc, has_expires, is_persistent, priority,
                 samesite, source_scheme, source_port, last_update_utc,
                 source_type, has_cross_site_ancestor)
                VALUES (?, ?, '', ?, ?, '', ?, ?, ?, 0, ?, 1, 1, 1, -1, 2, 443, ?, ?, ?)
            ''', (now, domain, name, value, path, chrome_expiry,
                  secure_flag, now, now, 0, 0))

    conn.commit()
    conn.close()

netscape_to_chromium('cookies.txt', 'Cookies')
