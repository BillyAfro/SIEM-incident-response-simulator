import re
import base64
import urllib.parse
import asyncio
import logging
from datetime import datetime, timedelta

# Advanced Logging Configuration for SIEM parsing
logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "module": "WAF_CORE", %(message)s}'
)

class AdvancedWAF:
    def __init__(self, rps_threshold: int = 5, cleanup_interval: int = 60):
        self.rps_threshold = rps_threshold
        self.cleanup_interval = cleanup_interval
        self.request_history = {}  # Structure: { ip: [timestamp1, timestamp2, ...] }
        
        # Compiled Regex Compiled Patterns for maximum execution speed
        self.b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
        self.comment_pattern = re.compile(r'/\*.*?\*/')
        self.sqli_pattern = re.compile(r"(\b(select|union|insert|update|delete|drop|alter|where|from|having|or|and)\b)|(['\"`\-\-\#])|(\bexec\b)")
        self.rfi_pattern = re.compile(r"(https?://|ftp://|[\.\.\/]{3,})")
        
        # Start the background asynchronous garbage collector for memory management
        asyncio.create_task(self._memory_cleanup_loop())

    async def _memory_cleanup_loop(self):
        """Asynchronous Garbage Collector: Prevents RAM bloat by evicting stale metrics."""
        while True:
            await asyncio.sleep(self.cleanup_interval)
            now = datetime.now()
            cutoff = now - timedelta(seconds=1)
            
            # Safe keys iteration to prevent runtime mutation errors
            for ip in list(self.request_history.keys()):
                # Keep only timestamps from the last second
                self.request_history[ip] = [t for t in self.request_history[ip] if t > cutoff]
                if not self.request_history[ip]:
                    del self.request_history[ip]

    def _recursive_decode(self, payload: str, max_depth: int = 5) -> str:
        """Defeats Double/Triple URL Encoding and nested obfuscation recursively."""
        current = payload
        for _ in range(max_depth):
            previous = current
            
            # Layer 1: Hex / URL-Decode
            current = urllib.parse.unquote(current)
            
            # Layer 2: Extract & Translate Base64 blocks
            def b64_replacer(match):
                try:
                    return base64.b64decode(match.group(0)).decode('utf-8', errors='ignore')
                except Exception:
                    return match.group(0)
            current = self.b64_pattern.sub(b64_replacer, current)
            
            # Layer 3: Strip Inline SQL Comments (e.g., U/**/NION -> UNION)
            current = self.comment_pattern.sub('', current)
            
            # Normalization
            current = current.lower().strip()
            
            # If payload stopped changing, deep decoding is complete
            if current == previous:
                break
                
        return current

    async def _check_dos(self, ip: str) -> bool:
        """Sliding window rate-limiter. True if clean, False if blocked."""
        now = datetime.now()
        cutoff = now - timedelta(seconds=1)
        
        if ip not in self.request_history:
            self.request_history[ip] = []
            
        # Filter out hits older than 1 second
        self.request_history[ip] = [t for t in self.request_history[ip] if t > cutoff]
        
        # Log current hit
        self.request_history[ip].append(now)
        
        return len(self.request_history[ip]) <= self.rps_threshold

    async def inspect_request(self, ip: str, uri: str) -> tuple[str, str]:
        """Core asynchronous inspection pipeline."""
        
        # 1. Volumetric DoS Layer
        if not await self._check_dos(ip):
            logging.warning(f'"event": "DOS_ATTACK", "ip": "{ip}", "details": "Rate limit exceeded"')
            return "BLOCK_DOS", "Rate limit exceeded."
            
        # 2. Deep Deep Recursive Normalization
        normalized = self._recursive_decode(uri)
        
        # 3. SQLi Inspection Layer
        if self.sqli_pattern.search(normalized):
            logging.error(f'"event": "SQLI_ATTACK", "ip": "{ip}", "uri": "{uri}", "normalized": "{normalized}"')
            return "BLOCK_SQLI", "Malicious SQL syntax matched structural signature."
            
        # 4. RFI / Path Traversal Layer
        if self.rfi_pattern.search(normalized):
            logging.error(f'"event": "RFI_ATTACK", "ip": "{ip}", "uri": "{uri}"')
            return "BLOCK_RFI", "Remote Resource Injection or Directory Traversal detected."
            
        return "ALLOW", "Clean Traffic."

# --- ASYNC HIGH-LOAD SIMULATION SUITE ---
async def main():
    # Instantiate WAF with 5 Requests-Per-Second threshold
    waf = AdvancedWAF(rps_threshold=5, cleanup_interval=2)
    
    print("[*] Deploying Enterprise Async WAF Engine...\n")
    
    # Test Case 1: Quadruple Obfuscation Bypass Attempt (Triple URL Encode + Comment Inline)
    # Payload: 1 UNION SELECT
    hardened_payload = "%252520U/**/NION/**/%252520S/**/ELECT"
    status, msg = await waf.inspect_request("10.0.0.99", hardened_payload)
    print(f"Test 1 (Deep Encoding Bypass Attempt):\n -> Status: {status}\n -> Action: {msg}\n")
    
    # Test Case 2: Asynchronous Volumetric DoS Attack Simulation (8 rapid hits)
    print("Test 2 (Simulating High-Speed Flood Attack - 8 concurrent requests)...")
    attacker_ip = "1.1.1.1"
    tasks = [waf.inspect_request(attacker_ip, f"/index.php?query={i}") for i in range(8)]
    results = await asyncio.gather(*tasks)
    
    for idx, (status, _) in enumerate(results):
        print(f"   Request {idx+1}: {status}")

if __name__ == "__main__":
    # Standard routine to execute async loop safely
    asyncio.run(main()) 

