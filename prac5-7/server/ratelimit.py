import time
from typing import Dict, Tuple

# Простий rate-limit: фіксоване вікно 60с, N спроб логіну на IP/логін, та глобальний RPS ліміт для echo
class RateLimiter:
    def __init__(self, login_limit=5, win=60, echo_rps=50):
        self.login_limit = login_limit
        self.win = win
        self.echo_rps = echo_rps
        self.login_attempts: Dict[Tuple[str,str], Tuple[int,int]] = {}
        self.echo_counts: Dict[int,int] = {}

    def allow_login(self, ip: str, username: str) -> bool:
        now = int(time.time())
        key = (ip, username)
        count, ts = self.login_attempts.get(key, (0, now))
        if now - ts >= self.win:
            count, ts = 0, now
        count += 1
        self.login_attempts[key] = (count, ts)
        return count <= self.login_limit

    def allow_echo(self) -> bool:
        sec = int(time.time())
        count = self.echo_counts.get(sec, 0) + 1
        self.echo_counts[sec] = count
        return count <= self.echo_rps
