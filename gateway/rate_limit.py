from __future__ import annotations

from collections import defaultdict, deque
import time


class TenantRateLimiter:
    def __init__(self, *, per_minute: int = 0, per_day: int = 0) -> None:
        self.per_minute = per_minute
        self.per_day = per_day
        self._minute: dict[str, deque[float]] = defaultdict(deque)
        self._day: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, tenant: str, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        if self.per_minute and not self._allow_window(self._minute[tenant], now, 60, self.per_minute):
            return False
        if self.per_day and not self._allow_window(self._day[tenant], now, 86_400, self.per_day):
            return False
        return True

    @staticmethod
    def _allow_window(values: deque[float], now: float, window: int, limit: int) -> bool:
        cutoff = now - window
        while values and values[0] <= cutoff:
            values.popleft()
        if len(values) >= limit:
            return False
        values.append(now)
        return True
