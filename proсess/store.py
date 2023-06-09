from pymemcache.client import base


class Store:
    def __init__(self, parameters: tuple, connect_attempts: int, timeout: int):
        self.client = base.Client(parameters, timeout=timeout)
        self.conn_attempts = connect_attempts

    def cache_get(self, key: str) -> float:
        i = 0
        while i < self.conn_attempts:
            try:
                value = self.client.get(key)
                return float(value)
            except (ConnectionRefusedError, TimeoutError):
                i += 1
            except (ValueError, TypeError):
                return None
        return None

    def cache_set(self, key: str, value, expire: int):
        i = 0
        while i < self.conn_attempts:
            try:
                self.client.set(key, value, expire)
                break
            except (ConnectionRefusedError, TimeoutError):
                i += 1

    def get(self, key: int) -> bytes:
        i = 0
        while i < self.conn_attempts:
            try:
                return self.client.get(key)
            except (ConnectionRefusedError, TimeoutError):
                i += 1
        raise ConnectionRefusedError
