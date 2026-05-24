import socket
from functools import lru_cache

@lru_cache(maxsize=5000)
def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"