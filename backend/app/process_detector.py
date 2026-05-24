import psutil
import time

PORT_PROCESS_CACHE = {}
LAST_REFRESH = 0
REFRESH_INTERVAL = 5  # seconds


def refresh_process_cache():
    global PORT_PROCESS_CACHE, LAST_REFRESH

    now = time.time()

    if now - LAST_REFRESH < REFRESH_INTERVAL:
        return

    temp_cache = {}

    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr and conn.pid:
                try:
                    process_name = psutil.Process(conn.pid).name()
                    temp_cache[conn.laddr.port] = process_name
                except:
                    pass

        PORT_PROCESS_CACHE = temp_cache
        LAST_REFRESH = now

    except:
        pass


def get_process_from_port(port):
    refresh_process_cache()
    return PORT_PROCESS_CACHE.get(port, "Unknown")