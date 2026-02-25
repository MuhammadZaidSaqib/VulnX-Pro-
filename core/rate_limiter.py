import time
from config import RATE_LIMIT_DELAY

def apply_rate_limit():
    time.sleep(RATE_LIMIT_DELAY)