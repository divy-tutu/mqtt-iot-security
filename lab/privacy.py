"""Bounded camera-channel shaping, not whole-network traffic-analysis immunity."""
import json
from security import compact

def pad_envelope(payload, size=1024):
    outer = json.loads(payload)
    outer['padding'] = ''
    missing = size - len(compact(outer).encode())
    if missing < 0:
        raise ValueError('camera envelope exceeds padding budget')
    outer['padding'] = ' ' * missing
    return compact(outer)

def camera_interval(motion, protected):
    return 0.5 if protected or motion else 2.0
