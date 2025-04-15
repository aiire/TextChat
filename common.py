import json
import os
from typing import Optional, Union, Any
import hashlib

DEFAULT_HOST = "localhost"
DEFAULT_PORT = 5000

MAX_NICKNAME_LENGTH = 24

def encode_packet(data) -> bytes:
    return json.dumps(data).encode()

def decode_packet(packet: bytes) -> Optional[Union[dict, list]]:
    try:
        data = json.loads(packet.decode())
        return data
    except json.JSONDecodeError:
        return None

def write_file(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Error writing to file {path}: {e}")

def read_file(path, default_value={}) -> Union[dict, list]:
    if not os.path.exists(path):
        write_file(path, default_value)
        return default_value

    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Error reading file {path}: {e}")
        return default_value


def generate_id(*values: Any, separator=":", hash_length=16):
    raw_string = separator.join(str(value) for value in values)
    hash_object = hashlib.sha256(raw_string.encode())
    return hash_object.hexdigest()[:hash_length]
