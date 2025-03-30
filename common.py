import json
import os
from typing import Optional, Union

DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 5000

def encode_packet(data) -> bytes:
    return json.dumps(data).encode()

def decode_packet(packet: bytes) -> Optional[Union[dict, list]]:
    try:
        data = json.loads(packet.decode())
        return data
    except json.JSONDecodeError:
        return None
    
def write_file(path, data):
    """Writes data to a JSON file safely."""
    try:
        with open(path, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Error writing to file {path}: {e}")

def read_file(path, default_value={}):
    """Reads data from a JSON file. If the file doesn't exist, creates it with a default value."""
    if not os.path.exists(path):
        write_file(path, default_value)  # Create file with default value
        return default_value

    try:
        with open(path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Error reading file {path}: {e}")
        return default_value  # Return default if file is corrupt

