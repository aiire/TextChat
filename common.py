import json
import os
from typing import Optional, Union

DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 5000

# Encodes data into a JSON object and encodes it into raw bytes
# to be sent through a network stream
def encode_packet(data) -> bytes:
    return json.dumps(data).encode()

# Decodes bytes of data sent over a network into a Python data structure
def decode_packet(packet: bytes) -> Optional[Union[dict, list]]:
    try:
        data = json.loads(packet.decode())
        return data
    except json.JSONDecodeError:
        return None

# Writes data to a JSON file safely.
def write_file(path, data):
    try:
        with open(path, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Error writing to file {path}: {e}")

# Reads data from a JSON file. If the file doesn't exist, creates it with a default value
def read_file(path, default_value={}):
    if not os.path.exists(path):
        write_file(path, default_value)  # Create file with default value
        return default_value

    try:
        with open(path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Error reading file {path}: {e}")
        return default_value  # Return default if file is corrupt

