import os
import json
import random
import hashlib
import ecdsa
import base58

# Puzzle #69 keyspace
START_HEX = "10000000000000000000000000"
END_HEX   = "1fffffffffffffffffffffffff"
START_INT = int(START_HEX, 16)
END_INT   = int(END_HEX, 16)
KEYSPACE_SIZE = END_INT - START_INT

# Config
PROGRESS_FILE = "progress.json"
TARGET_PREFIX = "19vk"
TARGET_ADDRESS = "19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG"
CHUNK_PERCENT = 0.1
CHUNK_SIZE = int(KEYSPACE_SIZE * (CHUNK_PERCENT / 100))
ATTEMPTS_PER_RUN = 100000
REQUIRED_MATCHES_PER_CHUNK = 5

def save_progress(chunk_index):
    with open(PROGRESS_FILE, "w") as f:
        json.dump({"chunk_index": chunk_index}, f)

def load_progress():
    if os.path.exists(PROGRESS_FILE):
        with open(PROGRESS_FILE, "r") as f:
            data = json.load(f)
            return data.get("chunk_index", 1)  # Start from 30.1% => index 301
    return 301

def private_key_to_address(private_key_hex):
    private_key_bytes = bytes.fromhex(private_key_hex)
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    public_key_bytes = b'\x04' + vk.to_string()
    sha256_bpk = hashlib.sha256(public_key_bytes).digest()
    ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
    network_byte = b'\x00' + ripemd160_bpk
    checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
    address = base58.b58encode(network_byte + checksum)
    return address.decode()

def scan_chunk(start, end):
    rng = random.Random(start)
    match_count = 0
    attempts = 0

    while True:
        private_key_int = rng.randint(start, end)
        private_key_hex = f"{private_key_int:064x}"
        address = private_key_to_address(private_key_hex)
        attempts += 1

        if address.startswith(TARGET_PREFIX):
            match_count += 1
            print(f"[MATCH] {address} — Private Key: {private_key_hex}")

        if address == TARGET_ADDRESS:
            print(f"🎯 FOUND TARGET: {address} — Private Key: {private_key_hex}")
            return True

        if match_count >= REQUIRED_MATCHES_PER_CHUNK:
            print(f"✅ Found {match_count} matches. Moving to next chunk.")
            return False

        if attempts % ATTEMPTS_PER_RUN == 0:
            print(f"⏳ Attempts: {attempts} — Matches: {match_count}")

def main():
    chunk_index = load_progress()

    while True:
        percent_start = round(chunk_index * CHUNK_PERCENT, 4)
        percent_end = round((chunk_index + 1) * CHUNK_PERCENT, 4)

        start = START_INT + int(chunk_index * CHUNK_SIZE)
        end = min(start + CHUNK_SIZE, END_INT)

        print(f"\n🔁 Scanning chunk {percent_start:.4f}%–{percent_end:.4f}% of Puzzle #69")
        print(f"📦 Range: 0x{start:x} – 0x{end:x}")

        found = scan_chunk(start, end)
        if found:
            break

        chunk_index += 1
        save_progress(chunk_index)

        if start >= END_INT:
            print("✅ Finished scanning 100% of Puzzle #69. Target not found.")
            break

if __name__ == "__main__":
    main()
