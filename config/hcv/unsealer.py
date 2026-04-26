import os
import time
import requests

VAULT_URL = os.getenv("VAULT_ADDR", "http://vault:8200")
KEYS = [
    os.getenv("VAULT_KEY1"),
    os.getenv("VAULT_KEY2"),
    os.getenv("VAULT_KEY3")
]

def run_watchdog():
    print(f"Monitoring Vault at {VAULT_URL}...")
    while True:
        try:
            r = requests.get(f"{VAULT_URL}/v1/sys/seal-status")
            if r.status_code == 200 and r.json().get("sealed"):
                print("Vault is sealed. Unsealing...")
                for key in KEYS:
                    if key:
                        requests.put(f"{VAULT_URL}/v1/sys/unseal", json={"key": key})

        except Exception as e:
            print(f"Waiting for Vault to be reachable... {e}")

        time.sleep(60)

if __name__ == "__main__":
    run_watchdog()