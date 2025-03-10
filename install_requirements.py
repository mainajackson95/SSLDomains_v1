import subprocess

# List of required dependencies
dependencies = ["pyOpenSSL", "requests", "urllib3", "ipaddress"]

print("[+] Installing dependencies...")

try:
    subprocess.run(["pip", "install"] + dependencies, check=True)
    print("[+] Installation complete.")
except subprocess.CalledProcessError as e:
    print(f"[!] Error installing dependencies: {e}")
