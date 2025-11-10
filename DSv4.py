import os
import time
import sys
import ssl
import socket
import re
import requests
import subprocess
import csv
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.support.ui import WebDriverWait
import pyshark
import tempfile
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
import json

CAPTURE_DURATION = 15                                                           # seconds
SSL_KEYLOGFILE = "sslkeys.log"                                                  # key log file
CSV_LOG_FILE = "tls_scan_log.csv"                                               # updated csv readable file for tls_results
BROWSER_NAME = "Chrome"                                                         # browser to be used
PCAP_FILE = "C:\\Users\\Andrew Beh\\OneDrive - UNSW\\Desktop\\Engineering Stuff\\Thesis\\Thesis C\\Extraction\\capture.pcapng"

# chrome packet capture environment
def setup_chrome_with_keylog():
        os.environ["SSLKEYLOGFILE"] = os.path.abspath(SSL_KEYLOGFILE)

        chrome_options = Options()
        chrome_options.add_argument(f"--ssl-key-log-file={os.path.abspath(SSL_KEYLOGFILE)}")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument("--disable-quic")                           # dont use quic
        chrome_options.add_argument("--disable-features=NetworkService,NetworkServiceInProcess,QUIC")
        chrome_options.add_argument("--disable-features=EnableQUIC")
        chrome_options.add_argument("--incognito")
        chrome_options.add_argument("--disable-features=EnableTLS13EarlyData,SSLSessionCache")
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--log-level=3")
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-gpu')

        # use unique temp user data directory for clean session (no resumption)
        user_data_dir = tempfile.mkdtemp()
        chrome_options.add_argument(f"--user-data-dir={user_data_dir}")

        driver = webdriver.Chrome(options=chrome_options)
        return driver


def map_tls_version(hex_version):
        mapping = {
                '0x0301': 'TLS 1.0',
                '0x0302': 'TLS 1.1',
                '0x0303': 'TLS 1.2',
                '0x0304': 'TLS 1.3',
        }
        return mapping.get(hex_version, 'Unknown')

# def is_site_https_via_http_check(domain, timeout=6):
#     """
#     Returns tuple (is_https_redirect, final_url, reason)
#     - is_https_redirect: True if accessing http://domain caused a redirect to https
#     - final_url: the URL returned after the HEAD/GET (may be same http://... or https://...)
#     - reason: human-friendly explanation
#     """
#     url = f"http://{domain}"
#     headers = {"User-Agent": "tls-scanner/1.0"}
#     try:
#         # Use HEAD first to avoid downloading large bodies; some servers don't honor HEAD -> fallback to GET
#         resp = requests.head(url, allow_redirects=True, timeout=timeout, headers=headers)
#         final = resp.url
#         # If final url scheme is https -> site uses HTTPS (redirected)
#         if final.lower().startswith("https://"):
#             return True, final, f"HTTP -> redirected to HTTPS (status {resp.status_code})"
#         # If we ended on http and got a normal status => stays HTTP
#         return False, final, f"HTTP responded (status {resp.status_code})"
#     except requests.RequestException as e:
#         # HEAD failed — try GET (some servers reject HEAD)
#         try:
#             resp = requests.get(url, allow_redirects=True, timeout=timeout, headers=headers)
#             final = resp.url
#             if final.lower().startswith("https://"):
#                 return True, final, f"HTTP GET -> redirected to HTTPS (status {resp.status_code})"
#             return False, final, f"HTTP GET responded (status {resp.status_code})"
#         except requests.RequestException as e2:
#             return None, None, f"HTTP probe failed: {e2}"

# --- insert this somewhere above your loop (no change to classify_scheme) ---
def is_site_https_via_classify(domain, timeout=6.0):
    """
    Wrapper to map classify_scheme() labels -> the expected
    True / False / None values used in your main loop.
    """
    try:
        result = classify_scheme(domain, timeout=timeout)
    except Exception as e:
        # network error, DNS failure, unexpected exception -> treat as probe failed
        # (your main currently treats None as 'probe failed or timed out')
        return None

    # Map labels to boolean/None
    if result == "http-only":
        return False
    # treat any case where HTTPS is available or TLS handshake succeeds as True
    if result in ("http-redirects-to-https", "https-only", "both-http-and-https", "tls-accepts-but-http-failed"):
        return True
    # if there's no service or unknown, return None so your existing 'probe failed' path handles it
    if result in ("no-service", "unknown"):
        return None

    # fallback: be conservative
    return None
# --- end wrapper ---

def classify_scheme(hostname, timeout=6.0):
    # Step 1: TLS handshake quick check
    def tls_ok(h):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((h, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=h):
                    return True
        except Exception:
            return False

    https_up = tls_ok(hostname)

    # Step 2: HTTP-level behaviour
    try:
        r_http = requests.head(f"http://{hostname}/", timeout=timeout, allow_redirects=True)
        http_reachable = True
    except requests.RequestException:
        r_http = None
        http_reachable = False

    try:
        r_https = requests.head(f"https://{hostname}/", timeout=timeout, allow_redirects=True, verify=False)
        https_reachable = True
    except requests.RequestException:
        r_https = None
        https_reachable = False

    # Inspect redirects and headers
    http_final = r_http.url if r_http is not None else None
    https_final = r_https.url if r_https is not None else None
    http_hsts = (r_http is not None) and ("strict-transport-security" in {k.lower():v for k,v in r_http.headers.items()})
    https_hsts = (r_https is not None) and ("strict-transport-security" in {k.lower():v for k,v in r_https.headers.items()})

    # Decision logic (order matters)
    if https_reachable and (http_reachable and http_final and http_final.startswith("https://")):
        return "http-redirects-to-https"
    if https_reachable and not http_reachable:
        return "https-only"
    if https_reachable and http_reachable and not (http_final and http_final.startswith("https://")):
        return "both-http-and-https"
    if http_reachable and not https_reachable and http_final and http_final.startswith("http://"):
        return "http-only"
    if https_up and not https_reachable:
        # TLS handshake ok but HTTP-level requests failed (e.g., server accepts TLS but blocks HEAD)
        return "tls-accepts-but-http-failed"
    if not https_up and not http_reachable:
        return "no-service"
    # fallback
    return "unknown"

# function to start capturing packets
def start_tshark_capture(ip=None):
        cmd = [
                "C:\\Program Files\\Wireshark\\tshark.exe",
                "-i", "\\Device\\NPF_{F8CDB05A-BC47-40C8-BF02-85CECB0EC6A6}",
                "-w", PCAP_FILE,
                "-f", f"host {ip}",
                "-a", f"duration:{CAPTURE_DURATION}"
        ]

        capture_filter = 'tcp port 443'
        print(f"[*] Starting capture with filter: {capture_filter}")
        cmd += ['-f', capture_filter]

        # print("[*] tshark command:\n", " ".join(cmd))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return proc

def domain_exists(domain):
        try:
                socket.gethostbyname(domain)
                return True
        except socket.gaierror:
                return False
        
def get_target_domains(base_domain):
        targets = []
        # if domain_exists(base_domain):
        #         targets.append(base_domain)
        if domain_exists(f"www.{base_domain}"):
                targets.append(f"www.{base_domain}")
        return targets

##
def parse_pkt(cap, target_domain):
        cap = pyshark.FileCapture('capture.pcapng', display_filter='tls', custom_parameters=['-o', 'tls.keylog_file:sslkeys.log'])

        # store multiple stream ids (if concurrent/multiple connections to same domain (tls1.2 + tls1.3))
        stream_ids = {}

        # might comment this out
        total_tls_info = []

        tls_ciphers = {
                # TLS 1.3
                0x1301: "TLS_AES_128_GCM_SHA256",
                4865:   "TLS_AES_128_GCM_SHA256",
                0x1302: "TLS_AES_256_GCM_SHA384",
                4866:   "TLS_AES_256_GCM_SHA384",
                0x1303: "TLS_CHACHA20_POLY1305_SHA256",
                4867:   "TLS_CHACHA20_POLY1305_SHA256",
                0x1304: "TLS_AES_128_CCM_SHA256",
                4868:   "TLS_AES_128_CCM_SHA256",
                0x1305: "TLS_AES_128_CCM_8_SHA256",
                4869:   "TLS_AES_128_CCM_8_SHA256",

                # TLS 1.2 (ECDHE)
                0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                49199:  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                49200:  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                49195:  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                49196:  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                49171:  "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                49172:  "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",

                # TLS 1.2 (RSA)
                0x009e: "TLS_RSA_WITH_AES_128_GCM_SHA256",
                158:    "TLS_RSA_WITH_AES_128_GCM_SHA256",
                0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256",
                60:     "TLS_RSA_WITH_AES_128_CBC_SHA256",
                0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
                47:     "TLS_RSA_WITH_AES_128_CBC_SHA",
                0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
                53:     "TLS_RSA_WITH_AES_256_CBC_SHA",

                # Post-Quantum experimental
                0x8a8a: "TLS_PQ_EXPERIMENTAL (e.g., x25519+mlkem768 or similar)",
                35466:  "TLS_PQ_EXPERIMENTAL (e.g., x25519+mlkem768 or similar)",

                # Add others if needed
        }

        # if no explicit server hello indicating key exchange, cipher_suite may contain the key exchange used
        kex_from_cipher = {
                0xc009: 'ECDHE_ECDSA',
                0xc00a: 'ECDHE_RSA',
                0xc030: 'ECDHE_RSA',
                0x009e: 'ECDHE_RSA',
                0xc02f: 'ECDHE_RSA'
                # Add more as needed
        }

        # ids for respective key exchange algorithms
        id_names = {
                1: 'sect163k1',
                2: 'sect163r1',
                3: 'sect163r2',
                4: 'sect193r1',
                5: 'sect193r2',
                6: 'sect233k1',
                7: 'sect233r1',
                8: 'sect239k1',
                9: 'sect283k1',
                10: 'sect283r1',
                11: 'sect409k1',
                12: 'sect409r1',
                13: 'sect571k1',
                14: 'sect571r1',
                15: 'secp160k1',
                16: 'secp160r1',
                17: 'secp160r2',
                18: 'secp192k1',
                19: 'secp192r1',
                20: 'secp224k1',
                21: 'secp224r1',
                22: 'secp256k1',
                23: 'secp256r1',
                24: 'secp384r1',
                25: 'secp521r1',
                26: 'brainpoolP256r1',
                27: 'brainpoolP384r1',
                28: 'brainpoolP512r1',
                29: 'x25519',
                30: 'x448',
                256: 'ffdhe2048',
                257: 'ffdhe3072',
                258: 'ffdhe4096',
                259: 'ffdhe6144',
                260: 'ffdhe8192',
                12089: 'x25519+mlkem512',
                12090: 'x25519+mlkem768',
                12091: 'x25519+mlkem1024'
        }

        # if variable already checked, change to True (prevents repeated loops)
        checked = False

        # Loop through packets
        for pkt in cap:
                if 'tls' in pkt:
                        try:
                        # Check if packet has an SNI and matches the target domain
                                sni = pkt.tls.handshake_extensions_server_name
                                if sni.lower() == target_domain.lower(): # or sni.lower() == target_domain.lower():            # uncomment if want explicit input
                                        stream_id = pkt.tcp.stream
                                        if stream_id not in stream_ids:                                                         # follow the tcp stream of packets to intended domain
                                                # print(f"[+] Found Client Hello with SNI {sni} in stream {stream_id}")
                                                stream_ids[stream_id] = sni                                                     # add multiple streams to list
                        except AttributeError:
                                continue  # If SNI not present, skip to next packet

        cap.close()

        if not stream_ids:                                                                                                      # stream_ids is TRUE if empty
                print("[!] No matching TLS Client Hello found.")
                return []

        # print(pkt.tls.field_names)

        for stream_id in stream_ids.keys():
                tls_info = {
                        "stream_id": stream_id,
                        "SNI": stream_ids[stream_id],
                        "TLS_Version": None,
                        "Cipher_Suite": None,
                        "Key_Exchange": None,
                        "Certificate_Info": None,
                        "Signature_Algorithm": None,
                        "Server_Signature_Algorithm": None,
                        "Key_Size": None,
                        "Public_Key_Algorithm": None,
                        "Valid_From": None,
                        "Valid_To": None
                }
                
                sni = stream_ids[stream_id]                                                                                     # sni cycles with each stream id
                # print(f"[*] Analysing stream {stream_id} ({sni})...")
                # using known stream of packets from domain, track them
                domain_pkts = pyshark.FileCapture('capture.pcapng', display_filter=f'tcp.stream == {stream_id}')

                cert_hexes = []

                # print(f"[DEBUG] Analysing stream {stream_id} for {sni}")                        #debug
                # pkt_count = 0                                                                   # debug
                # tls_count = 0                                                                   #debug

                for pkt in domain_pkts:
                        # pkt_count += 1
                        if 'tls' in pkt:
                                # tls_count += 1
                                try:
                                        if hasattr(pkt.tls, 'record_version'):
                                                tls_version = map_tls_version(pkt.tls.record_version)                                   # '0x0303' TLS 1.2, '0x0304' TLS 1.3
                                        elif hasattr(pkt.tls, 'handshake_version'):
                                                tls_version = map_tls_version(pkt.tls.handshake_version)
                                        else:
                                                tls_version = 'Unknown'

                                        # check ciphersuite for tls ver
                                        if hasattr(pkt.tls, 'handshake_ciphersuite'):
                                                cipher_suite = int(pkt.tls.handshake_ciphersuite, 16)
                                                tls13_ciphers = {0x1301, 0x1302, 0x1303, 0x1304, 0x1305, 0x1306}
                                                if cipher_suite in tls13_ciphers:
                                                        tls_version = 'TLS 1.3'

                                        hs_type = int(pkt.tls.handshake_type)                                                   # turns into an int to be used in the if statements

                                        cipher_suite = pkt.tls.handshake_ciphersuite
                                        cipher_suite_name = tls_ciphers.get(int(cipher_suite, 16), f"Unknown({cipher_suite})") 

                                                
                                        if hs_type == 2:                                                                        # CHECK DIFF BETWEEN KEY EXCHANGE AND KEY SHARE GROUP                                 
                                                key_exchange_group_id = getattr(pkt.tls, 'handshake_extensions_key_share_group', None)
                                                
                                                # if unable to find id in key_share_group heading, check for supported_groups heading (CAN ADD MORE IF MORE KNOWN)
                                                if key_exchange_group_id is None:
                                                        key_exchange_group_id = getattr(pkt.tls, 'handshake_extensions_supported_groups', None)

                                                if key_exchange_group_id is None:
                                                        key_exchange_group_id = 'N/A, check ciphersuite'

                                                # this is the crazy part
                                                if isinstance(key_exchange_group_id, list):
                                                        group_names = [id_names.get(int(gid), f'Unknown({gid})') for gid in key_exchange_group_id]
                                                        key_exchange_group = ', '.join(group_names)
                                                else:
                                                        try:
                                                                key_exchange_group = id_names.get(int(key_exchange_group_id), f'Unknown({key_exchange_group_id})')
                                                                if key_exchange_group == "Unknown(4588)":
                                                                        key_exchange_group = "x25519MLKEM768"
                                                        except (ValueError, TypeError):
                                                                key_exchange_group = f'Unknown({key_exchange_group_id})'

                                                # if no explicit key exchange found, check if in ciphersuite
                                                if key_exchange_group_id == 'N/A, check ciphersuite':
                                                        key_exchange_group = kex_from_cipher.get(int(cipher_suite, 16), 'Unknown')
                                                        tls_info["Key_Exchange"] = key_exchange_group
                                                        # print(f"{tls_version} Server Hello - Cipher Suite: {cipher_suite_name}, Key Exchange Algorithm: {key_exchange_group}")
                                                
                                                if hasattr(pkt.tls, 'handshake_certificate'):
                                                       cert_hexes.append(pkt.tls.handshake_certificate)

                                                tls_info["TLS_Version"] = tls_version
                                                tls_info["Cipher_Suite"] = cipher_suite_name
                                                tls_info["Key_Exchange"] = key_exchange_group
                                                tls_info["SNI"] = sni
                                                
                                except AttributeError:
                                        tls_version = 'Unknown'
                domain_pkts.close()

                # print(f"[DEBUG] Total packets in stream {stream_id}: {pkt_count}, TLS packets: {tls_count}")                        

                # If cert blobs found, try to parse certs and find matching one
                if cert_hexes:
                        print(f"[DEBUG] Number of certificates captured for {target_domain} (stream-level): {len(cert_hexes)}")
                        certs_der = []
                        for hexblob in cert_hexes:
                                clean_hex = re.sub(r'[^0-9A-Fa-f]', '', hexblob)
                                try:
                                        der_bytes = bytes.fromhex(clean_hex)
                                        certs_der.append(der_bytes)
                                except Exception:
                                        continue

                        certs = []
                        for der in certs_der:
                                try:
                                        certs.append(x509.load_der_x509_certificate(der, default_backend()))
                                except Exception:
                                        continue

                        # Find cert matching target domain
                        matched_cert = None
                        for cert in certs:
                                if domain_matches_cert(cert, target_domain):
                                        matched_cert = cert
                                        break

                        if matched_cert:
                                info = cert_to_dict(matched_cert)
                                tls_info["Certificate_Info"] = cert_summary_text(matched_cert)
                                tls_info["Signature_Algorithm"] = info["Signature_Algorithm"]
                                tls_info["Server_Signature_Algorithm"] = info.get("Server_Signature_Algorithm", info.get("Signature_Algorithm"))
                                tls_info["Key_Size"] = info["Key_Size"]
                                tls_info["Public_Key_Algorithm"] = info["Public_Key_Algorithm"]
                                tls_info["Valid_From"] = info["Valid_From"]
                                tls_info["Valid_To"] = info["Valid_To"]
                                tls_info["Issuer"] = info["Issuer"]           

                        else:
                                tls_info["Certificate_Info"] = f"No matching certificate found for domain {target_domain}"
                
                if any(tls_info.get(k) in [None, "Unavailable"] for k in ["TLS_Version", "Cipher_Suite", "Certificate_Info"]) and not checked:
                        checked = True
                        missing = [k for k in ["TLS_Version", "Cipher_Suite", "Certificate_Info"] if tls_info.get(k) in [None, "Unavailable"]]
                        print(f"[!] Missing info for {target_domain}: {missing}. Attempting OpenSSL fallback...")

                        openssl_info = openssl_fallback(target_domain)

                        if openssl_info:
                                for k, v in openssl_info.items():
                                        if tls_info.get(k) in [None, "Unavailable"] and v not in [None, "Unavailable"]:
                                                tls_info[k] = v
                                print(f"[+] Fallback TLS info retrieved via OpenSSL for {target_domain}")
                        else:
                                print(f"[!] OpenSSL TLS fallback failed for {target_domain}")


                        total_tls_info.append(tls_info)
                        continue

                total_tls_info.append(tls_info)
        return total_tls_info

##
def domain_matches_cert(cert, domain):
        domain = domain.lower()

        # Check CN (Common Name)
        try:
                cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value.lower()
                print(f"[DEBUG] CN: {cn}")  # 🔥 Debug print

                if (
                domain == cn or
                domain.endswith('.' + cn) or
                (cn.startswith('*.') and domain.endswith(cn[2:]))
                ):
                        print(f"[DEBUG] CN matches for domain {domain}")
                return True
        except IndexError:
                print("[DEBUG] No CN found")

        # Check SAN (Subject Alternative Names)
        try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_dns = san_ext.value.get_values_for_type(x509.DNSName)

                print(f"[DEBUG] SANs: {san_dns}")  # 🔥 Debug print

                for san in san_dns:
                        san = san.lower()
                        if (
                                domain == san or
                                domain.endswith('.' + san) or
                                (san.startswith('*.') and domain.endswith(san[2:]))
                        ):
                                print(f"[DEBUG] SAN matches for domain {domain}")
                                return True
        except x509.ExtensionNotFound:
                print("[DEBUG] No SAN found")

        print(f"[DEBUG] No match found for domain {domain}")
        return False

def openssl_fallback(domain):
        # tls_versions = ['-tls1_3', '-tls1_2', '']  # Try TLS 1.3, then 1.2, then default

        # for tls in tls_versions:
        try:
                cmd = [
                        "openssl", "s_client",
                        "-connect", f"{domain}:443",
                        "-servername", domain,
                        "-showcerts"
                ]
                # if tls:
                #         cmd.append(tls)

                result = subprocess.run(
                        cmd,
                        input="Q\n",
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=10,                                                     # change this if keep timing out
                        text=True
                )
                output = result.stdout + result.stderr

                # Basic TLS fields
                version = re.search(r"Protocol\s*:\s*(TLS[^\s]*)", output)
                cipher = re.search(r"Cipher\s*:\s*([^\n]+)", output)
                kx = re.search(r"Server Temp Key\s*:\s*([^\n]+)", output)

                # Fallback #1: sometimes OpenSSL uses “New, TLSv1.3, Cipher is …”
                if not version:
                        match = re.search(r"New,\s*(TLSv[^\s,]+)", output)
                        if match:
                                version = match

                if not cipher:
                        match = re.search(r"Cipher is\s*([^\s\n]+)", output)
                        if match:
                                cipher = match

                # (you already have a kx regex, but if you needed a fallback:)
                if not kx:
                        match = re.search(r"Server public key is.*?(\d+)\s*bit", output)
                        if match:
                                # this isn’t really the temp key, but at least tells you key size
                                kx = match

                # Find all certs in chain
                certs = re.findall(r"(-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----)", output, re.DOTALL)
                if certs:
                        # Parse the first certificate (leaf cert)
                        leaf_cert_pem = certs[0].encode()
                        cert_obj = x509.load_pem_x509_certificate(leaf_cert_pem, default_backend())

                        issuer = cert_obj.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                        key_obj = cert_obj.public_key()
                        pub_key = key_obj.__class__.__name__

                        # Extract Peer signature info from OpenSSL output
                        peer_sig_type = re.search(r"Peer signature type:\s*(\S+)", output)
                        peer_sig_digest = re.search(r"Peer signing digest:\s*(\S+)", output)

                        # Combine into a normalized string like "rsa_pss_sha256"
                        if peer_sig_type and peer_sig_digest:
                                server_signature = f"{peer_sig_type.group(1).lower()}_{peer_sig_digest.group(1).lower()}"
                        else:
                                server_signature = "Unavailable"


                        try:
                                key_size = key_obj.key_size
                        except Exception:
                                key_size = "Unavailable"

                        return {
                                "TLS_Version": version.group(1) if version else "Unavailable",
                                "Cipher_Suite": cipher.group(1) if cipher else "Unavailable",
                                "Key_Exchange": kx.group(1) if kx else "Unavailable",
                                "Issuer": issuer[0].value if issuer else "Unavailable",
                                "Valid_From": cert_obj.not_valid_before_utc.isoformat(),
                                "Valid_To": cert_obj.not_valid_after_utc.isoformat(),
                                "Certificate_Info": output.strip(),
                                "Public_Key_Algorithm": pub_key,
                                "Signature_Algorithm": cert_obj.signature_hash_algorithm.name if cert_obj.signature_hash_algorithm else "Unavailable",
                                "Server_Signature_Algorithm": server_signature,                                                 # from Peer signature type + digest
                                "Key_Size": key_size
                        }
                else:
                        return {
                                "TLS_Version": version.group(1) if version else "Unavailable",
                                "Cipher_Suite": cipher.group(1).strip() if cipher else "Unavailable",
                                "Key_Exchange": kx.group(1).strip() if kx else "Unavailable",
                                "Issuer": "Unavailable",
                                "Valid_From": "Unavailable",
                                "Valid_To": "Unavailable",
                                "Certificate_Info": output.strip(),
                                "Public_Key_Algorithm": "Unavailable",
                                "Signature_Algorithm": "Unavailable",
                                "Server_Signature_Algorithm": "Unavailable",
                                "Key_Size": "Unavailable"
                        }

        except subprocess.TimeoutExpired:
                print(f"[OpenSSL Fallback] Timeout when connecting to {domain}")
                # continue
        except Exception as e:
                print(f"[OpenSSL Fallback] Error parsing cert for {domain}: {e}")
                # continue

        print(f"[!] No TLS info could be retrieved for {domain}. All fallbacks failed.")
        return None

def get_server_signature_from_cert(cert):
        """Return normalized server signature like:
        rsa_pkcs1_sha256, rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256, ed25519, etc."""
        try:
                hash_alg = cert.signature_hash_algorithm.name.lower() if cert.signature_hash_algorithm else None
        except Exception:
                hash_alg = None

        pub = cert.public_key()
        pub_class = pub.__class__.__name__.lower()

        # RSA cases
        if isinstance(pub, rsa.RSAPublicKey):
                # Check whether the signature OID indicates PSS
                sig_oid_name = getattr(cert.signature_algorithm_oid, "_name", "") or str(cert.signature_algorithm_oid).lower()
                sig_oid_name = sig_oid_name.lower()
                if "pss" in sig_oid_name or "rsassa-pss" in sig_oid_name:
                        # most common: rsa_pss_rsae_sha*
                        if hash_alg:
                                return f"rsa_pss_rsae_{hash_alg}"
                        return "rsa_pss_rsae"
                else:
                # PKCS#1 v1.5
                        if hash_alg:
                                return f"rsa_pkcs1_{hash_alg}"
                        return "rsa_pkcs1"

        # ECDSA cases
        if isinstance(pub, ec.EllipticCurvePublicKey):
                curve_name = getattr(pub.curve, "name", None)
                if curve_name and hash_alg:
                # e.g., ecdsa_secp256r1_sha256
                        return f"ecdsa_{curve_name}_{hash_alg}"
                elif curve_name:
                        return f"ecdsa_{curve_name}"
                elif hash_alg:
                        return f"ecdsa_{hash_alg}"

        # EdDSA (ed25519, ed448)
        if pub_class.startswith("ed"):
                # ed25519 / ed448 — they are usually self-describing (no hash suffix)
                return pub_class

        # fallback: combine signature OID and hash if available
        if hash_alg:
                return hash_alg
        return "unavailable"



def cert_to_dict(cert):

        try:
                issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except IndexError:
                issuer = "Unavailable"

        server_sig = get_server_signature_from_cert(cert)
        sig_algo = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid)
        key_size = getattr(cert.public_key(), 'key_size', 'Unavailable')
        valid_from = cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S')
        valid_to = cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S')
        pubkey_algo = cert.public_key().__class__.__name__

        return {
                'Signature_Algorithm': sig_algo,
                'Server_Signature_Algorithm': server_sig, 
                'Key_Size': f"{key_size} bits" if key_size != 'Unavailable' else key_size,
                'Public_Key_Algorithm': pubkey_algo,
                'Valid_From': valid_from,
                'Valid_To': valid_to,
                'Issuer': issuer
        }


def cert_summary_text(cert):
        info = cert_to_dict(cert)

        lines = [
                "=== Certificate ===",
                f"Issuer: {info.get('Issuer', 'Unavailable')}",
                f"Signature Algorithm: {info.get('Signature_Algorithm', 'Unavailable')}",
                f"Public Key Algorithm: {info.get('Public_Key_Algorithm', 'Unavailable')}",
                f"Key Size: {info.get('Key_Size', 'Unavailable')}",
                f"Valid From: {info.get('Valid_From', 'Unavailable')}",
                f"Valid To: {info.get('Valid_To', 'Unavailable')}",
        ]
        return "\n".join(lines)



##
## old write report func to text file
def cert_report(cert_text, filename="cert_report.txt"):
        cert_text = cert_text or "No certificate info"
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"=== Certificate Report ===\n")
                f.write(f"Generated on: {timestamp}\n\n")
                f.write(cert_text.strip() + "\n")

        print(f"[+] Report saved to {os.path.abspath(filename)}")

def main():
        csv_input = input("Enter input file name with domain list (e.g., domains.csv): ").strip()
        timestamp = datetime.now().strftime('%Y-%m-%d %H-%M-%S')
        output_file = f"encryption_report_{timestamp}.csv"

        try:
                with open(csv_input, 'r', encoding='utf-8-sig') as file:
                        ext = os.path.splitext(csv_input)[-1].lower()

                        if ext != '.csv':
                                print(f"[!] Unsupported file format: {ext}")
                                return

                        # Read all rows first (preserves first row so we can detect header)
                        reader = csv.reader(file)
                        rows = [r for r in reader if r and any(cell.strip() for cell in r)]  # drop empty/blank rows

                        if not rows:
                                print(f"[!] CSV '{csv_input}' contains no data.")
                                return

                        # Heuristic: detect header row (if any cell contains 'domain'/'org'/'site' etc or starts with '#')
                        first_row = [c.strip().lower() for c in rows[0]]
                        header_like_tokens = {'domain', 'org', 'organisation', 'site', 'host', 'url', 'name'}
                        is_header = False
                        for cell in first_row:
                                if not cell:
                                        continue
                                if cell.startswith('#'):
                                        is_header = True
                                        break
                        # if any token is contained in the cell, treat as header
                                if any(tok in cell for tok in header_like_tokens):
                                        is_header = True
                                        break

                        # If header-like, drop it
                        if is_header:
                                data_rows = rows[1:]
                                print("[*] Detected header row and skipped it.")
                        else:
                                data_rows = rows

                        domain_entries = []
                        for row in data_rows:
                        # normalize and strip each cell
                                cells = [c.strip() for c in row]
                                if len(cells) >= 2:
                                        inst = cells[0] or "Unknown"
                                        dom = cells[1]
                                else:
                                        inst = "Unknown"
                                        dom = cells[0]

                                # discard empty domain strings
                                if not dom or not dom.strip():
                                        continue

                                domain_entries.append((inst, dom.strip()))

        except FileNotFoundError:
                print(f"[!] File '{csv_input}' not found.")
                return

        print(f"[*] Found {len(domain_entries)} domains to scan:")
        # for inst, dom in domain_entries:
        #         # use repr to show hidden chars if present
        #         print(f"    INST: {repr(inst)}  DOMAIN: {repr(dom)}")


        # Prepare output file with headers
        with open(output_file, 'w', newline='') as out_csv:
                writer = csv.writer(out_csv)
                writer.writerow([
                        'Org_Name', 'Domain', 'TLS_Version', 'Cipher_Suite', 'Key_Exchange', 'Issuer',
                        'Signature_Algorithm', 'Server_Signature_Algorithm', 'Key_Size', 'Public_Key_Algorithm', 'Valid_From', 'Valid_To'
                ])

                for inst_name, domain in domain_entries:
                        if not domain or not domain.strip():
                                print(f"[!] No domain found for {inst_name}. Skipping...")
                                writer.writerow([inst_name, 'N/A'] + ['N/A'] * 10)
                                continue
                        
                        base_domain = domain.lower()
                        targets = get_target_domains(domain)

                        
                        if not targets:
                                print(f"[!] Domain {base_domain} not found (neither www nor base). Skipping...")
                                writer.writerow([inst_name, domain] + ['N/A'] * 10)
                                continue

                        for domain_to_match in targets:  # ✅ loop through both domain.com and www.domain.com
                                print(f"\n==== Scanning {domain_to_match} ====")

                                is_https = is_site_https_via_classify(domain_to_match)

                                if is_https is False:
                                        print(f"[HTTP CHECK] {domain_to_match} is HTTP-only → marking UNSECURE and skipping TLS capture.")
                                        writer.writerow([inst_name, domain_to_match, "UNSECURE_HTTP"] + ["N/A"] * 9)
                                        continue  # skip to next domain

                                elif is_https is None:
                                        print(f"[HTTP CHECK] {domain_to_match}: probe failed or timed out — proceeding cautiously.")
                                        writer.writerow([inst_name, domain_to_match, "UNSECURE_HTTP"] + ["N/A"] * 9)

                                        # You can choose to skip or continue
                                        continue  # optional: skip uncertain ones

                                # If we reach here, site redirected to HTTPS → proceed normally
                                print(f"[HTTP CHECK] {domain_to_match} redirected to HTTPS → proceeding with capture.")

                                driver = setup_chrome_with_keylog()
                                tshark_proc = start_tshark_capture()

                                time.sleep(3)  # Allow tshark to start

                                try:
                                        driver.get(f"https://{domain_to_match}/about")
                                        WebDriverWait(driver, 10).until(lambda d: d.execute_script('return document.readyState') == 'complete')
                                except Exception as e:
                                        print(f"[!] Error loading {domain_to_match}: {e}")
                                finally:
                                        driver.quit()
                                # time.sleep(10)

                                tshark_proc.wait()
                                stdout, stderr = tshark_proc.communicate()
                                if stderr:
                                        print("[!] tshark stderr:\n", stderr.decode())

                                tls_info = parse_pkt(PCAP_FILE, domain_to_match)
                                first_tls = None
                                if tls_info and isinstance(tls_info, list) and len(tls_info) > 0:
                                        first_tls = tls_info[0]
                                        # print(first_tls)

                                # Fallback if TLS info is missing (optional step)
                                # if not first_tls or not first_tls.get('TLS_Version'):
                                #         print(f"[!] TLS info missing for {domain_to_match}, using OpenSSL fallback...")
                                #         first_tls = openssl_fallback(domain_to_match)  # <-- You must define this function

                                if not first_tls:
                                        print(f"[!] No TLS info could be retrieved for {domain_to_match}. Skipping...")
                                        writer.writerow([inst_name, domain_to_match] + ['N/A'] * 10)
                                        continue # skip to next domain
                                else:
                                        cert_info = first_tls.get('Certificate_Info')
                                        
                                        ## uncomment below to get cert printed
                                        # if cert_info and isinstance(cert_info, str) and cert_info.strip():
                                        #         cert_report_filename = f"cert_report_{domain_to_match.replace('.', '_')}_{timestamp}.txt"
                                        #         cert_report(first_tls.get('Certificate_Info', 'No certificate info'), cert_report_filename)
                                        # else:
                                        #         print(f"[!] No certificate info for {domain_to_match}, skipping text report.")

                                        writer.writerow([
                                                inst_name,
                                                domain_to_match,
                                                first_tls.get('TLS_Version', 'N/A'),
                                                first_tls.get('Cipher_Suite', 'N/A'),
                                                first_tls.get('Key_Exchange', 'N/A'),
                                                first_tls.get('Issuer', 'N/A'),
                                                first_tls.get('Signature_Algorithm', 'N/A'),
                                                first_tls.get('Server_Signature_Algorithm', 'N/A'),
                                                first_tls.get('Key_Size', 'N/A'),
                                                first_tls.get('Public_Key_Algorithm', 'N/A'),
                                                first_tls.get('Valid_From', 'N/A'),
                                                first_tls.get('Valid_To', 'N/A')
                                        ])


        print(f"\n[*] All domains scanned. Report saved to {output_file}.")



if __name__ == "__main__":
    main()
