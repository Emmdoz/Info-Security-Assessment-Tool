import os
import glob
import pandas as pd
import json
import requests
from datetime import datetime, timezone
import re
import glob
import math

## global
CIPHER_CACHE_FILE = "cipher_lookup_cache.json"
csv_file = "tls-parameters-8.csv"

# for weighting scores
# Component lists
encryption_components = ["TLS_Score", "Cipher_Score", "KeyExchange_Score"]
auth_components = ["Signature_Score", "CertValidity_Score", "Issuer_Score"]

# ----------------------------
## Helpers
# ----------------------------
## normalizer

def normalize(name: str) -> str:
        if not isinstance(name, str):                                   # handles NaN or floats
                return ""
        s = name.lower().replace("-", "_").replace(" ", "_")
        s = re.sub(r"_+", "_", s)                                       # collapse multiple underscores
        return s


# # Max scores (adjust KeyExchange max if weighted differently)
# ENCRYPTION_MAX = 5 + 5 + 5                                              # TLS + Cipher + KEX (weighted max)                                                     + KeySize
# AUTH_MAX = 5 + 5 + 5                                           # Signature + Validity + Issuer


def scale_to_1_5(raw, raw_min, raw_max, equal_bins=False):
    """
    Scale a raw total into 1–5 range.
    If equal_bins=True, use fixed-width bins (1–1.8, 1.8–2.6, etc.).
    Otherwise, use normal rounding.
    """
    if raw_max <= raw_min:
        return 1  # conservative fallback

    scaled = 1 + (raw - raw_min) * 4.0 / (raw_max - raw_min)
    scaled = max(1.0, min(5.0, scaled))  # clamp to [1,5]

    if not equal_bins:
        # 🔹 Normal rounding (your current method)
        scaled_rounded = int(round(scaled))
        return max(1, min(5, scaled_rounded))
    else:
        # 🔹 Equal-chance bins you described
        if scaled < 1.8:
            return 1
        elif scaled < 2.6:
            return 2
        elif scaled < 3.4:
            return 3
        elif scaled < 4.2:
            return 4
        else:
            return 5

def colour_from_score(score):
    """Map integer 1–5 score to colour."""
    if score == 5:
        return "green"
    elif score == 4:
        return "yellow"
    elif score == 3:
        return "orange"
    elif score == 2:
        return "red"
    else:
        return "black"

def robust_read_csv(path):
    encodings = ['utf-8', 'utf-8-sig', 'cp1252', 'latin-1']
    last_exc = None
    for enc in encodings:
        try:
            # engine='python' is a bit more tolerant; change on_bad_lines as needed
            return pd.read_csv(path, encoding=enc, engine='python', on_bad_lines='warn')
        except Exception as e:
            last_exc = e
    # if we get here, none worked
    raise last_exc

def compute_totals(row, scoring_method, individual_weights, alpha):
    if scoring_method == "basic":
        # simple sum
        enc_total = sum(row[c] for c in encryption_components)
        auth_total = sum(row[c] for c in auth_components)
        overall = enc_total + auth_total

    elif scoring_method == "group":
        # sum each group
        enc_total = sum(row[c] for c in encryption_components)
        auth_total = sum(row[c] for c in auth_components)
        # weighted by alpha
        overall = alpha * enc_total + (1 - alpha) * auth_total

    elif scoring_method == "individual":
        # weighted sum per attribute
        overall = 0
        enc_total = 0
        auth_total = 0
        for c in encryption_components:
            w = individual_weights.get(c, 1.0)
            enc_total += row[c] * w
            overall += row[c] * w
        for c in auth_components:
            w = individual_weights.get(c, 1.0)
            auth_total += row[c] * w
            overall += row[c] * w
    else:
        raise ValueError(f"Unknown scoring method: {scoring_method}")

    return pd.Series({
        "Encryption_Total": enc_total,
        "Auth_Total": auth_total,
        "Overall_Score": overall
    })


# ----------------------------
# Dictionaries for scoring
# ----------------------------

# -----------------------------
## TLS + Scoring
# -----------------------------

## TLS VERSION
TLS_VERSION_SCORES = {
        "tls_1.3": 5,
        "tls_1.2": 4,
        "tls_1.1": 2,
        "tls_1.0": 1,
}

def score_tls_version(version: str) -> int:
        if version is None or pd.isna(version):
        # optional debug:
        # print("[DEBUG] score_tls_version: received missing value")
                return 1
        
        # treat "unsecure", "none", "na", "n/a" etc. as lowest score
        if any(x in version for x in ["unsecure", "none", "n/a", "na"]):
                return 1

        version = normalize(version)
        # print(f"[DEBUG] TLS version input (normalized): '{version}'")                         # debug
        version = version.replace("tlsv", "tls_")                                               # e.g. TLSv1.2 → tls_1.2
        for key, score in TLS_VERSION_SCORES.items():
                if key in version:
                        # print(f"[DEBUG] Matched key '{key}' → score {score}")                 # debug
                        return score
        return 1

# -----------------------------
## CIPHERSUITE + Scoring
# -----------------------------
CIPHER_CATEGORY_SCORES = {
        "insecure": 1,
        "weak": 2,
        "secure": 4,
        "recommended": 5
}

SECURITY_LEVELS = ["recommended", "secure", "weak", "insecure"]

def load_cipher_lookup(force_refresh=False):
        """Load cipher lookup from cache if available, otherwise fetch from API and save."""
        if not force_refresh and os.path.exists(CIPHER_CACHE_FILE):
                with open(CIPHER_CACHE_FILE, "r") as f:
                        print(f"Loading cipher lookup from cache: {CIPHER_CACHE_FILE}")
                        return json.load(f)
        
        print("Fetching cipher lookup from ciphersuite.info API...")
        cipher_lookup = {}
        for level in SECURITY_LEVELS:
                url = f"https://ciphersuite.info/api/cs/security/{level}"
                try:
                        response = requests.get(url)
                        response.raise_for_status()
                        ciphers = response.json()

                        ## debug
                        # print(f"\n--- Raw response for {level} ---")
                        # print(response.text[:500])  # print first 500 chars of the response

                        # ciphers = response.json()
                        # print(f"Parsed {len(ciphers)} ciphers for {level}")
                        
                        for entry in ciphers.get("ciphersuites", []):
                                # each entry is typically a single-key dict: { "IANA_NAME": { ... } }
                                for cs_key, cs in entry.items():
                                        # candidate_names: include the IANA key (cs_key) plus any string fields found in cs
                                        candidate_names = set()
                                        if cs_key:
                                                candidate_names.add(str(cs_key))

                                        # if cs is a dict, gather any string-valued fields or strings inside lists
                                        if isinstance(cs, dict):
                                                for val in cs.values():
                                                        if isinstance(val, str) and val.strip():
                                                                candidate_names.add(val)
                                                        elif isinstance(val, (list, tuple)):
                                                                for item in val:
                                                                        if isinstance(item, str) and item.strip():
                                                                                candidate_names.add(item)

                                        # fallback: if nothing found, still index the cs_key
                                        if not candidate_names and cs_key:
                                                candidate_names.add(str(cs_key))

                                        # normalise and save each candidate variant into cipher_lookup
                                        for raw_name in candidate_names:
                                                n = raw_name.strip().lower().replace("-", "_")
                                                # store multiple simple variants so lookups are resilient:
                                                variants = {
                                                        n,                       # normalized (underscores)
                                                        n.replace("_", ""),      # no underscores
                                                        re.sub(r"^tls_", "", n), # strip leading tls_
                                                        re.sub(r"_?with_?", "_", n),       # collapse 'with' variations
                                                        re.sub(r"_sha\d+$", "", n),        # strip trailing _shaNNN
                                                }
                                                for v in variants:
                                                        if v:  # keep first-seen category for this variant
                                                                cipher_lookup.setdefault(v, level)


                except Exception as e:
                        print(f"Failed to fetch {level}: {e}")
        # Save to cache
        with open(CIPHER_CACHE_FILE, "w") as f:
                json.dump(cipher_lookup, f)
        print(f"Cipher lookup saved to cache: {CIPHER_CACHE_FILE}")
        return cipher_lookup

# Load cipher lookup (from cache if available, otherwise fetch from API)
cipher_lookup = load_cipher_lookup()

def score_cipher_suite(cipher: str) -> int:
        # Handle None, NaN, empty, or n/a
        if cipher is None or (isinstance(cipher, float) and math.isnan(cipher)) or str(cipher).strip().lower() in ("", "n/a"):
                return 1  # lowest score
        
        normalized = normalize(cipher)

        # print(f"Input cipher: {cipher}")
        # print(f"Normalized: {normalized}")

        normalized_lookup = normalized.replace("_", "")   # strip all underscores temporarily
        # Also strip underscores from JSON keys for matching
        cache_lookup = {k.replace("_", ""): v for k, v in cipher_lookup.items()}
        
        category = cache_lookup.get(normalized_lookup)
        # print(f"Category after first lookup: {category}")

        if category is None:
                norm_more = normalized.replace("tls_", "").replace("_with_", "_")
                norm_more = norm_more.replace("_", "")
                # print(f"Normalized fallback: {norm_more}")
                category = cache_lookup.get(norm_more, "insecure")  # default insecure
                # print(f"Category after fallback lookup: {category}")

        score = CIPHER_CATEGORY_SCORES.get(category, 0)
        # print(f"Final score: {score}\n")
        return score

# -----------------------------
## KEX + Scoring
# -----------------------------
def categorize_kex(name):
        if not name or pd.isna(name):
                return "Unsecured"
        name_lower = name.lower()

        if "kyber" in name_lower or "frodokem" in name_lower or "pqc" in name_lower:
                return "PQC"

        if "mlkem" in name_lower:
                return "Hybrid"
        
        elif "x25519" in name_lower or "secp" in name_lower or "sect" in name_lower or "ecdhe" in name_lower or "dhe" in name_lower or "ecdh" in name_lower:
                return "Classical"
        # Add additional PQC detection if you have pure PQC names
        return "Classical"  # default fallback

def build_kex_dict(df):

        # Apply category
        df['Category'] = df['Description'].apply(categorize_kex)


       # Map Recommended to a small bonus; DTLS removed from scoring
        recommended_map = {'D': 0, 'N': 0, 'Y': 1}
        df['RecommendedScore'] = df['Recommended'].map(recommended_map).fillna(0)

        # Map Category to base score on 1..4 (final score will be capped to 1..5)
        category_map = {'Unsecured': 1, 'Classical': 2, 'Hybrid': 3, 'PQC': 4}
        df['CategoryScore'] = df['Category'].map(category_map).fillna(1)


        # Build dictionary
        # Key: KEX Name, Value: dict of attributes
        kex_dict = {}
        for _, row in df.iterrows():
                kex_key = normalize(row['Description'])
                kex_dict[kex_key] = {
                        'Category': row['Category'],
                        'CategoryScore': row['CategoryScore'],
                        'Recommended': row['Recommended'],
                        'RecommendedScore': row['RecommendedScore']
                }
        return kex_dict

def score_kex(kx: str) -> int:
        if not kx or pd.isna(kx):
                return 1

        key = normalize(kx)
        key = re.sub(r"[\s,(\[]*\d+\s*-?\s*bits?\)?\]?", "", key, flags=re.IGNORECASE).strip("_huh")

        entry = kex_dict.get(key)
        if entry:
                base = int(entry.get("CategoryScore", 1))
                rec = int(entry.get("RecommendedScore", 0))
                return max(1, min(5, base + rec))

        category = categorize_kex(key)
        fallback_map = {'Unsecured': 1, 'Classical': 2, 'Hybrid': 3, 'PQC': 4}
        return fallback_map.get(category, 1)


## define KEX dict globally
kex_df = pd.read_csv("tls-parameters-8.csv")        # tls-parameters-8.csv
kex_dict = build_kex_dict(kex_df)                   # returns the lookup dictionary


# -----------------------------
## SIGNATURE ALGORITHM
# -----------------------------

def build_sig_dict(df):
         # Map Recommended column to numeric scores
        recommended_map = {'D': 1, 'N': 2, 'Y': 3}

        df['RecommendedScore'] = df['Recommended'].map(recommended_map).fillna(0)

        sig_dict = {}
        for _, row in df.iterrows():
                sig_key = normalize(row['Description'])
                sig_dict[sig_key] = {
                'Description': row['Description'],
                'Recommended': row['Recommended'],
                'RecommendedScore': row['RecommendedScore']
                }
        return sig_dict

def fuzzy_signature_match(server_norm: str) -> str:
        """Return the best matching DB key for a given normalized server signature."""
        if not server_norm:
                return None

        server_parts = set(server_norm.split("_"))
        best_score = -1
        best_key = None

        for key, entry in sig_dict.items():
                key_norm = normalize(key)
                key_parts = set(key_norm.split("_"))

                # count overlapping components
                match_count = len(server_parts & key_parts)

                if match_count > best_score:
                        best_score = match_count
                        best_key = key
                elif match_count == best_score:
                # tie-breaker: higher recommended score
                        if entry.get("RecommendedScore", 0) > sig_dict[best_key].get("RecommendedScore", 0):
                                best_key = key

        return best_key


def score_signature_algo(sig: str, pubkey: str = None, server_sig: str = None) -> int:
        if not sig or pd.isna(sig):
                return 1

        sig_norm = normalize(sig)
        server_norm = normalize(server_sig) if server_sig and not pd.isna(server_sig) else ""
        pubkey_norm = normalize(pubkey) if pubkey and not pd.isna(pubkey) else ""

        # --- NEW: if any of the fields contains "mldsa" (case-insensitive), treat as PQC top score 5
        if ("mldsa" in sig_norm) or ("mldsa" in server_norm) or ("mldsa" in pubkey_norm):
                return 5

        # 1) Prefer exact server-level token (if provided).
        if server_norm:
                entry = sig_dict.get(server_norm)
                if entry:
                        return entry.get("RecommendedScore", 1)

        # 2) Try exact lookup of the cert-level signature token (sig_norm) as-is.
        entry = sig_dict.get(sig_norm)
        if entry:
                return entry.get("RecommendedScore", 1)

        # 3) Fuzzy fallback using components
        best_key = fuzzy_signature_match(server_norm or sig_norm)
        if best_key:
                return sig_dict[best_key].get("RecommendedScore", 1)

        # 4) Nothing found -> conservative fallback (lowest non-zero score)
        return 1


        # # Handle special case: RSA + SHA combos
        # if pubkey and not pd.isna(pubkey):
        #         pubkey_norm = normalize(pubkey)
        #         # Example: RSAPublicKey + sha256 -> rsa_pkcs1_sha256
        #         if "rsa" in pubkey_norm and "pss" in sig_norm:
        #                 combined = f"rsa_pss_rsae_{sig_norm}"
        #         elif "rsa" in pubkey_norm and sig_norm.startswith("sha"):
        #                 combined = f"rsa_pkcs1_{sig_norm}"
        #         elif "ecdsa" in pubkey_norm or "ec" in pubkey_norm:
        #                 sig_norm = re.sub(r"secp\d+r\d+", "", sig_norm)
        #                 combined = f"ecdsa_{sig_norm}"
        #         elif "ed25519" in pubkey_norm:
        #                 combined = "ed25519"
        #         elif "ed448" in pubkey_norm:
        #                 combined = "ed448"
        #         elif "dsa" in pubkey_norm:
        #                 combined = f"dsa_{sig_norm}"  # maps to dsa_sha1, etc. (deprecated)
        #         elif "anon" in sig_norm or "anon" in pubkey_norm:
        #                 combined = "anonymous"
        #         else:
        #                 combined = sig_norm
        # else:
        #         combined = sig_norm

        # combined = re.sub(r"_+", "_", combined).strip("_")

        # # Direct lookup
        # entry = sig_dict.get(combined)
        # if entry:
        #         print(f"[DEBUG] Signature: {sig} | PubKey: {pubkey} | Combined: {combined} → "
        #                 f"Matched DB: {entry['Description']} | Recommended={entry['Recommended']} "
        #                 f"| Score={entry['RecommendedScore']}")
        #         return entry.get("RecommendedScore", 0)
        # else:
        #         print(f"[DEBUG] Signature: {sig} | PubKey: {pubkey} | Combined: {combined} → Not found in DB")

        # # Fallback: try partial matches
        # for key in sig_dict:
        #         if sig_norm in key or key in sig_norm:
        #                 return sig_dict[key].get("RecommendedScore", 0)

        # # Final fallback: unknown → score 0
        # print(f"[DEBUG] Unknown signature algo → {sig_norm} (pubkey={pubkey})")
        # return 0

## define SIG_ALGO dict globally
sig_df = pd.read_csv("tls-signaturescheme.csv")
sig_dict = build_sig_dict(sig_df)

# Placeholders (will stay at 0 for now)
# PLACEHOLDER_ATTRS = ["Key_Size", "Common_Name", "SANs"]


# ----------------------------
# CCADB (Database for CAs)
# ----------------------------

# -----------------------------
# Trusted CA Database (CCADB)
# -----------------------------
CCADB_FILE = "AllCertificateRecordsReport.csv"  # <-- put the CCADB CSV here

try:
        ccadb_df = pd.read_csv(CCADB_FILE, usecols=["Certificate Name", "CA Owner"])
        trusted_cert_names = set(ccadb_df["Certificate Name"].dropna().unique())
        cert_to_owner = dict(zip(ccadb_df["Certificate Name"], ccadb_df["CA Owner"]))
        print(f"Loaded {len(trusted_cert_names)} trusted certificate names from CCADB")
except FileNotFoundError:
        print(f"Warning: CCADB file {CCADB_FILE} not found, Issuer_Score will be 0")
        trusted_cert_names = set()
        cert_to_owner = {}
    

def score_issuer(issuer: str) -> int:
        issuer = normalize(issuer)
        for trusted in trusted_cert_names:
                trusted_issuer = normalize(trusted)
                if issuer == trusted_issuer:
                        return 5   # full points if trusted issuer
        return 1    # penalty if not found


# ----------------------------
## Cert Score
# ----------------------------
def score_cert_validity(valid_from: str, valid_to: str) -> int:
        """Score based on whether the certificate is valid now and time left until expiry."""
        try:
                # Handle NaN or None gracefully
                if (valid_from is None or valid_to is None or
                        (isinstance(valid_from, float) and math.isnan(valid_from)) or
                        (isinstance(valid_to, float) and math.isnan(valid_to))):
                        return 1  # missing values → no score

                # Ensure both are strings
                if not isinstance(valid_from, str) or not isinstance(valid_to, str):
                        print(f"[DEBUG] Unexpected types: valid_from={valid_from}, valid_to={valid_to}")
                        return 1

                # Parse datetimes (replace Z with +00:00 if needed)
                start = datetime.fromisoformat(valid_from.replace("Z", "+00:00"))
                end = datetime.fromisoformat(valid_to.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)

                if start <= now <= end:
                        days_left = (end - now).days
                        if days_left > 365:
                                return 5
                        elif days_left > 180:
                                return 4
                        elif days_left > 30:
                                return 3
                        elif days_left >= 0:
                                return 2
                else:
                        return 1  # expired or not yet valid
        except Exception as e:
                # print(f"[DEBUG] Exception in score_cert_validity: {e}, inputs=({valid_from}, {valid_to})")
                return 1  # fallback if parsing fails

# ----------------------------
# Main Scoring Routine
# ----------------------------

def score_file(csv_path, output_suffix="_scored"):
        """Load the latest report, score it, and save with new columns."""
        df = robust_read_csv(csv_path)

        ## Encryption scoring
        df["TLS_Score"] = df["TLS_Version"].apply(score_tls_version)
        df["Cipher_Score"] = df["Cipher_Suite"].apply(score_cipher_suite)

        # KEX scored here
        df["KeyExchange_Score"] = df["Key_Exchange"].apply(score_kex)

        # Authentication scoring
        df["Signature_Score"] = df.apply(lambda row: score_signature_algo(sig = row["Signature_Algorithm"], pubkey = row["Public_Key_Algorithm"], server_sig = row.get("Server_Signature_Algorithm")), axis=1)
        df["CertValidity_Score"] = df.apply(
                lambda row: score_cert_validity(row["Valid_From"], row["Valid_To"]), axis=1
        )

        # Issuer scoring
        df["Issuer_Score"] = df["Issuer"].apply(score_issuer)

        # # Placeholder scores
        # for attr in PLACEHOLDER_ATTRS:
        #         df[f"{attr}_Score"] = 0

            # 🧩 Apply Unsecured Override
        for idx, row in df.iterrows():
                tls_version = str(row["TLS_Version"]).strip().lower()

                # Case: explicitly unsecured (e.g., plain HTTP)
                if "unsecure" in tls_version:
                        df.loc[idx, [
                                "TLS_Score", "Cipher_Score", "KeyExchange_Score",
                                "Signature_Score", "CertValidity_Score", "Issuer_Score"
                        ]] = 1

        # 🧹 Remove rows where all encryption attributes are empty or NaN
        encryption_cols = [
        "TLS_Version", "Cipher_Suite", "Key_Exchange", "Issuer", "Signature_Algorithm", "Server_Signature_Algorithm", "Key_Size", "Public_Key_Algorithm", "Valid_From", "Valid_To" 
        ]

        # Clean up variations like 'n/a' or 'N/A' or '' by converting them to NaN
        df[encryption_cols] = df[encryption_cols].replace(to_replace=["n/a", "N/A", "na", "NaN", "None", ""], value=pd.NA)

        # Drop rows where *all* of these attributes are missing (meaning no data was retrieved)
        df = df.dropna(subset=encryption_cols, how='all')
        # print(f"[INFO] Dropped {before_drop - after_drop} rows with no encryption data.")


        # # Totals
        # df["Encryption_Total"] = (
        #         df["TLS_Score"] + df["Cipher_Score"] + df["KeyExchange_Score"]
        # )
        # df["Auth_Total"] = (
        #         df["Signature_Score"]
        #         + df["CertValidity_Score"]
        #         + df["Issuer_Score"]
        # )
        # df["Overall_Score"] = df["Encryption_Total"] + df["Auth_Total"]

        
        # define min/max possible raw totals (based on 1..5 per component)
        # ENC_COMPONENTS = 3
        # AUTH_COMPONENTS = 3
        # MIN_PER_COMPONENT = 1
        # MAX_PER_COMPONENT = 5

        # ENCRYPTION_MIN = ENC_COMPONENTS * MIN_PER_COMPONENT    # 3
        # ENCRYPTION_MAX = ENC_COMPONENTS * MAX_PER_COMPONENT    # 15
        # AUTH_MIN = AUTH_COMPONENTS * MIN_PER_COMPONENT         # 3
        # AUTH_MAX = AUTH_COMPONENTS * MAX_PER_COMPONENT         # 15
        # OVERALL_MIN = ENCRYPTION_MIN + AUTH_MIN                # 6
        # OVERALL_MAX = ENCRYPTION_MAX + AUTH_MAX                # 30

        with open("config.json") as f:
                config = json.load(f)

        scoring_method = config.get("scoring_method", "basic")
        equal_bin_rounding = config.get("rounding", {}).get("equal_bins", True)
        weights = config.get("weighting", {})
        alpha = weights.get("group", {}).get("alpha", 0.5)
        individual_weights = weights.get("individual", {}).get("individual_weights", {})

        # define min/max possible raw totals
        ENC_COMPONENTS = 3
        AUTH_COMPONENTS = 3
        MIN_PER_COMPONENT = config.get("scoring_scale", {}).get("min_per_component", 1)
        MAX_PER_COMPONENT = config.get("scoring_scale", {}).get("max_per_component", 5)

        ENCRYPTION_MIN = ENC_COMPONENTS * MIN_PER_COMPONENT
        ENCRYPTION_MAX = ENC_COMPONENTS * MAX_PER_COMPONENT
        AUTH_MIN = AUTH_COMPONENTS * MIN_PER_COMPONENT
        AUTH_MAX = AUTH_COMPONENTS * MAX_PER_COMPONENT

        OVERALL_MIN = ENCRYPTION_MIN + AUTH_MIN
        OVERALL_MAX = ENCRYPTION_MAX + AUTH_MAX

        # If using weighted scoring, OVERALL_MAX/OVERALL_MIN might need scaling
        if scoring_method == "individual":
                # calculate max/min using weights
                ENCRYPTION_MIN = sum(individual_weights.get(c, 1.0) * MIN_PER_COMPONENT for c in encryption_components)
                ENCRYPTION_MAX = sum(individual_weights.get(c, 1.0) * MAX_PER_COMPONENT for c in encryption_components)
                AUTH_MIN = sum(individual_weights.get(c, 1.0) * MIN_PER_COMPONENT for c in auth_components)
                AUTH_MAX = sum(individual_weights.get(c, 1.0) * MAX_PER_COMPONENT for c in auth_components)
                OVERALL_MIN = ENCRYPTION_MIN + AUTH_MIN
                OVERALL_MAX = ENCRYPTION_MAX + AUTH_MAX
        elif scoring_method == "group":
                OVERALL_MIN = alpha * ENCRYPTION_MIN + (1 - alpha) * AUTH_MIN
                OVERALL_MAX = alpha * ENCRYPTION_MAX + (1 - alpha) * AUTH_MAX

        df[["Encryption_Total", "Auth_Total", "Overall_Score"]] = df.apply(compute_totals, axis=1, args=(scoring_method, individual_weights, alpha))

        df["Norm_Enc_Total"] = df["Encryption_Total"].apply(lambda r: scale_to_1_5(r, ENCRYPTION_MIN, ENCRYPTION_MAX, equal_bins=equal_bin_rounding))
        df["Norm_Auth_Total"] = df["Auth_Total"].apply(lambda r: scale_to_1_5(r, AUTH_MIN, AUTH_MAX, equal_bins=equal_bin_rounding))
        df["Norm_Score_Total"] = df["Overall_Score"].apply(lambda r: scale_to_1_5(r, OVERALL_MIN, OVERALL_MAX, equal_bins=equal_bin_rounding))


        df["Encryption_Colour"] = df["Norm_Enc_Total"].apply(colour_from_score)
        df["Auth_Colour"] = df["Norm_Auth_Total"].apply(colour_from_score)
        df["Overall_Colour"] = df["Norm_Score_Total"].apply(colour_from_score)

        # define output directory
        output_dir = r"C:\Users\Andrew Beh\OneDrive - UNSW\Desktop\Engineering Stuff\Thesis\Thesis C\Poster Resources\visual data display"

        # Save scored file
        new_filename = csv_path.replace(".csv", f"{scoring_method}{output_suffix}.csv")

        # Ask the user if they want to rename before saving
        print(f"\n[INFO] Default output filename: {new_filename}")
        custom_name = input("Enter a different output name (or press Enter to keep default): ").strip()

        if custom_name:
                if not custom_name.lower().endswith(".csv"):
                        custom_name += ".csv"
                        new_filename = custom_name

        save_path = os.path.join(output_dir, new_filename)
        df.to_csv(save_path, index=False)
        print(f"Scored file saved as: {new_filename}")
        return new_filename

# ----------------------------
# If run directly
# ----------------------------
if __name__ == "__main__":
        # Find CSV files in current folder
        csv_files = glob.glob("*.csv")

        if not csv_files:
                print("[ERROR] No CSV files found in current directory.")
        else:
                print("Available CSV files:")
                for i, f in enumerate(csv_files, start=1):
                        print(f"{i}. {f}")

                # Ask user to pick one
                choice = input("Select a CSV file by number (or press Enter for first): ").strip()
                if choice.isdigit() and 1 <= int(choice) <= len(csv_files):
                        selected_file = csv_files[int(choice) - 1]
                else:
                        selected_file = csv_files[0]

                print(f"[INFO] Using {selected_file}")
                score_file(selected_file)





