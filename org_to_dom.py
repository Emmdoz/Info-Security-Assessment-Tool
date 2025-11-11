# import requests
# import tldextract
# import csv

# API_KEY = "AIzaSyDmrK8xBC7hXkN5T8aFkPa4MNZSVMwHB9I"
# CX = "027c40527e6794a1d"

# def get_domain_from_name(name):
#     query = f"{name} official site"
#     url = "https://www.googleapis.com/customsearch/v1"
#     params = {
#         "key": API_KEY,
#         "cx": CX,
#         "q": query,
#         "num": 5,
#         "gl": "au",       # bias towards Australian domains
#         "hl": "en"        # language: English
#     }
#     response = requests.get(url, params=params)
#     data = response.json()

#     if "items" not in data:
#         print(f"No results for {name}")
#         return None

#     filtered_domains = ["wikipedia.org", "linkedin.com", "bloomberg.com", "reuters.com", "apra.gov.au", "asic.gov.au"]

#     for item in data["items"]:
#         link = item["link"]
#         ext = tldextract.extract(link)
#         domain = f"{ext.domain}.{ext.suffix}"  # just clean domain

#         # skip unwanted domains
#         if domain in filtered_domains:
#             continue

#         # only allow corporate TLDs
#         if ext.suffix not in ["com.au", "net.au", "org.au"]:
#             continue

#         return domain

#     return None


# with open("names_Significant_financial_institutions_register.txt", "r", encoding="utf-8") as f:
#     institutions = [line.strip() for line in f if line.strip()]

# seen_domains = set()


# with open("domains.csv", mode="w", newline="", encoding="utf-8") as file:
#         writer = csv.writer(file)


#         for inst in institutions:
#                 domain = get_domain_from_name(inst)
#                 if domain in seen_domains:
#                         domain = ""  # leave blank if already seen
#                 elif domain:
#                         seen_domains.add(domain)

#                 writer.writerow([inst, domain])
import requests
import tldextract
import csv
import time
import re
import glob
import os
from urllib.parse import urlparse

# ---------------- CONFIG ----------------
API_KEY = "AIzaSyDmrK8xBC7hXkN5T8aFkPa4MNZSVMwHB9I"   # <-- keep private
CX = "027c40527e6794a1d"             # your custom search engine id
INPUT_FOLDER = "./"        # folder containing input .txt files
BATCH_SIZE = 100           # max names per run / per quota
FILTERED_DOMAINS = {"wikipedia.org", "linkedin.com", "bloomberg.com", "reuters.com", "apra.gov.au", "asic.gov.au", "abc.net.au"}
ALLOWED_SUFFIXES = {"com.au", "net.au", "org.au"}
MAX_RESULTS = 5
GL = "au"
HL = "en"
SLEEP_BETWEEN_QUERIES = 0.25  # seconds between API calls

# Output files
DETAILED_CSV = "domains_detailed.csv"
SUMMARY_CSV = "domains_summary.csv"
FINAL_CSV = "domains_final.csv"


# ---------------- HELPERS ----------------
def query_google_customsearch(query, num=5):
    url = "https://www.googleapis.com/customsearch/v1"
    params = {
        "key": API_KEY,
        "cx": CX,
        "q": query,
        "num": num,
        "gl": GL,
        "hl": HL
    }
    resp = requests.get(url, params=params, timeout=15)
    resp.raise_for_status()
    return resp.json()


def _tokenize_org_name(org_name):
    if not org_name:
        return []
    tokens = re.findall(r"[A-Za-z0-9]{2,}", org_name)
    stop = {"and", "the", "of", "for", "a", "co", "company", "ltd", "pty", "limited", "group", "inc"}
    return [t.lower() for t in tokens if t.lower() not in stop]


def extract_domain(link):
    if not link:
        return "", ""
    ext = tldextract.extract(link)
    domain = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()
    suffix = ext.suffix.lower() if ext.suffix else ""
    return domain, suffix


def pick_by_rank_with_light_checks(items, org_name, seen_domains):
    org_tokens = _tokenize_org_name(org_name)
    candidates = []
    rank = 0

    for item in items:
        rank += 1
        link = item.get("link", "") or ""
        title = (item.get("title") or "").lower()
        snippet = (item.get("snippet") or "").lower()
        domain, suffix = extract_domain(link)

        candidate = {
            "rank": rank,
            "link": link,
            "title": title,
            "snippet": snippet,
            "domain": domain,
            "suffix": suffix,
            "token_hits": 0,
            "accepted": False,
            "reason": ""
        }

        # Sanity checks
        if not domain:
            candidate["reason"] = "no_domain_extracted"
        elif domain in seen_domains:
            candidate["reason"] = "duplicate_of_previous"
        elif domain in FILTERED_DOMAINS:
            candidate["reason"] = "filtered_domain_list"
        elif suffix not in ALLOWED_SUFFIXES:
            candidate["reason"] = f"disallowed_suffix ({suffix})"
        else:
            # compute token_hits
            hits = sum(1 for t in org_tokens if t and (t in domain or t in title or t in snippet))
            candidate["token_hits"] = hits
            candidate["accepted"] = True
            candidate["reason"] = "token_match" if hits > 0 else "fallback_pass_suffix_and_not_blacklisted"

        candidates.append(candidate)

    # Selection: prefer candidate with token_hits>0 first
    for c in candidates:
        if c["accepted"] and c["token_hits"] > 0:
            return c["domain"], candidates
    for c in candidates:
        if c["accepted"]:
            return c["domain"], candidates

    return None, candidates


# ---------------- MAIN ----------------
def main():
    # 1. Collect all input files
    input_files = glob.glob(os.path.join(INPUT_FOLDER, "*.txt"))
    all_institutions = []
    for file_path in input_files:
        with open(file_path, "r", encoding="utf-8") as fh:
            names = [line.strip() for line in fh if line.strip()]
            all_institutions.extend(names)

    # Deduplicate
    all_institutions = list(dict.fromkeys(all_institutions))
    print(f"[INFO] Found {len(all_institutions)} unique institutions from {len(input_files)} files")

    # 2. Load already processed institutions and domains
    seen_institutions = set()
    seen_domains = set()
    if os.path.exists(FINAL_CSV):
        with open(FINAL_CSV, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)
            for row in reader:
                seen_institutions.add(row[0])
                if len(row) > 1 and row[1]:
                    seen_domains.add(row[1])

    # Load existing detailed CSV
    existing_detailed = {}
    if os.path.exists(DETAILED_CSV):
        with open(DETAILED_CSV, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                existing_detailed[row["Organisation"]] = row

    # Load existing summary CSV
    existing_summary = {}
    if os.path.exists(SUMMARY_CSV):
        with open(SUMMARY_CSV, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                existing_summary[row["Organisation"]] = row

    # 3. Batch processing
    batch_count = 0
    processed_today = 0
    for i in range(0, len(all_institutions), BATCH_SIZE):
        batch = all_institutions[i:i + BATCH_SIZE]
        batch = [o for o in batch if o not in seen_institutions]  # skip already done
        if not batch:
            continue
        batch_count += 1
        print(f"[INFO] Processing batch {batch_count} ({len(batch)} orgs)")

        for inst in batch:
            if processed_today >= BATCH_SIZE:  # stop after 100 orgs
                print(f"[INFO] Reached daily quota of {BATCH_SIZE} orgs. Stopping.")
                return
            processed_today += 1

        # Open CSVs for appending
        with open(DETAILED_CSV, "a", newline="", encoding="utf-8") as det_fh, \
             open(SUMMARY_CSV, "a", newline="", encoding="utf-8") as sum_fh, \
             open(FINAL_CSV, "a", newline="", encoding="utf-8") as final_fh:

            det_writer = csv.writer(det_fh)
            sum_writer = csv.writer(sum_fh)
            final_writer = csv.writer(final_fh)

            # Write headers if files empty
            if det_fh.tell() == 0:
                det_writer.writerow(["Organisation", "Rank", "Result_Link", "Domain", "Suffix", "Token_Hits", "Accepted", "Reason"])
            if sum_fh.tell() == 0:
                sum_writer.writerow(["Organisation", "Top5_count", "Accepted_count", "Chosen_domain_or_blank"])
            if final_fh.tell() == 0:
                final_writer.writerow(["Organisation", "Chosen_domain_or_blank"])

            for inst in batch:
                time.sleep(SLEEP_BETWEEN_QUERIES)
                query = f"{inst} official site"
                try:
                    data = query_google_customsearch(query, num=MAX_RESULTS)
                except Exception as e:
                    print(f"[ERROR] Search error for '{inst}': {e}")
                    # Update summary dict for failed query
                    existing_summary[inst] = {
                        "Organisation": inst,
                        "Top5_count": 0,
                        "Accepted_count": 0,
                        "Chosen_domain_or_blank": ""
                    }
                    # Write immediately to final CSV
                    final_writer.writerow([inst, ""])
                    continue

                items = data.get("items", [])[:MAX_RESULTS]
                chosen_domain, candidates = pick_by_rank_with_light_checks(items, inst, seen_domains)

                accepted_count = 0
                # Prepare detailed info
                if candidates:
                    for c in candidates:
                        if c.get("accepted"):
                            accepted_count += 1

                    first_candidate = candidates[0]
                    existing_detailed[inst] = {
                        "Organisation": inst,
                        "Rank": first_candidate.get("rank", ""),
                        "Result_Link": first_candidate.get("link", ""),
                        "Domain": chosen_domain or "",
                        "Suffix": first_candidate.get("suffix", ""),
                        "Token_Hits": first_candidate.get("token_hits", ""),
                        "Accepted": "YES" if any(c.get("accepted") for c in candidates) else "NO",
                        "Reason": first_candidate.get("reason", "")
                    }
                else:
                    existing_detailed[inst] = {
                        "Organisation": inst,
                        "Rank": "",
                        "Result_Link": "",
                        "Domain": "",
                        "Suffix": "",
                        "Token_Hits": "",
                        "Accepted": "NO",
                        "Reason": ""
                    }

                top5_count = len(candidates)
                if chosen_domain and chosen_domain in seen_domains:
                    final_choice = ""
                elif chosen_domain:
                    final_choice = chosen_domain
                    seen_domains.add(chosen_domain)
                else:
                    final_choice = ""

                # Update summary dict
                existing_summary[inst] = {
                    "Organisation": inst,
                    "Top5_count": top5_count,
                    "Accepted_count": accepted_count,
                    "Chosen_domain_or_blank": final_choice or ""
                }

                # Write immediately to final CSV
                final_writer.writerow([inst, final_choice or ""])
                seen_institutions.add(inst)

                print(f"[INFO] {inst} -> {final_choice or 'NO DOMAIN'}  (top5={top5_count}, accepted={accepted_count})")

        # After processing the batch, rewrite detailed and summary CSVs from dictionaries
        with open(DETAILED_CSV, "w", newline="", encoding="utf-8") as det_fh:
            fieldnames_det = ["Organisation", "Rank", "Result_Link", "Domain", "Suffix", "Token_Hits", "Accepted", "Reason"]
            det_writer = csv.DictWriter(det_fh, fieldnames=fieldnames_det)
            det_writer.writeheader()
            for row in existing_detailed.values():
                det_writer.writerow(row)

        with open(SUMMARY_CSV, "w", newline="", encoding="utf-8") as sum_fh:
            fieldnames_sum = ["Organisation", "Top5_count", "Accepted_count", "Chosen_domain_or_blank"]
            sum_writer = csv.DictWriter(sum_fh, fieldnames=fieldnames_sum)
            sum_writer.writeheader()
            for row in existing_summary.values():
                sum_writer.writerow(row)


        print(f"[INFO] Batch {batch_count} complete. Processed {len(batch)} orgs.\n")
        

    print("Done. Files written:")
    print(" -", DETAILED_CSV)
    print(" -", SUMMARY_CSV)
    print(" -", FINAL_CSV)


if __name__ == "__main__":
    main()
