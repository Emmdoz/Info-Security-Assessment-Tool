from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import ElementClickInterceptedException, TimeoutException
import time
import re
import csv
import os

# ---------------- Helpers ----------------
def safe_filename(title):
    return re.sub(r"[^\w\d]+", "_", title).strip("_") or "apra_page"

def normalize_name(s):
    s = (s or "").strip()
    s = s.replace("\u00A0", " ")
    s = re.sub(r"\s+", " ", s)
    s = s.rstrip("*").strip()
    return s

def save_diagnostics(driver, safe_title):
    """Save page source and screenshot for later inspection."""
    html_path = f"names_{safe_title}.html"
    png_path = f"names_{safe_title}.png"
    try:
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(driver.page_source)
        print(f"[DIAG] Saved page source -> {html_path}")
    except Exception as e:
        print("[DIAG] Could not save page source:", e)
    try:
        driver.save_screenshot(png_path)
        print(f"[DIAG] Saved screenshot -> {png_path}")
    except Exception as e:
        print("[DIAG] Could not save screenshot:", e)

def try_dismiss_cookies(driver):
    """Try a few common cookie/consent button labels to remove overlays."""
    candidates = [
        ("button", "Accept"),
        ("button", "I accept"),
        ("button", "Agree"),
        ("button", "Dismiss"),
        ("button", "OK"),
        ("button", "Close"),
        ("a", "Accept"),
        ("button", "Got it"),
    ]
    for tag, text in candidates:
        try:
            el = driver.find_element(By.XPATH,
                f"//{tag}[contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'), '{text.lower()}')]")
            if not el:
                continue
            try:
                el.click()
            except ElementClickInterceptedException:
                driver.execute_script("arguments[0].click();", el)
            time.sleep(0.5)
            print(f"[INFO] Clicked cookie button: {text}")
            return True
        except Exception:
            continue
    return False

def click_show_all_if_present(driver):
    """
    Safer: click only explicit 'view all' or 'show all' controls or known classes.
    Returns True if clicked anything.
    """
    clicked = False

    # explicit text matches (phrase-based)
    xpaths = [
        "//a[contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'), 'view all')]",
        "//button[contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'), 'view all')]",
        "//a[contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'), 'show all')]",
        "//button[contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'), 'show all')]",
    ]
    for xp in xpaths:
        try:
            elems = driver.find_elements(By.XPATH, xp)
            for el in elems:
                text = (el.text or "").strip()
                if len(text) < 3:
                    continue
                href = el.get_attribute("href") or ""
                if href and (href.startswith("http") and "apra.gov.au" not in href):
                    continue
                try:
                    driver.execute_script("arguments[0].scrollIntoView(true);", el)
                    el.click()
                except ElementClickInterceptedException:
                    driver.execute_script("arguments[0].click();", el)
                time.sleep(0.5)
                print(f"[INFO] Clicked explicit show-all element: {text[:60]}")
                clicked = True
        except Exception:
            continue

    class_selectors = [
        ".views-more__link",
        ".views-more",
        ".show-all",
        ".js-show-all",
        ".view-more",
        ".views-exposed-form .views-submit",
    ]
    if not clicked:
        for cls in class_selectors:
            try:
                elems = driver.find_elements(By.CSS_SELECTOR, cls)
                for el in elems:
                    text = (el.text or "").strip()
                    if len(text) < 2:
                        continue
                    href = el.get_attribute("href") or ""
                    if href and (href.startswith("http") and "apra.gov.au" not in href):
                        continue
                    try:
                        driver.execute_script("arguments[0].scrollIntoView(true);", el)
                        el.click()
                    except ElementClickInterceptedException:
                        driver.execute_script("arguments[0].click();", el)
                    time.sleep(0.5)
                    print(f"[INFO] Clicked show-all via class selector: {cls} ({text[:40]})")
                    clicked = True
            except Exception:
                continue

    return clicked

# ---------- NEW helpers for stability and filtering ----------
def wait_for_stable_count(driver, find_fn, timeout=10, stable_period=1.0, poll=0.25):
    """
    Wait until the count returned by find_fn() stops changing for stable_period seconds
    or until timeout. find_fn should return an integer count (or a list/iterable).
    Returns the last found list/iterable.
    """
    end = time.time() + timeout
    last_count = None
    last_change_time = time.time()
    last_result = []
    while time.time() < end:
        try:
            res = find_fn()
        except Exception:
            res = []
        cur_count = len(res) if hasattr(res, "__len__") else (1 if res else 0)
        if last_count is None or cur_count != last_count:
            last_count = cur_count
            last_change_time = time.time()
            last_result = res
        else:
            # unchanged since last sample
            if time.time() - last_change_time >= stable_period:
                return last_result
        time.sleep(poll)
    # timeout: return whatever we last saw
    return last_result

def safe_click(driver, el):
    """
    Robust click: scroll into view and attempt JS click if normal click fails.
    """
    try:
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
        el.click()
    except Exception:
        try:
            driver.execute_script("arguments[0].click();", el)
        except Exception:
            pass

# Conservative reject patterns for non-org lines
_re_bad_phrases = [
    r"\binstrument\b", r"\bvariation\b", r"\btakes effect\b", r"\bPublished\b", r"\bvariation of licence\b",
    r"\bconditions\b", r"\bbulletin\b", r"\bPDF\b", r"\.pdf\b", r"\bKB\b", r"\bMB\b",
    r"\bno\.\s*\d{1,4}\b", r"\bof\s+20\d{2}\b", r"\b20\d{2}\b"  # years often in doc titles
]
_re_bad = re.compile("|".join(_re_bad_phrases), re.IGNORECASE)

def is_likely_org_name(text, element=None):
    """
    Conservative heuristic: return True if text looks like an organisation name,
    False if it matches document/notice patterns or obviously nav text.
    element param optional: a selenium element to allow extra checks later (e.g. link href).
    """
    if not text:
        return False
    txt = text.strip()
    # filter very short lines
    if len(txt) < 3:
        return False
    # nav/common labels
    low = txt.lower()
    if low in ("home", "back", "registers", "contact", "enforceable undertakings", "infringement notices"):
        return False
    # if it contains obvious doc/notice phrases or a year-only, reject
    if _re_bad.search(txt):
        return False
    # if it looks like a file-size label or only uppercase acronym + number, reject
    if re.match(r"^[\d\(\)\-\s]+$", txt):
        return False
    # if element is provided, check the href: if the li's only meaningful child is a PDF link and the text contains 'Variation' etc,
    # it's very likely a document not an org
    if element is not None:
        try:
            anchors = element.find_elements(By.TAG_NAME, "a")
            if anchors:
                # if the first anchor href ends with pdf, heavy suspicion it's a doc
                href = anchors[0].get_attribute("href") or ""
                if href.lower().endswith(".pdf") and len(txt) > 20:
                    return False
        except Exception:
            pass
    # otherwise accept
    return True

def get_li_main_text(li):
    """
    Return the main text of a <li>, ignoring hyperlinks that are appended but
    keeping the main org name.
    """
    text = li.text.strip()
    # Optionally remove appended notices or footnotes (common pattern: ' – ' or newline)
    text = text.split(' – ')[0].split('\n')[0].strip()
    if not text:
        return None
    return normalize_name(text)



# ---------------- Detection ----------------
def detect_page_type(driver, timeout=10):
    """
    Return 'ul', 'dropdown', 'table', 'views' or 'unknown'
    Wait up to `timeout` seconds to find markers
    """
    end = time.time() + timeout
    while time.time() < end:
        # table markers
        if driver.find_elements(By.CSS_SELECTOR, "main table tbody tr, article table tbody tr, table.register-table tr, table.dataTable tr, table.views-table tr"):
            return "table"
        # common list markers in content areas
        if driver.find_elements(By.CSS_SELECTOR, "div.block-field-blocknodebasicbody ul li, div.accordion__content li, main ul li, article ul li"):
            return "ul"
        # Drupal Views
        if driver.find_elements(By.CSS_SELECTOR, "div.view-content, .view-content, div.views-row, .views-row"):
            return "views"
        # accordion toggles
        if driver.find_elements(By.CSS_SELECTOR, "button.accordion__toggle, button.accordion__title"):
            return "dropdown"
        time.sleep(0.3)
    return "unknown"

# ---------------- Scrapers ----------------
def _is_nav_or_menu_li(li):
    try:
        li.find_element(By.XPATH,
            "ancestor::nav | ancestor::header | ancestor::footer | ancestor::*[contains(@role,'navigation') or contains(@class,'breadcrumb') or contains(@class,'menu') or contains(@class,'region--navigation')]")
        return True
    except:
        return False

def scrape_ul(driver, max_wait=6):
    try:
        page_title = driver.find_element(By.TAG_NAME, "h1").text.strip()
    except:
        page_title = "apra_page"

    selectors = [
        "div.block-field-blocknodebasicbody ul",
        "div.field--name-body ul",
        "main ul",
        "article ul",
        "div.content ul",
        "div.accordion__content ul"
    ]

    names = []
    for sel in selectors:
        # wait until the selector yields a stable set of UL elements
        uls = wait_for_stable_count(driver, lambda: driver.find_elements(By.CSS_SELECTOR, sel), timeout=max_wait, stable_period=0.8)
        if uls:
            for ul in uls:
                for li in ul.find_elements(By.TAG_NAME, "li"):
                    if _is_nav_or_menu_li(li):
                        continue
                    txt = normalize_name(li.text)
                    if not is_likely_org_name(txt, li):
                        continue
                    names.append(txt)
            if names:
                break

    if not names:
        all_uls = wait_for_stable_count(driver, lambda: driver.find_elements(By.TAG_NAME, "ul"), timeout=3, stable_period=0.6)
        for ul in all_uls:
            for li in ul.find_elements(By.TAG_NAME, "li"):
                if _is_nav_or_menu_li(li):
                    continue
                txt = normalize_name(li.text)
                if not is_likely_org_name(txt, li):
                    continue
                names.append(txt)

    # dedupe preserving order
    seen = set(); dedup = []
    for n in names:
        if n not in seen:
            dedup.append(n); seen.add(n)

    print(f"[DEBUG] scrape_ul: Found {len(dedup)} items (title: {page_title[:60]})")
    print("[DEBUG] sample:", dedup[:10])
    return page_title, dedup

def scrape_dropdown(driver, per_panel_wait=4):
    """
    Robustly open each accordion panel, wait for its content to stabilise,
    and scrape <li> items inside that panel only.

    Returns: (page_title, combined_names_list, panels_info)
      - combined_names_list: deduped list of all names across panels
      - panels_info: list of dicts per-panel: { 'header': str, 'names': [..], 'panel_id': id_or_index }
    """
    try:
        page_title = driver.find_element(By.TAG_NAME, "h1").text.strip()
    except:
        page_title = "apra_page"

    panels_info = []
    all_names = []

    # find button toggles (these are the clickable headers)
    try:
        buttons = driver.find_elements(By.CSS_SELECTOR, "button.accordion__toggle, button.accordion__title, .accordion__toggle, .accordion__title")
    except Exception:
        buttons = []

    if not buttons:
        # fallback selectors for some site variants
        buttons = driver.find_elements(By.CSS_SELECTOR, "[role='button'][aria-controls], [data-toggle='accordion']")

    # iterate buttons in order
    for idx, btn in enumerate(buttons):
        header_text = (btn.text or "").strip()
        panel_id = btn.get_attribute("aria-controls") or f"index-{idx}"

        # click the panel to expand it (if not already expanded)
        try:
            aria = btn.get_attribute("aria-expanded")
            if aria != "true":
                safe_click(driver, btn)
            else:
                driver.execute_script("arguments[0].scrollIntoView({block:'center'});", btn)
        except Exception:
            try:
                driver.execute_script("arguments[0].click();", btn)
            except Exception:
                pass

        # determine panel content divs
        if panel_id.startswith("index-"):
            def find_panel_content():
                try:
                    return btn.find_elements(By.XPATH, "./following-sibling::*[contains(@class,'accordion__content') or contains(@class,'accordion-content') or contains(@class,'content')]")
                except Exception:
                    return []
            content_divs = wait_for_stable_count(driver, find_panel_content, timeout=per_panel_wait, stable_period=0.6)
        else:
            def find_by_id():
                return driver.find_elements(By.CSS_SELECTOR, f"div#{panel_id}, section#{panel_id}, div[id='{panel_id}']")
            content_divs = wait_for_stable_count(driver, find_by_id, timeout=per_panel_wait, stable_period=0.6)
            if not content_divs:
                try:
                    content_divs = btn.find_elements(By.XPATH, "./following-sibling::*[contains(@class,'accordion__content') or contains(@class,'accordion-content')]")
                except Exception:
                    content_divs = []

        if not content_divs:
            content_divs = wait_for_stable_count(driver, lambda: driver.find_elements(By.CSS_SELECTOR, "div.accordion__content, .accordion__content"), timeout=per_panel_wait, stable_period=0.6)

        panel_names = []

        # scrape <li> in content divs for this panel
        for div in content_divs:
            try:
                lis = wait_for_stable_count(driver, lambda d=div: d.find_elements(By.TAG_NAME, "li"), timeout=1.5, stable_period=0.5)
            except Exception:
                lis = div.find_elements(By.TAG_NAME, "li")

            for li in lis:
                txt = get_li_main_text(li)
                if not txt:
                    continue
                # filter out non-org lines or notices appended as links
                if not is_likely_org_name(txt, li):
                    continue
                panel_names.append(txt)

        # also check <a> inside divs if no <li> names found
        if not panel_names:
            for div in content_divs:
                anchors = div.find_elements(By.TAG_NAME, "a")
                for a in anchors:
                    txt = normalize_name(a.text)
                    if txt and is_likely_org_name(txt, a):
                        panel_names.append(txt)

        # dedupe panel
        seen = set()
        dedup_panel = []
        for n in panel_names:
            if n not in seen:
                dedup_panel.append(n)
                seen.add(n)

        panels_info.append({
            "header": header_text or f"panel_{idx}",
            "panel_id": panel_id,
            "names": dedup_panel
        })

        # accumulate globally preserving order and dedup
        for n in dedup_panel:
            if n not in all_names:
                all_names.append(n)

    print(f"[DEBUG] scrape_dropdown: Found {len(all_names)} total items across {len(panels_info)} panels (title: {page_title[:60]})")
    print("[DEBUG] panels summary:", [(p['header'][:40], len(p['names'])) for p in panels_info])
    print("[DEBUG] sample:", all_names[:10])

    return page_title, all_names, panels_info



def scrape_table(driver, max_wait=6):
    try:
        page_title = driver.find_element(By.TAG_NAME, "h1").text.strip()
    except:
        page_title = "apra_page"

    names = []
    selectors = [
        "main table, article table, table.register-table, table.dataTable, table.views-table",
        "table"
    ]
    for sel in selectors:
        end = time.time() + max_wait
        while time.time() < end:
            tables = driver.find_elements(By.CSS_SELECTOR, sel)
            if tables:
                for table in tables:
                    # --- BLACKLIST TABLES BY HEADER OR CONTENT ---
                    table_text = table.text.lower()
                    if "revoked insurers" in table_text:
                        print("[INFO] Skipping table containing 'Revoked Insurance'")
                        continue
                    # -----------------------------------------------
                    try:
                        rows = table.find_elements(By.CSS_SELECTOR, "tbody tr")
                        if not rows:
                            rows = table.find_elements(By.CSS_SELECTOR, "tr")
                    except Exception:
                        rows = table.find_elements(By.TAG_NAME, "tr")
                    for r in rows:
                        cells = [c.text.strip() for c in r.find_elements(By.TAG_NAME, "td") if c.text.strip()]
                        if not cells:
                            cells = [c.text.strip() for c in r.find_elements(By.TAG_NAME, "th") if c.text.strip()]
                        if not cells:
                            continue
                        candidate = None
                        for c in cells:
                            if len(c) > 2:
                                candidate = c
                                break
                        if not candidate:
                            candidate = " | ".join(cells)
                        names.append(normalize_name(candidate))
                if names:
                    break
            time.sleep(0.25)
        if names:
            break

    # dedupe
    seen = set(); dedup = []
    for n in names:
        if n not in seen:
            dedup.append(n); seen.add(n)

    print(f"[DEBUG] scrape_table: Found {len(dedup)} rows (title: {page_title[:60]})")
    print("[DEBUG] sample:", dedup[:10])
    return page_title, dedup


def scrape_views(driver, max_wait=6):
    """
    Scrape Drupal Views-style outputs (div.view-content / div.views-row / .views-row)
    """
    try:
        page_title = driver.find_element(By.TAG_NAME, "h1").text.strip()
    except:
        page_title = "apra_page"

    names = []
    end = time.time() + max_wait
    while time.time() < end and not names:
        view_containers = driver.find_elements(By.CSS_SELECTOR, "div.view-content, .view-content")
        for vc in view_containers:
            rows = wait_for_stable_count(driver, lambda: vc.find_elements(By.CSS_SELECTOR, "div.views-row, .views-row, .view-row"), timeout=3, stable_period=0.6)
            if not rows:
                rows = vc.find_elements(By.XPATH, "./*")
            for r in rows:
                # 1) anchor text inside row (prefer longest text)
                anchors = [a.text.strip() for a in r.find_elements(By.TAG_NAME, "a") if a.text.strip()]
                if anchors:
                    best = max(anchors, key=len)
                    cand = normalize_name(best)
                    if is_likely_org_name(cand, r):
                        names.append(cand)
                    continue
                # 2) list items inside row
                for li in r.find_elements(By.TAG_NAME, "li"):
                    t = li.text.strip()
                    if t:
                        cand = normalize_name(t)
                        if is_likely_org_name(cand, li):
                            names.append(cand)
                # 3) paragraphs fallback
                if not names:
                    for p in r.find_elements(By.TAG_NAME, "p"):
                        t = p.text.strip()
                        if t and len(t) > 2:
                            cand = normalize_name(t)
                            if is_likely_org_name(cand, p):
                                names.append(cand)
                # 4) cells fallback
                if not names:
                    for c in r.find_elements(By.CSS_SELECTOR, "td, th"):
                        t = c.text.strip()
                        if t and len(t) > 2:
                            cand = normalize_name(t)
                            if is_likely_org_name(cand, r):
                                names.append(cand)
            if names:
                break
        time.sleep(0.25)

    # dedupe
    seen = set(); dedup = []
    for n in names:
        if n not in seen:
            dedup.append(n); seen.add(n)

    print(f"[DEBUG] scrape_views: Found {len(dedup)} items (title: {page_title[:60]})")
    print("[DEBUG] sample:", dedup[:10])
    return page_title, dedup

def scrape_text_fallback(driver, max_wait=3):
    """
    Fallback: extract visible text from main/article/body and search for company-like names
    using a conservative regex for common suffixes. Returns (page_title, names).
    """
    try:
        page_title = driver.find_element(By.TAG_NAME, "h1").text.strip()
    except:
        page_title = "apra_page"

    # Wait a short time to let JS populate text (if needed)
    end = time.time() + max_wait
    page_text = ""
    while time.time() < end and not page_text.strip():
        try:
            # Prefer main or article; fallback to body
            if driver.find_elements(By.TAG_NAME, "main"):
                page_text = driver.find_element(By.TAG_NAME, "main").text
            elif driver.find_elements(By.TAG_NAME, "article"):
                page_text = driver.find_element(By.TAG_NAME, "article").text
            else:
                page_text = driver.find_element(By.TAG_NAME, "body").text
        except:
            page_text = ""
        if page_text.strip():
            break
        time.sleep(0.25)

    # Normalize whitespace
    page_text = page_text.replace("\u00A0", " ")
    lines = [ln.strip() for ln in page_text.splitlines() if ln.strip()]

    # Conservative regex to capture lines that look like org names
    # matches lines containing words then a suffix like Limited, Ltd, Pty, Bank, Insurance, Group, PLC, etc.
    suffix_pattern = r"(?:Limited|Ltd|Pty(?:\.?)\s?Ltd|Pty|Bank|Insurance|Trust|Corporation|Corp\.?|PLC|LLP|SE|AG|Company|Co\.?)"
    # capture whole line if it contains at least one capitalized word and a suffix
    pattern = re.compile(rf"^(.{{3,200}}?\b{suffix_pattern}\b.*)$", re.IGNORECASE)

    candidates = []
    for ln in lines:
        m = pattern.search(ln)
        if m:
            cand = normalize_name(m.group(1))
            # filter out very generic nav labels
            if len(cand) > 3 and cand.lower() not in ("home", "registers", "back", "contact"):
                if is_likely_org_name(cand):
                    candidates.append(cand)

    # also a looser approach: find multi-word capitalized lines (min 2 capitalised words)
    if not candidates:
        cap_pattern = re.compile(r"^([A-Z][\w&'\.\-]+(?:\s+[A-Z][\w&'\.\-]+){1,6}.*)$")
        for ln in lines:
            if cap_pattern.match(ln) and len(ln) > 6 and len(ln) < 160:
                cand = normalize_name(ln)
                if len(cand) > 3 and is_likely_org_name(cand):
                    candidates.append(cand)

    # dedupe while preserving order
    seen = set()
    out = []
    for c in candidates:
        if c not in seen:
            out.append(c)
            seen.add(c)

    print(f"[DEBUG] scrape_text_fallback: Found {len(out)} candidate lines (title: {page_title[:60]})")
    print("[DEBUG] sample:", out[:10])
    return page_title, out


# ---------------- Main script ----------------
def main():
    chrome_options = Options()
    # Uncomment the next line to run headless; comment it out to watch browser for debugging
    # chrome_options.add_argument("--headless")
    driver = webdriver.Chrome(options=chrome_options)

    urls = [
        "https://www.apra.gov.au/significant-financial-institutions-register",
        "https://www.apra.gov.au/register-of-authorised-deposit-taking-institutions",
        "https://www.apra.gov.au/register-of-general-insurance",
        "https://www.apra.gov.au/registers-of-life-insurance-companies-and-friendly-societies",
        # "https://www.apra.gov.au/register-of-superannuation-institutions",                        # nothing here
        "https://www.apra.gov.au/list-of-registered-financial-corporations"
    ]

    all_global = []
    for url in urls:
        print("----")
        print(f"[INFO] Visiting {url}")
        try:
            driver.get(url)
        except Exception as e:
            print("[ERROR] Could not load URL:", e)
            continue

        time.sleep(0.8)
        # try dismiss cookie banners
        try_dismiss_cookies(driver)
        # try show-all if present
        click_show_all_if_present(driver)

        page_type = detect_page_type(driver, timeout=10)
        print("[INFO] Detected page type:", page_type)

        # prefer the detected scraper, but fall back through others robustly
        title, names = ("apra_page", [])
        if page_type == "ul":
            title, names = scrape_ul(driver)
        elif page_type == "dropdown":
            title, names, panels_info = scrape_dropdown(driver)
        elif page_type == "table":
            title, names = scrape_table(driver)
        elif page_type == "views":
            title, names = scrape_views(driver)
        else:
            print("[WARN] Unknown page type — trying all strategies as fallback.")

        # fallback cascade if first detected strategy returned nothing
        if not names:
            title, names = scrape_ul(driver)
        if not names:
            title, names, panels_info = scrape_dropdown(driver)
        if not names:
            title, names = scrape_table(driver)
        if not names:
            title, names = scrape_views(driver)
        if not names:
            # FINAL TEXT FALLBACK
            title, names = scrape_text_fallback(driver)

        safe_title = safe_filename(title)
        filename = f"names_{safe_title}.txt"

        # if nothing found, save diagnostics and try a couple more quick attempts
        if not names:
            print(f"[WARN] No names found for page '{title}'. Saving diagnostics for inspection.")
            save_diagnostics(driver, safe_title)
            time.sleep(0.6)
            # quick retry attempts
            t2, n2 = scrape_views(driver)
            if n2:
                title, names = t2, n2
            else:
                t3, n3 = scrape_table(driver, max_wait=3)
                if n3:
                    title, names = t3, n3

        # write per-page file
        with open(filename, "w", encoding="utf-8") as fh:
            for n in names:
                fh.write(n + "\n")
        print(f"[INFO] Saved {len(names)} names to {filename}")

        # accumulate global deduped list
        for n in names:
            if n not in all_global:
                all_global.append(n)

    # write combined CSV
    csv_path = "all_apra_names.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as csvf:
        writer = csv.writer(csvf)
        writer.writerow(["Organisation"])
        for n in all_global:
            writer.writerow([n])
    print(f"[INFO] Wrote combined list: {len(all_global)} unique names -> {csv_path}")

    driver.quit()

if __name__ == "__main__":
    main()
