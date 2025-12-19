"""TP4 - Crazy Decoder (compatible Windows) - Nagib Lakhdari"""

import socket, base64

HOST = "31.220.95.27"
PORT = 13337

# Table Morse
MORSE_CODE = {
    '.-': 'a', '-...': 'b', '-.-.': 'c', '-..': 'd', '.': 'e',
    '..-.': 'f', '--.': 'g', '....': 'h', '..': 'i', '.---': 'j',
    '-.-': 'k', '.-..': 'l', '--': 'm', '-.': 'n', '---': 'o',
    '.--.': 'p', '--.-': 'q', '.-.': 'r', '...': 's', '-': 't',
    '..-': 'u', '...-': 'v', '.--': 'w', '-..-': 'x', '-.--': 'y',
    '--..': 'z', '.----': '1', '..---': '2', '...--': '3',
    '....-': '4', '.....': '5', '-....': '6', '--...': '7',
    '---..': '8', '----.': '9', '-----': '0'
}


def decode_morse(morse):
    """Decode du morse en texte"""

    words = morse.strip().split('   ')  # 3 espaces = séparateur de mots
    result = []
    for word in words:
        letters = word.split(' ')
        decoded_word = ''.join(MORSE_CODE.get(l, '') for l in letters if l)
        result.append(decoded_word)
    return ' '.join(result)


def decode_message(encoded):
    """Decode le message selon son format"""

    encoded = encoded.strip()

    # Detecter morse (contient . et -)
    if all(c in '.- ' for c in encoded) and '.' in encoded: return decode_morse(encoded)

    # On essaie hex
    try:
        if all(c in '0123456789abcdefABCDEF' for c in encoded): return bytes.fromhex(encoded).decode()
    except:
        pass

    # Sinon base64
    try:
        return base64.b64decode(encoded).decode()
    except:
        pass

    return encoded


def recvline(sock):
    """Recoit une ligne jusqu'a \\n"""

    data = b""
    while True:
        chunk = sock.recv(1)
        if not chunk or chunk == b"\n": break
        data += chunk
    return data.decode()


def solve():
    """Resout le challenge Crazy Decoder"""

    print(f"[*] Connexion a {HOST}:{PORT}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((HOST, PORT))

    count = 0
    while True:
        try:
            data = recvline(sock).strip()

            if not data: continue

            # Check flag
            if "FLAG" in data.upper() or "BRAVO" in data.upper():
                print(f"\n{'='*50}")
                print(f"[+] FLAG: {data}")
                print(f"{'='*50}")
                break

            # Ignorer les messages de statut
            if "suivant" in data.lower() or "Au suivant" in data: continue

            # Extraire la partie encodee
            if ":" in data: encoded = data.split(":", 1)[1].strip()
            else: continue  # Pas de challenge valide

            # Decoder
            decoded = decode_message(encoded)

            # Affichage
            print(f"[{count:3d}] {encoded[:40]}... -> {decoded[:30]}...") # Afficher debut seulement via les indexes :40 et :30 parce qu'on est des G00d_Pr0gr4mmer :=)

            # Envoyer
            sock.send(decoded.encode() + b"\n")
            count += 1

        except socket.timeout:
            print("[!] Timeout")
            break
        except Exception as e:
            print(f"[!] Erreur: {e}")
            break

    sock.close()
    print(f"\n[*] {count} messages decodes")


if __name__ == "__main__":
    solve()
