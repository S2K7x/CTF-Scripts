import random
import string
import os
from datetime import datetime
import json

# --- Configuration et Dictionnaires ---

SEPARATORS = ["", ".", "_", "-", "__"]
SPECIAL_CHARS = ["!", "x", "X", "0", "~", "*", "+", "="]

# Dictionnaire pour le remplacement des caractères (Leet Speak)
LEET_DICT = {
    'a': ['4', '@', 'A', '1'], 
    'e': ['3', 'E'], 
    'i': ['1', '!', 'I', 'x'],
    'o': ['0', 'O'], 
    's': ['5', '$', 'S'], 
    't': ['7', 'T'],
    'l': ['1', 'L'], 
    'g': ['9', 'G'], 
    'b': ['8', 'B']
}

# Listes de mots pour l'enrichissement des pseudonymes
PREFIXES = ["the", "real", "official", "true", "pro", "elite", "dark", "ghost", "cyber", "alpha", "beta", "omega", "just", "its"]
SUFFIXES = ["gg", "tv", "yt", "ttv", "live", "gaming", "pro", "official", "hd", "4k", "og", "og_", "spam", "priv"]
COMMON_WORDS = ["gamer", "streamer", "player", "king", "queen", "master", "lord", "boss", "legend", "god", "vibes", "chill"]

# Configuration par défaut des plateformes populaires
PLATFORM_PATTERNS = {
    "twitter": {"max_length": 15, "allow_dot": False, "preferred_sep": "_"},
    "instagram": {"max_length": 30, "allow_dot": True, "preferred_sep": "."},
    "tiktok": {"max_length": 24, "allow_dot": True, "preferred_sep": "_"},
    "youtube": {"max_length": 30, "allow_dot": False, "preferred_sep": ""},
    "twitch": {"max_length": 25, "allow_dot": False, "preferred_sep": "_"},
    "discord": {"max_length": 32, "allow_dot": True, "preferred_sep": "."},
    "generic": {"max_length": 20, "allow_dot": True, "preferred_sep": "_"}
}

def print_banner():
    """Affiche l'en-tête de l'application GhostName."""
    os.system('cls' if os.name == 'nt' else 'clear')
    print("=" * 64)
    print("  GHOSTNAME v3.3 | Système de Génération d'Identités Numériques")
    print("  Protection de la vie privée & Brouillage OSINT")
    print("=" * 64)

def create_typo(word):
    """Génère une inversion de lettres pour simuler une faute de frappe."""
    if len(word) < 4:
        return word
    idx = random.randint(1, len(word) - 3)
    word_list = list(word)
    word_list[idx], word_list[idx+1] = word_list[idx+1], word_list[idx]
    return "".join(word_list)

def get_consonants(word):
    """Extrait les consonnes d'une chaîne de caractères."""
    return "".join([c for c in word.lower() if c in "bcdfghjklmnpqrstvwxz"])

def apply_substitution(word, target_char='a', sub_char='x'):
    """Remplace une lettre spécifique par un caractère de substitution."""
    if target_char in word.lower():
        return word.lower().replace(target_char, sub_char)
    return word

def generate_variants(word, use_typos=True):
    """Génère des variantes simplifiées basées sur un mot source."""
    if not word:
        return [""]
    
    word = word.lower()
    variants = {word}
    
    variants.add(word[0])
    if len(word) > 2: variants.add(word[:2])
    if len(word) > 3: variants.add(word[:3])
    
    cons = get_consonants(word)
    if cons: variants.add(cons)
    
    if use_typos and len(word) > 3:
        variants.add(create_typo(word))
    
    return list(variants)

def apply_leet(text, intensity=0.3):
    """Applique des transformations Leet Speak de manière aléatoire."""
    if not text: return text
    result = ""
    for char in text.lower():
        if char in LEET_DICT and random.random() < intensity:
            result += random.choice(LEET_DICT[char])
        else:
            result += char
    return result

def get_random_noise():
    """Génère un suffixe ou préfixe aléatoire (chiffres/caractères)."""
    options = [
        str(random.randint(0, 99)),
        random.choice(SPECIAL_CHARS),
        "".join(random.choices(string.digits, k=2)),
        "x" + str(random.randint(0, 9)),
    ]
    return random.choice(options)

def apply_case_variation(text):
    """Applique des changements de casse pour varier le style visuel."""
    variations = [
        text.lower(), text.upper(), text.lower(),
        "".join([c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(text)]),
        text[0].upper() + text[1:].lower() if len(text) > 1 else text.upper()
    ]
    return random.choice(variations)

def generate_username(first_name, last_name, pseudo_habituel, 
                      decoy_words=None, decoy_number=None, 
                      platform="generic", leet_level=1, noise_level=1,
                      min_length=0, max_length_override=None, forbidden_chars="",
                      require_number=False, require_special=False):
    """Logique principale de génération combinant plusieurs stratégies d'anonymisation."""
    
    platform_config = PLATFORM_PATTERNS.get(platform, PLATFORM_PATTERNS["generic"])
    sep = platform_config["preferred_sep"] if random.random() > 0.3 else random.choice(SEPARATORS)
    if not platform_config["allow_dot"] and sep == ".": sep = "_"

    first = first_name.lower() if first_name else ""
    last = last_name.lower() if last_name else ""
    psd = pseudo_habituel.lower() if pseudo_habituel else ""
    num = str(decoy_number) if decoy_number else ""

    strategies = []
    
    # Stratégie 1 : Combinaisons classiques (ex: j.doe, john_d)
    f_vars = generate_variants(first)
    l_vars = generate_variants(last)
    p_vars = generate_variants(psd)
    comp = [c for c in [random.choice(f_vars), random.choice(l_vars), random.choice(p_vars)] if c]
    if comp: strategies.append(sep.join(random.sample(comp, min(len(comp), 2))))

    # Stratégie 2 : Initiales + Séquence numérique (ex: J1D0)
    if first and last and num:
        if len(num) >= 2:
            strategies.append(f"{first[0]}{num[0]}{last[0]}{num[1:]}")
            strategies.append(f"{num}{first[0]}{last[0]}")
        else:
            strategies.append(f"{first[0]}{num}{last[0]}")

    # Stratégie 3 : Substitution et Compression (ex: jxm_doe)
    if first:
        sub_name = apply_substitution(first, 'a', 'x')
        sub_name = apply_substitution(sub_name, 'i', '1')
        if last:
            strategies.append(f"{sub_name}{get_consonants(last)}")
        else:
            strategies.append(f"{sub_name}{get_random_noise()}")

    # Stratégie 4 : Leet Speak Ciblé (ex: j0hn_d03)
    if first and last:
        full = first + last
        strategies.append(apply_leet(full, intensity=0.5))
    elif psd:
        strategies.append(apply_leet(psd, intensity=0.5))

    # Base finale du pseudonyme
    base_name = random.choice(strategies) if strategies else "user_" + get_random_noise()
    
    # Ajout de bruit si le niveau est élevé
    if noise_level > 1 and random.random() > 0.5:
        noise = get_random_noise()
        base_name = f"{base_name}{noise}" if random.random() > 0.5 else f"{noise}{base_name}"

    # --- Nettoyage et Validation des Contraintes ---
    if forbidden_chars:
        for c in forbidden_chars: base_name = base_name.replace(c, "")
            
    if require_number and not any(c.isdigit() for c in base_name):
        base_name += str(random.randint(0, 9))
        
    if require_special:
        allowed_specials = [c for c in SPECIAL_CHARS if c not in forbidden_chars]
        if allowed_specials and not any(c in allowed_specials for c in base_name):
            base_name += random.choice(allowed_specials)
            
    while len(base_name) < min_length:
        base_name += random.choice(string.ascii_lowercase)
            
    max_l = max_length_override if max_length_override else platform_config["max_length"]
    if len(base_name) > max_l: base_name = base_name[:max_l]

    return base_name

def generate_poison_bio(decoy_city, decoy_hobbies, decoy_pet):
    """Génère une biographie de profil pour renforcer le leurre OSINT."""
    bios = [
        f"Basé à {decoy_city or 'Paris'}. Passionné par {decoy_hobbies[0] if decoy_hobbies else 'le développement'}.",
        f"📍 {decoy_city or 'Lyon'} | {', '.join(decoy_hobbies[:2]) if decoy_hobbies else 'Tech & Design'}. Fan de {decoy_pet or 'nature'}.",
        f"Amateur de {decoy_hobbies[0] if decoy_hobbies else 'photographie'} situé en {decoy_city or 'Europe'}.",
    ]
    return random.choice(bios)

def export_results(usernames, metadata, poison_bio, filename, format_json=False):
    """Enregistre les pseudonymes générés dans un fichier externe."""
    if format_json:
        data = {"metadata": metadata, "bio_suggestion": poison_bio, "usernames": list(usernames), "generated_at": datetime.now().isoformat()}
        with open(filename, 'w', encoding='utf-8') as f: json.dump(data, f, ensure_ascii=False, indent=2)
    else:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"--- GHOSTNAME EXPORT - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n\n")
            if poison_bio: f.write(f"BIO SUGGÉRÉE: {poison_bio}\n\n")
            for u in usernames: f.write(f"{u}\n")
    print(f"\n[OK] Fichier enregistré sous : {filename}")

def main():
    """Point d'entrée principal de l'interface interactive."""
    print_banner()
    
    print("\n[1] IDENTITÉ À PROTÉGER")
    first_name = input(" > Prénom : ").strip()
    last_name = input(" > Nom : ").strip()
    pseudo = input(" > Pseudo habituel (optionnel) : ").strip()
    
    print("\n[2] ÉLÉMENTS DE LEURRE")
    decoy_city = input(" > Ville leurre : ").strip()
    decoy_hobbies_input = input(" > Centres d'intérêt (virgules) : ").strip()
    decoy_number = input(" > Nombre ou année de référence : ").strip()
    
    print("\n[3] CONTRAINTES DU SITE")
    min_length = int(input(" > Longueur min. [0] : ") or 0)
    max_length = int(input(" > Longueur max. [20] : ") or 20)
    forbidden = input(" > Caractères interdits : ").strip()
    req_num = input(" > Chiffre obligatoire ? (o/n) : ").lower() == 'o'
    req_spec = input(" > Caractère spécial obligatoire ? (o/n) : ").lower() == 'o'

    print("\n[4] PLATEFORME CIBLE")
    platforms = list(PLATFORM_PATTERNS.keys())
    for i, p in enumerate(platforms, 1): print(f"    {i}. {p}")
    p_choice = input(" > Sélection : ").strip()
    platform = platforms[int(p_choice)-1] if p_choice.isdigit() and int(p_choice) <= len(platforms) else "generic"
    
    count = int(input("\n[5] NOMBRE DE RÉSULTATS [50] : ") or 50)
    
    # Processus de génération
    usernames = set()
    attempts = 0
    while len(usernames) < count and attempts < count * 20:
        usernames.add(generate_username(first_name, last_name, pseudo, 
                                        decoy_hobbies_input.split(','), decoy_number, 
                                        platform, 1, 1, min_length, max_length, 
                                        forbidden, req_num, req_spec))
        attempts += 1
    
    bio = generate_poison_bio(decoy_city, decoy_hobbies_input.split(','), None)
    
    # Affichage des résultats avec un design épuré
    print("\n" + "=" * 64)
    if bio: print(f" BIO SUGGÉRÉE : {bio}\n")
    print(f" LISTE DES {len(usernames)} PSEUDONYMES GÉNÉRÉS :")
    print("-" * 64)
    
    # Affichage en colonnes pour la lisibilité
    list_usernames = list(usernames)
    for i in range(0, len(list_usernames), 2):
        col1 = list_usernames[i]
        col2 = list_usernames[i+1] if i+1 < len(list_usernames) else ""
        print(f" {i+1:2d}. {col1:<28} {i+2:2d}. {col2}")
        
    print("-" * 64)
    
    if input("\nSouhaitez-vous exporter ces résultats ? (o/n) : ").lower() == 'o':
        export_results(usernames, {}, bio, "pseudos_export.txt")

    print("\nFin de session GhostName. Restez vigilant.")

if __name__ == "__main__":
    try: 
        main()
    except KeyboardInterrupt: 
        print("\n\n[!] Session interrompue par l'utilisateur.")
    except Exception as e: 
        print(f"\n[ERREUR] Une erreur est survenue : {e}")