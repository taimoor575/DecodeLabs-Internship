import string
import math


# ─── Common / Leaked Passwords Blocklist ─────────────────────────────────────
COMMON_PASSWORDS = {
    "password", "123456", "password1", "12345678", "qwerty",
    "abc123", "111111", "letmein", "monkey", "dragon",
    "master", "login", "welcome", "admin", "iloveyou",
    "sunshine", "princess", "football", "shadow", "superman",
    "michael", "password123", "123456789", "1234567890",
}

def check_length(password: str) -> bool:
    return len(password) >= 8

def has_uppercase(password: str) -> bool:
    return any(c.isupper() for c in password)

def has_lowercase(password: str) -> bool:
    return any(c.islower() for c in password)

def has_digit(password: str) -> bool:
    return any(c.isdigit() for c in password)

def has_symbol(password: str) -> bool:
    return any(c in string.punctuation for c in password)

def is_leaked(password: str) -> bool:
    return password.lower() in COMMON_PASSWORDS


def calculate_entropy(password: str) -> float:
    """
    Shannon entropy estimate based on character pool size.
    Entropy (bits) = length × log2(pool_size)
    """
    pool = 0
    if has_lowercase(password):  pool += 26
    if has_uppercase(password):  pool += 26
    if has_digit(password):      pool += 10
    if has_symbol(password):     pool += 32   # printable ASCII symbols
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def classify_strength(score: int, entropy: float, leaked: bool) -> tuple[str, str]:
    """
    Returns (strength_label, colour_code).
    Score is 0-5 based on criteria met.
    """
    if leaked:
        return "LEAKED / BLACKLISTED", "\033[91m"   # Red

    if score <= 2 or entropy < 28:
        return "WEAK", "\033[91m"                   # Red
    elif score == 3 or entropy < 50:
        return "MEDIUM", "\033[93m"                 # Yellow
    elif score == 4 or entropy < 70:
        return "STRONG", "\033[92m"                 # Green
    else:
        return "VERY STRONG", "\033[96m"            # Cyan


def analyse_password(password: str) -> dict:
    criteria = {
        "Length ≥ 8"       : check_length(password),
        "Uppercase letter" : has_uppercase(password),
        "Lowercase letter" : has_lowercase(password),
        "Digit (0-9)"      : has_digit(password),
        "Symbol (!@#…)"    : has_symbol(password),
    }

    score   = sum(criteria.values())
    entropy = calculate_entropy(password)
    leaked  = is_leaked(password)
    strength, colour = classify_strength(score, entropy, leaked)

    return {
        "criteria" : criteria,
        "score"    : score,
        "entropy"  : round(entropy, 2),
        "leaked"   : leaked,
        "strength" : strength,
        "colour"   : colour,
    }


RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
DIM    = "\033[2m"

BANNER = f"""{CYAN}{BOLD}
╔══════════════════════════════════════════════════════╗
║       Password Strength Checker                      ║
╚══════════════════════════════════════════════════════╝{RESET}
"""

def print_report(password: str, result: dict) -> None:
    print(f"\n{BOLD}{'─'*54}{RESET}")
    print(f"  Password   : {'*' * len(password)}  ({len(password)} chars)")
    print(f"{'─'*54}")

    
    print(f"\n  {BOLD}Security Criteria:{RESET}")
    for criterion, passed in result["criteria"].items():
        tick  = f"{GREEN}✔{RESET}" if passed else f"{RED}✘{RESET}"
        label = f"{DIM}{criterion}{RESET}"
        print(f"    {tick}  {label}")

 
    entropy = result["entropy"]
    e_colour = GREEN if entropy >= 70 else (YELLOW if entropy >= 40 else RED)
    print(f"\n  {BOLD}Entropy Score:{RESET}  {e_colour}{entropy} bits{RESET}")

    colour   = result["colour"]
    strength = result["strength"]
    score    = result["score"]
    bar_fill = "█" * score + "░" * (5 - score)

    print(f"  {BOLD}Criteria Met:{RESET}   {colour}{score}/5  [{bar_fill}]{RESET}")

    if result["leaked"]:
        print(f"\n  {RED}{BOLD}⚠  PASSWORD FOUND IN BREACH DATABASE — CHANGE IT NOW!{RESET}")

    print(f"\n  {BOLD}Verdict:{RESET}  {colour}{BOLD}{strength}{RESET}")
    print(f"{'─'*54}\n")

    tips = []
    if not result["criteria"]["Length ≥ 8"]:
        tips.append("Use at least 8 characters (12+ recommended).")
    if not result["criteria"]["Uppercase letter"]:
        tips.append("Add uppercase letters (A–Z).")
    if not result["criteria"]["Digit (0-9)"]:
        tips.append("Include at least one number (0–9).")
    if not result["criteria"]["Symbol (!@#…)"]:
        tips.append("Add special symbols like !@#$%^&*.")
    if result["leaked"]:
        tips.append("Never use passwords found in public breach lists.")
    if entropy < 50 and not tips:
        tips.append("Increase password length to boost entropy.")

    if tips:
        print(f"  {BOLD}{YELLOW}💡 Recommendations:{RESET}")
        for tip in tips:
            print(f"    • {tip}")
        print()


def main():
    print(BANNER)
    print(f"  {DIM}Type 'quit' to exit.{RESET}\n")

    while True:
        try:
            password = input(f"  {BOLD}Enter password:{RESET} ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n\n  {CYAN}Session ended. Stay secure!{RESET}\n")
            break

        if password.lower() == "quit":
            print(f"\n  {CYAN}Session ended. Stay secure!{RESET}\n")
            break

        if not password:
            print(f"  {YELLOW}⚠  No input detected. Try again.{RESET}\n")
            continue

        result = analyse_password(password)
        print_report(password, result)


if __name__ == "__main__":
    main()
