import re
import hashlib
import requests
import string
import random

# Common weak passwords list
COMMON_PASSWORDS = [
    "password", "123456", "password123", "admin", "letmein",
    "qwerty", "abc123", "monkey", "1234567890", "superman",
    "iloveyou", "sunshine", "princess", "welcome", "shadow"
]

def check_length(password):
    length = len(password)
    if length < 6:
        return 0, "Too short (minimum 6 characters)"
    elif length < 8:
        return 1, "Short (8+ characters recommended)"
    elif length < 12:
        return 2, "Good length"
    else:
        return 3, "Excellent length"

def check_complexity(password):
    score = 0
    feedback = []

    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    if has_upper:
        score += 1
    else:
        feedback.append("Add uppercase letters")

    if has_lower:
        score += 1
    else:
        feedback.append("Add lowercase letters")

    if has_digit:
        score += 1
    else:
        feedback.append("Add numbers")

    if has_special:
        score += 1
    else:
        feedback.append("Add special characters (!@#$...)")

    return score, feedback

def check_uniqueness(password):
    # Check against common passwords
    if password.lower() in COMMON_PASSWORDS:
        return False, "This is a very common password - avoid it!"
    
    # Check for repeated characters
    if len(set(password)) < len(password) * 0.5:
        return False, "Too many repeated characters"
    
    # Check for sequential patterns
    sequences = ["abcdef", "qwerty", "123456", "654321"]
    for seq in sequences:
        if seq in password.lower():
            return False, f"Contains predictable sequence: '{seq}'"
    
    return True, "No common patterns detected"

def check_pwned(password):
    """Check if password has been in a data breach using HaveIBeenPwned API"""
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        if response.status_code == 200:
            hashes = response.text.splitlines()
            for line in hashes:
                h, count = line.split(":")
                if h == suffix:
                    return False, f"Found in {count} data breaches! Change it immediately."
            return True, "Not found in known data breaches"
    except Exception:
        return None, "Could not check breach database (offline)"

def generate_strong_password(length=14):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    while True:
        pwd = ''.join(random.choice(chars) for _ in range(length))
        # Make sure it meets all criteria
        if (re.search(r'[A-Z]', pwd) and re.search(r'[a-z]', pwd)
                and re.search(r'\d', pwd) and re.search(r'[!@#$%^&*()]', pwd)):
            return pwd

def analyze_password(password):
    print("\n" + "="*50)
    print(f"  Analyzing: {'*' * len(password)}")
    print("="*50)

    total_score = 0
    max_score = 11

    # Length check
    len_score, len_msg = check_length(password)
    total_score += len_score
    print(f"\n[Length] Score: {len_score}/3")
    print(f"  → {len_msg}")

    # Complexity check
    comp_score, comp_feedback = check_complexity(password)
    total_score += comp_score
    print(f"\n[Complexity] Score: {comp_score}/4")
    if comp_feedback:
        for tip in comp_feedback:
            print(f"  → {tip}")
    else:
        print("  → All character types present!")

    # Uniqueness check
    is_unique, unique_msg = check_uniqueness(password)
    uniqueness_score = 2 if is_unique else 0
    total_score += uniqueness_score
    print(f"\n[Uniqueness] Score: {uniqueness_score}/2")
    print(f"  → {unique_msg}")

    # Breach check
    print("\n[Breach Check] Checking HaveIBeenPwned...")
    safe, breach_msg = check_pwned(password)
    breach_score = 2 if safe else 0
    if safe is not None:
        total_score += breach_score
    print(f"  → {breach_msg}")

    # Final verdict
    print("\n" + "-"*50)
    percentage = (total_score / max_score) * 100

    if percentage >= 80:
        strength = "STRONG 💪"
    elif percentage >= 60:
        strength = "MODERATE ⚠️"
    elif percentage >= 40:
        strength = "WEAK ❌"
    else:
        strength = "VERY WEAK 🚨"

    print(f"  OVERALL STRENGTH: {strength}")
    print(f"  Score: {total_score}/{max_score} ({percentage:.0f}%)")
    print("="*50)

    if percentage < 80:
        print("\n💡 Suggested Strong Password:")
        print(f"   {generate_strong_password()}")
    
    print()

def main():
    print("\n╔══════════════════════════════╗")
    print("║   Password Strength Analyzer  ║")
    print("╚══════════════════════════════╝")

    while True:
        print("\nOptions:")
        print("  1. Analyze a password")
        print("  2. Generate a strong password")
        print("  3. Exit")

        choice = input("\nEnter choice (1/2/3): ").strip()

        if choice == "1":
            password = input("Enter password to analyze: ")
            if password:
                analyze_password(password)
            else:
                print("No password entered.")

        elif choice == "2":
            length = input("Enter desired length (default 14): ").strip()
            try:
                length = int(length) if length else 14
                if length < 8:
                    print("Minimum length is 8. Setting to 8.")
                    length = 8
            except ValueError:
                length = 14
            print(f"\n Generated Password: {generate_strong_password(length)}")

        elif choice == "3":
            print("Bye!")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
