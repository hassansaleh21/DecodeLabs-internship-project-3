

import re
from urllib.parse import urlparse


messages = [
    """
    Dear User,

    Your bank account has been suspended.
    Click here immediately to verify your account:
    http://secure-bank-login.xyz

    Failure to act within 24 hours will permanently lock your account.

    Regards,
    Bank Security Team
    """,

    """
    Congratulations!

    You have won a FREE iPhone 15.
    Claim your reward now at:
    http://free-gift-prize.ru

    Hurry! Limited time offer.
    """,

    """
    Hello Employee,

    Please review the attached company meeting schedule.
    https://company-portal.com/meeting

    Regards,
    HR Department
    """
]


suspicious_keywords = [
    "urgent",
    "verify",
    "suspended",
    "click here",
    "winner",
    "free",
    "claim",
    "password",
    "limited time",
    "account locked",
    "bank account"
]


def extract_urls(text):
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, text)


def analyze_message(message):
    red_flags = []

   
    lower_msg = message.lower()

  
    for keyword in suspicious_keywords:
        if keyword in lower_msg:
            red_flags.append(f"Suspicious keyword found: '{keyword}'")

    
    urls = extract_urls(message)

    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc

       
        suspicious_domains = [".xyz", ".ru", ".tk"]

        if any(domain.endswith(ext) for ext in suspicious_domains):
            red_flags.append(f"Suspicious domain detected: {domain}")

      
        if parsed.scheme == "http":
            red_flags.append(f"Insecure link (HTTP): {url}")

    
    print("=" * 60)
    print("MESSAGE:")
    print(message.strip())

    print("\nANALYSIS RESULT:")

    if red_flags:
        print("⚠ Potential Phishing Attempt Detected!")
        print("\nRed Flags:")
        for flag in red_flags:
            print("-", flag)

        print("\nWhy This Message is Unsafe:")
        print("- It contains suspicious words designed to create panic or urgency.")
        print("- The links may redirect users to fake websites.")
        print("- Attackers may steal personal or banking information.")
    else:
        print("✅ This message appears safe.")

    print("=" * 60)
    print("\n")



for msg in messages:
    analyze_message(msg)
