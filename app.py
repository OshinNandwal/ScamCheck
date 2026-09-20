import streamlit as st
import re
import json
import os
import datetime
from html import escape
from io import BytesIO
from collections import Counter

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="ScamCheck",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    .main-title {
        font-size: 46px;
        font-weight: 800;
        text-align: center;
        margin-bottom: 5px;
    }

    .subtitle {
        text-align: center;
        color: #6b7280;
        font-size: 17px;
        margin-bottom: 25px;
    }

    .section-title {
        font-size: 25px;
        font-weight: 750;
        margin-top: 25px;
        margin-bottom: 12px;
    }

    .risk-card {
        padding: 22px;
        border-radius: 16px;
        margin: 12px 0;
        border: 1px solid #e5e7eb;
        background: #ffffff;
        box-shadow: 0 4px 14px rgba(0,0,0,0.06);
        text-align: center;
    }

    .risk-number {
        font-size: 40px;
        font-weight: 800;
        margin: 5px 0;
    }

    .category-card {
        padding: 18px;
        border-radius: 14px;
        background: #f8fafc;
        border: 1px solid #e5e7eb;
        margin-bottom: 10px;
    }

    .category-name {
        font-size: 22px;
        font-weight: 750;
    }

    .category-score {
        font-size: 16px;
        color: #4b5563;
    }

    .evidence-box {
        padding: 18px;
        border-radius: 14px;
        background: #f8fafc;
        border-left: 5px solid #64748b;
        margin: 10px 0;
    }

    .dashboard-label {
        font-size: 13px;
        font-weight: 700;
        color: #6b7280;
        letter-spacing: 0.5px;
    }

    .dashboard-number {
        font-size: 32px;
        font-weight: 800;
        margin: 3px 0;
    }

    .metric-card {
        padding: 18px;
        border-radius: 14px;
        border: 1px solid #e5e7eb;
        background: #ffffff;
        text-align: center;
        min-height: 120px;
    }

    .small-muted {
        color: #6b7280;
        font-size: 14px;
    }

    .warning-box {
        padding: 16px;
        border-radius: 12px;
        background: #fff7ed;
        border: 1px solid #fed7aa;
    }

    .success-box {
        padding: 16px;
        border-radius: 12px;
        background: #f0fdf4;
        border: 1px solid #bbf7d0;
    }

    .info-box {
        padding: 16px;
        border-radius: 12px;
        background: #eff6ff;
        border: 1px solid #bfdbfe;
    }

    .history-item {
        padding: 14px;
        border-radius: 12px;
        border: 1px solid #e5e7eb;
        margin-bottom: 8px;
        background: #fafafa;
    }

    .footer {
        text-align: center;
        color: #6b7280;
        margin-top: 35px;
        padding: 20px;
        font-size: 14px;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# CONSTANTS
# ============================================================

HISTORY_FILE = "scan_history.json"


# ============================================================
# HISTORY FUNCTIONS
# ============================================================

def normalize_history_item(item):
    """Convert old and new history records into one consistent format."""

    if not isinstance(item, dict):
        return None

    normalized = dict(item)

    normalized["timestamp"] = item.get(
        "timestamp",
        item.get("scan_time", "Unknown time")
    )

    normalized["classification"] = item.get(
        "classification",
        item.get("category", "⚠️ Suspicious Activity")
    )

    try:
        normalized["risk_score"] = int(item.get("risk_score", 0))
    except (TypeError, ValueError):
        normalized["risk_score"] = 0

    try:
        normalized["confidence"] = int(item.get("confidence", 0))
    except (TypeError, ValueError):
        normalized["confidence"] = 0

    risk_level = item.get("risk_level", "")

    if not risk_level:
        score = normalized["risk_score"]

        if score >= 70:
            risk_level = "🔴 HIGH"
        elif score >= 40:
            risk_level = "🟠 MEDIUM"
        else:
            risk_level = "🟢 LOW"

    normalized["risk_level"] = risk_level

    indicators = item.get("indicators", [])

    if not isinstance(indicators, list):
        indicators = [str(indicators)] if indicators else []

    normalized["indicators"] = indicators

    if isinstance(item.get("report"), dict):
        normalized["report"] = item["report"]

    return normalized


def load_scan_history():

    if not os.path.exists(HISTORY_FILE):
        return []

    try:

        with open(
            HISTORY_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        if not isinstance(data, list):
            return []

        normalized_history = []

        for item in data:

            normalized_item = normalize_history_item(item)

            if normalized_item:
                normalized_history.append(
                    normalized_item
                )

        return normalized_history[:50]

    except Exception:
        return []


def save_scan_history(history):

    try:

        normalized_history = []

        for item in history:

            normalized_item = normalize_history_item(item)

            if normalized_item:
                normalized_history.append(
                    normalized_item
                )

        with open(
            HISTORY_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                normalized_history[:50],
                file,
                indent=2,
                ensure_ascii=False
            )

    except Exception:
        pass


def clear_saved_history():

    try:

        if os.path.exists(HISTORY_FILE):
            os.remove(HISTORY_FILE)

    except Exception:
        pass


# ============================================================
# SESSION STATE
# ============================================================

if "scan_history" not in st.session_state:
    st.session_state.scan_history = load_scan_history()

if "latest_report" not in st.session_state:
    st.session_state.latest_report = None


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def contains_any(text, words):

    for word in words:

        word = word.lower().strip()

        if not word:
            continue

        if (
            " " in word
            or any(character in word for character in "₹-%")
        ):

            if word in text:
                return True

        else:

            if re.search(
                r"\b" + re.escape(word) + r"\b",
                text
            ):
                return True

    return False


def unique_list(items):

    result = []

    for item in items:

        if item not in result:
            result.append(item)

    return result


# ============================================================
# MAIN ANALYSIS ENGINE
# ============================================================

def analyze_message(text):

    lower = text.lower().strip()

    indicators = []
    smart_intents = []
    advanced_patterns = []
    suspicious_phrases = []
    risk_breakdown = []

    category_scores = {}

    total_signal_points = 0

    def add_signal(label, points):

        nonlocal total_signal_points

        risk_breakdown.append(
            {
                "signal": label,
                "points": points
            }
        )

        total_signal_points += points


    # ========================================================
    # DETECTION DICTIONARIES
    # ========================================================

    # Step 38:
    # Removed generic "now" and standalone "today".
    urgency_words = [
        "urgent",
        "immediately",
        "immediate",
        "act now",
        "verify now",
        "respond now",
        "pay now",
        "do it now",
        "limited time",
        "expires today",
        "within 24 hours",
        "last chance",
        "hurry",
        "as soon as possible",
        "final notice",
    ]

    money_words = [
        "₹",
        "rs",
        "rupees",
        "money",
        "payment",
        "pay",
        "fee",
        "deposit",
        "charge",
        "cash",
        "amount",
        "transfer",
        "refund",
        "registration fee",
        "joining fee",
        "application fee",
        "processing fee",
        "security deposit",
    ]

    job_words = [
        "job",
        "work from home",
        "work-from-home",
        "employment",
        "hiring",
        "vacancy",
        "salary",
        "earn",
        "earning",
        "recruitment",
        "recruit",
        "career opportunity",
        "selected for a job",
        "no experience required",
        "part time job",
        "part-time job",
        "full time job",
        "work opportunity",
        "data analyst position",
        "application for the",
    ]

    banking_words = [
        "bank",
        "banking",
        "account",
        "debit card",
        "credit card",
        "credit",
        "debit",
        "kyc",
        "transaction",
        "blocked",
        "suspended",
        "bank account",
        "verify your account",
        "account verification",
        "net banking",
        "bank statement",
        "monthly statement",
        "transaction history",
    ]

    otp_words = [
        "otp",
        "one time password",
        "one-time password",
        "verification code",
        "security code",
        "login code",
        "verification otp",
    ]

    sensitive_words = [
        "password",
        "otp",
        "pin",
        "cvv",
        "card number",
        "bank details",
        "account number",
        "login",
        "username",
        "aadhaar",
        "pan",
        "verification code",
        "security code",
    ]

    investment_words = [
        "investment",
        "invest",
        "trading",
        "crypto",
        "cryptocurrency",
        "stock",
        "forex",
        "returns",
        "profit",
        "guaranteed return",
        "double your money",
        "double money",
        "high return",
        "guaranteed profit",
    ]

    delivery_words = [
        "parcel",
        "package",
        "courier",
        "delivery",
        "shipment",
        "customs",
        "tracking",
        "delivery attempt",
        "delivery address",
    ]

    tech_support_words = [
        "virus",
        "malware",
        "computer infected",
        "device infected",
        "technical support",
        "tech support",
        "microsoft support",
        "security support",
        "remote access",
        "remote desktop",
        "anydesk",
        "teamviewer",
    ]

    organization_words = [
        "government",
        "police",
        "income tax",
        "bank",
        "amazon",
        "google",
        "microsoft",
        "apple",
        "flipkart",
        "paytm",
        "phonepe",
        "sbi",
        "hdfc",
        "icici",
    ]

    secrecy_words = [
        "keep this secret",
        "don't tell anyone",
        "do not tell anyone",
        "keep it private",
        "confidential",
        "secret",
    ]

    threat_words = [
        "account will be blocked",
        "account will be suspended",
        "legal action",
        "police action",
        "arrest",
        "penalty",
        "fine",
        "case will be filed",
        "service will be terminated",
        "account may be blocked",
    ]

    click_words = [
        "click here",
        "click the link",
        "tap here",
        "open this link",
        "visit this link",
        "follow the link",
        "verify here",
    ]

    alternative_payment_words = [
        "upi",
        "upi id",
        "qr code",
        "gift card",
        "voucher",
        "crypto payment",
        "bitcoin",
        "usdt",
    ]


    # ========================================================
    # STEP 38 — LEGITIMATE / NEUTRAL CONTEXT
    # ========================================================

    legitimate_context_words = [
        "application received",
        "application has been received",
        "successfully received",
        "recruitment team will review",
        "will review your application",
        "shortlisted candidates",
        "check your application status",
        "check application status",
        "official careers portal",
        "company's official careers portal",
        "company official careers portal",
        "statement is now available",
        "monthly bank statement",
        "monthly statement",
        "download your statement",
        "transaction history",
        "review your transactions",
        "secure mobile banking app",
        "official app",
        "official website",
        "recruitment team",
        "contact shortlisted candidates",
        "application status",
        "received successfully",
    ]

    found_legitimate_context = contains_any(
        lower,
        legitimate_context_words
    )

    # Strong legitimate signals are used to suppress weak
    # category detections, but NOT strong scam combinations.
    benign_strength = 0

    if found_legitimate_context:
        benign_strength = sum(
            1
            for phrase in legitimate_context_words
            if phrase in lower
        )


    # ========================================================
    # STEP 36 — FALSE POSITIVE REDUCTION
    # ========================================================

    strong_prize_words = [
        "you won",
        "winner",
        "lottery",
        "jackpot",
        "prize",
        "lucky winner",
        "claim your reward",
        "claim the prize",
        "cash prize",
        "lottery prize",
        "reward amount",
    ]

    weak_reward_words = [
        "congratulations",
        "reward",
    ]


    # ========================================================
    # BASIC DETECTION
    # ========================================================

    found_urgency = contains_any(
        lower,
        urgency_words
    )

    # Threat + deadline context can still create urgency.
    if found_threat := contains_any(
        lower,
        threat_words
    ):
        if contains_any(
            lower,
            [
                "today",
                "within",
                "immediately",
                "now",
                "deadline",
                "before",
            ]
        ):
            found_urgency = True

    found_money = contains_any(
        lower,
        money_words
    )

    found_job = contains_any(
        lower,
        job_words
    )

    found_banking = contains_any(
        lower,
        banking_words
    )

    found_otp = contains_any(
        lower,
        otp_words
    )

    found_sensitive = contains_any(
        lower,
        sensitive_words
    )

    found_investment = contains_any(
        lower,
        investment_words
    )

    found_delivery = contains_any(
        lower,
        delivery_words
    )

    found_tech = contains_any(
        lower,
        tech_support_words
    )

    found_organization = contains_any(
        lower,
        organization_words
    )

    found_secrecy = contains_any(
        lower,
        secrecy_words
    )

    found_click = contains_any(
        lower,
        click_words
    )

    found_alt_payment = contains_any(
        lower,
        alternative_payment_words
    )


    # ========================================================
    # URL / EMAIL / PHONE DETECTION
    # ========================================================

    urls = re.findall(
        r"(?:https?://|www\.)[^\s]+",
        text,
        flags=re.IGNORECASE
    )

    emails = re.findall(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        text
    )

    phones = re.findall(
        r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)",
        text
    )


    suspicious_url = False
    url_reasons = []

    for url in urls:

        clean_url = url.rstrip(
            ".,!?;:)"
        )

        url_lower = clean_url.lower()

        if any(
            domain in url_lower
            for domain in [
                "bit.ly",
                "tinyurl",
                "t.co",
                "goo.gl",
                "is.gd",
                "cutt.ly",
            ]
        ):

            suspicious_url = True

            url_reasons.append(
                "URL shortener detected."
            )

        if re.search(
            r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
            url_lower
        ):

            suspicious_url = True

            url_reasons.append(
                "IP-address based URL detected."
            )

        if any(
            word in url_lower
            for word in [
                "verify",
                "login",
                "secure",
                "update",
                "account",
                "claim",
                "reward",
            ]
        ):

            suspicious_url = True

            url_reasons.append(
                "URL contains a potentially sensitive action keyword."
            )


    # ========================================================
    # STRONG SCAM SIGNALS
    # ========================================================

    strong_job_scam_signal = (
        found_money
        or found_urgency
        or contains_any(
            lower,
            [
                "no interview",
                "without interview",
                "guaranteed salary",
                "guaranteed income",
                "guaranteed earning",
                "earn ₹",
                "earn rs",
                "earn rupees",
                "pay to confirm",
                "registration fee",
                "joining fee",
                "application fee",
                "security deposit",
                "selected immediately",
                "limited vacancies",
            ]
        )
        or suspicious_url
        or found_sensitive
        or (
            found_job
            and found_alt_payment
        )
    )

    strong_banking_scam_signal = (
        found_otp
        or found_sensitive
        or found_urgency
        or found_threat
        or suspicious_url
        or (
            found_money
            and (
                "bank" in lower
                or "account" in lower
            )
        )
        or contains_any(
            lower,
            [
                "verify your account",
                "account verification",
                "enter your details",
                "update your kyc",
                "confirm your identity",
                "card will be blocked",
                "account will be blocked",
                "account will be suspended",
            ]
        )
    )

    strong_otp_signal = (
        found_otp
        and (
            found_sensitive
            or found_banking
            or found_urgency
            or found_click
            or suspicious_url
        )
    )

    strong_phishing_signal = (
        urls
        and (
            suspicious_url
            or found_sensitive
            or found_click
            or found_organization
        )
    )

    strong_payment_signal = (
        found_money
        and (
            found_urgency
            or found_job
            or found_banking
            or found_investment
            or found_delivery
            or found_alt_payment
            or found_sensitive
            or found_threat
            or suspicious_url
        )
    )


    # ========================================================
    # CONTEXT-AWARE PRIZE DETECTION
    # ========================================================

    found_strong_prize = contains_any(
        lower,
        strong_prize_words
    )

    found_weak_reward = contains_any(
        lower,
        weak_reward_words
    )

    found_prize = (
        found_strong_prize
        or (
            found_weak_reward
            and (
                found_money
                or found_urgency
                or contains_any(
                    lower,
                    [
                        "claim",
                        "won",
                        "winner",
                        "lottery",
                        "jackpot",
                    ]
                )
            )
        )
    )


    job_context = (
        found_job
        and (
            found_money
            or contains_any(
                lower,
                [
                    "registration fee",
                    "joining fee",
                    "application fee",
                    "deposit",
                ]
            )
        )
    )

    if job_context and not found_strong_prize:
        found_prize = False


    # ========================================================
    # LEGITIMATE CONTEXT SUPPRESSION
    # ========================================================

    legitimate_job_message = (
        found_legitimate_context
        and found_job
        and not strong_job_scam_signal
    )

    legitimate_banking_message = (
        found_legitimate_context
        and found_banking
        and not strong_banking_scam_signal
    )

    legitimate_neutral_message = (
        found_legitimate_context
        and not (
            strong_job_scam_signal
            or strong_banking_scam_signal
            or strong_otp_signal
            or strong_phishing_signal
            or strong_payment_signal
            or found_threat
            or found_prize
            or found_investment
            or found_delivery
            or found_tech
        )
    )


    # ========================================================
    # INDICATORS
    # ========================================================

    if found_urgency:

        indicators.append(
            "Urgent or pressure-based language detected"
        )

        add_signal(
            "Urgency / Pressure",
            15
        )

        smart_intents.append(
            "🧠 Psychological Manipulation"
        )


    if found_money:

        indicators.append(
            "Money or payment-related language detected"
        )

        # Weak informational financial language gets less weight
        # when legitimate context is clearly present.
        if (
            found_legitimate_context
            and not strong_payment_signal
        ):
            add_signal(
                "Financial Language",
                5
            )
        else:
            add_signal(
                "Financial Request",
                20
            )


    if found_click:

        indicators.append(
            "Message asks the user to follow a link"
        )

        add_signal(
            "Suspicious Link Instruction",
            10
        )

        smart_intents.append(
            "🖱️ Suspicious Link Instruction"
        )


    if found_job:

        indicators.append(
            "Job or employment-related language detected"
        )

        if legitimate_job_message:

            add_signal(
                "Employment Context",
                0
            )

        else:

            add_signal(
                "Job Scam Indicators",
                20
            )

            smart_intents.append(
                "💼 Employment / Job Fraud"
            )


    if found_prize:

        indicators.append(
            "Prize or reward language detected"
        )

        add_signal(
            "Prize / Reward",
            20
        )

        smart_intents.append(
            "🎁 Fake Prize / Reward Claim"
        )


    if found_otp:

        indicators.append(
            "OTP or verification-code language detected"
        )

        add_signal(
            "OTP / Verification Request",
            20
        )

        smart_intents.append(
            "🔐 Account Verification Attempt"
        )


    if found_sensitive:

        indicators.append(
            "Sensitive information request detected"
        )

        add_signal(
            "Sensitive Information Request",
            20
        )


    if found_banking:

        indicators.append(
            "Banking or account-related language detected"
        )

        if legitimate_banking_message:

            add_signal(
                "Banking Context",
                0
            )

        else:

            add_signal(
                "Banking Language",
                15
            )


    if found_investment:

        indicators.append(
            "Investment or financial-return language detected"
        )

        add_signal(
            "Investment Language",
            15
        )


    if found_delivery:

        indicators.append(
            "Delivery or parcel-related language detected"
        )

        add_signal(
            "Delivery Language",
            10
        )


    if found_tech:

        indicators.append(
            "Technical-support or device-security language detected"
        )

        add_signal(
            "Tech Support Language",
            15
        )


    if suspicious_url:

        indicators.append(
            "Potentially suspicious URL characteristics detected"
        )

        add_signal(
            "Suspicious URL Characteristics",
            20
        )


    if found_alt_payment:

        indicators.append(
            "Alternative payment method detected"
        )

        add_signal(
            "Alternative Payment Method",
            15
        )


    # ========================================================
    # COMBINATION SIGNALS
    # ========================================================

    if found_urgency and found_money:

        indicators.append(
            "Urgency combined with a financial request"
        )

        add_signal(
            "Urgency + Financial Request",
            10
        )

        advanced_patterns.append(
            "🚨 Urgent Money Extraction Pattern"
        )


    if found_prize and found_money:

        indicators.append(
            "Prize/reward language combined with money"
        )

        add_signal(
            "Prize + Money",
            10
        )

        advanced_patterns.append(
            "🎁 Prize + Payment Scam Pattern"
        )


    if found_job and found_money:

        indicators.append(
            "Job opportunity combined with financial request"
        )

        add_signal(
            "Job + Money",
            10
        )

        advanced_patterns.append(
            "💼 Job + Payment Scam Pattern"
        )


    if job_context:

        advanced_patterns.append(
            "💰 Upfront Job Fee Pattern"
        )


    if found_banking and found_sensitive:

        indicators.append(
            "Banking language combined with sensitive information request"
        )

        add_signal(
            "Banking + Sensitive Information",
            15
        )

        advanced_patterns.append(
            "🏦 Banking Credential Theft Pattern"
        )


    if found_otp and found_sensitive:

        add_signal(
            "OTP + Sensitive Information",
            15
        )

        advanced_patterns.append(
            "🔐 OTP Credential Theft Pattern"
        )


    if found_investment and found_money:

        add_signal(
            "Investment + Financial Request",
            15
        )

        advanced_patterns.append(
            "📈 Investment Payment Pattern"
        )


    if found_delivery and found_money:

        add_signal(
            "Delivery + Payment",
            10
        )

        advanced_patterns.append(
            "📦 Delivery Payment Scam Pattern"
        )


    if found_tech and (
        found_sensitive
        or found_click
    ):

        add_signal(
            "Tech Support + Sensitive Action",
            10
        )

        advanced_patterns.append(
            "💻 Fake Technical Support Pattern"
        )


    if found_secrecy:

        indicators.append(
            "Secrecy or isolation language detected"
        )

        add_signal(
            "Secrecy / Isolation",
            10
        )


    if found_threat:

        indicators.append(
            "Threatening or intimidating language detected"
        )

        add_signal(
            "Threat / Intimidation",
            15
        )


    # ========================================================
    # CATEGORY SCORES — STEP 38 GATED
    # ========================================================

    # --------------------------------------------------------
    # JOB
    # --------------------------------------------------------

    if found_job and strong_job_scam_signal:

        category_scores["💼 Job Scam"] = (
            8 if found_money else 6
        )


    # --------------------------------------------------------
    # PAYMENT / UPI
    # --------------------------------------------------------

    if strong_payment_signal:

        category_scores["💳 Payment / UPI Scam"] = 5


    # --------------------------------------------------------
    # PHISHING
    # --------------------------------------------------------

    if strong_phishing_signal:

        category_scores["🎣 Phishing Scam"] = 7


    # --------------------------------------------------------
    # LOTTERY / REWARD
    # --------------------------------------------------------

    if (
        found_strong_prize
        and (
            found_money
            or found_urgency
            or suspicious_url
        )
    ):

        category_scores[
            "🎁 Lottery / Reward Scam"
        ] = 9


    # --------------------------------------------------------
    # BANKING
    # --------------------------------------------------------

    if found_banking and strong_banking_scam_signal:

        category_scores["🏦 Banking Scam"] = (
            8 if (
                found_sensitive
                or found_otp
                or found_threat
                or suspicious_url
            )
            else 6
        )


    # --------------------------------------------------------
    # OTP
    # --------------------------------------------------------

    if strong_otp_signal:

        category_scores[
            "🔐 OTP / Account Verification Scam"
        ] = 8


    # --------------------------------------------------------
    # INVESTMENT
    # --------------------------------------------------------

    if found_investment:

        investment_scam_signal = (
            found_money
            or found_urgency
            or contains_any(
                lower,
                [
                    "guaranteed",
                    "double",
                    "high return",
                    "guaranteed return",
                    "guaranteed profit",
                ]
            )
        )

        if investment_scam_signal:

            category_scores[
                "📈 Investment Scam"
            ] = 8


    # --------------------------------------------------------
    # DELIVERY
    # --------------------------------------------------------

    if found_delivery:

        delivery_scam_signal = (
            found_money
            or found_urgency
            or suspicious_url
            or found_sensitive
        )

        if delivery_scam_signal:

            category_scores[
                "📦 Delivery Scam"
            ] = 7


    # --------------------------------------------------------
    # TECH SUPPORT
    # --------------------------------------------------------

    if found_tech:

        tech_scam_signal = (
            found_sensitive
            or found_click
            or suspicious_url
            or found_money
            or found_urgency
        )

        if tech_scam_signal:

            category_scores[
                "💻 Tech-Support Scam"
            ] = 7


    # --------------------------------------------------------
    # IMPERSONATION
    # --------------------------------------------------------

    if found_organization and (
        found_money
        or found_sensitive
        or found_threat
        or suspicious_url
        or found_otp
    ):

        category_scores[
            "👤 Impersonation Scam"
        ] = 6


    # --------------------------------------------------------
    # SOCIAL ENGINEERING
    # --------------------------------------------------------

    if found_secrecy and (
        found_money
        or found_threat
        or found_sensitive
    ):

        category_scores[
            "💬 Romance / Social-Engineering Scam"
        ] = 5


    # ========================================================
    # PRIMARY CLASSIFICATION — STEP 38
    # ========================================================

    primary_classification = (
        "⚠️ Suspicious Activity"
    )


    # Strong classifications take priority.

    if (
        found_otp
        and strong_otp_signal
    ):

        primary_classification = (
            "🔐 OTP / Account Verification Scam"
        )


    elif (
        found_banking
        and strong_banking_scam_signal
    ):

        primary_classification = (
            "🏦 Banking Scam"
        )


    elif (
        found_job
        and strong_job_scam_signal
    ):

        primary_classification = (
            "💼 Job Scam"
        )


    elif (
        found_investment
        and (
            found_money
            or contains_any(
                lower,
                [
                    "guaranteed",
                    "double",
                    "high return",
                    "guaranteed return",
                    "guaranteed profit",
                ]
            )
        )
    ):

        primary_classification = (
            "📈 Investment Scam"
        )


    elif (
        found_delivery
        and (
            found_money
            or found_urgency
            or suspicious_url
        )
    ):

        primary_classification = (
            "📦 Delivery Scam"
        )


    elif (
        found_tech
        and (
            found_sensitive
            or found_click
            or suspicious_url
            or found_money
        )
    ):

        primary_classification = (
            "💻 Tech-Support Scam"
        )


    elif (
        found_prize
        and (
            found_money
            or found_urgency
            or suspicious_url
        )
    ):

        primary_classification = (
            "🎁 Lottery / Reward Scam"
        )


    elif strong_payment_signal:

        primary_classification = (
            "💳 Payment / UPI Scam"
        )


    elif strong_phishing_signal:

        primary_classification = (
            "🎣 Phishing Scam"
        )


    elif (
        found_organization
        and (
            found_money
            or found_sensitive
            or found_threat
            or suspicious_url
        )
    ):

        primary_classification = (
            "👤 Impersonation Scam"
        )


    elif (
        found_secrecy
        and (
            found_money
            or found_threat
            or found_sensitive
        )
    ):

        primary_classification = (
            "💬 Romance / Social-Engineering Scam"
        )


    elif category_scores:

        primary_classification = max(
            category_scores,
            key=category_scores.get
        )


    # ========================================================
    # LIKELY LEGITIMATE CLASSIFICATION
    # ========================================================

    if (
        legitimate_neutral_message
        or legitimate_job_message
        or legitimate_banking_message
    ):

        primary_classification = (
            "🟢 Likely Legitimate"
        )


    # ========================================================
    # POSSIBLE TYPES
    # ========================================================

    possible_types = []

    for category, score in sorted(
        category_scores.items(),
        key=lambda item: item[1],
        reverse=True
    ):

        if score >= 2:

            possible_types.append(
                category
            )


    # ========================================================
    # CLASSIFICATION EVIDENCE
    # ========================================================

    classification_evidence = []


    if primary_classification == "🟢 Likely Legitimate":

        classification_evidence.append(
            "🟢 Normal notification or recruitment context detected."
        )

        if found_legitimate_context:

            classification_evidence.append(
                "📄 The message contains language consistent with a routine official communication."
            )

        if legitimate_job_message:

            classification_evidence.append(
                "💼 The employment language describes an application/recruitment process rather than requesting payment."
            )

        if legitimate_banking_message:

            classification_evidence.append(
                "🏦 The banking language describes a statement or transaction-review process without requesting credentials."
            )

        if not (
            found_urgency
            or found_money
            or found_sensitive
            or suspicious_url
            or found_threat
        ):

            classification_evidence.append(
                "✅ No strong scam indicators were detected."
            )


    elif primary_classification == "💼 Job Scam":

        if found_job:

            classification_evidence.append(
                "💼 Employment or work-from-home language detected."
            )

        if job_context:

            classification_evidence.append(
                "💰 An upfront job-related fee or deposit is requested."
            )

        if found_money:

            classification_evidence.append(
                "💳 The message contains a financial or payment request."
            )

        if found_urgency:

            classification_evidence.append(
                "🚨 Urgency or time pressure is used to encourage quick action."
            )

        if found_click:

            classification_evidence.append(
                "🖱️ The recipient is encouraged to follow a link or click an action."
            )

        if found_sensitive:

            classification_evidence.append(
                "🔐 Sensitive information may be requested."
            )


    elif primary_classification == "🏦 Banking Scam":

        if found_banking:

            classification_evidence.append(
                "🏦 Banking or account-related language detected."
            )

        if found_sensitive:

            classification_evidence.append(
                "🔐 Sensitive account information appears to be requested."
            )

        if found_otp:

            classification_evidence.append(
                "🔑 OTP or verification-code language detected."
            )

        if found_urgency:

            classification_evidence.append(
                "🚨 Urgency is used to encourage immediate action."
            )

        if found_threat:

            classification_evidence.append(
                "⚠️ Threatening or account-blocking language detected."
            )

        if suspicious_url:

            classification_evidence.append(
                "🔗 A potentially suspicious URL is present."
            )


    elif primary_classification == (
        "🔐 OTP / Account Verification Scam"
    ):

        if found_otp:

            classification_evidence.append(
                "🔑 OTP or verification-code language detected."
            )

        if found_sensitive:

            classification_evidence.append(
                "🔐 Sensitive account information is involved."
            )

        if found_urgency:

            classification_evidence.append(
                "🚨 Urgency is used to encourage immediate verification."
            )

        if suspicious_url:

            classification_evidence.append(
                "🔗 A potentially suspicious verification URL is present."
            )


    elif primary_classification == "📈 Investment Scam":

        if found_investment:

            classification_evidence.append(
                "📈 Investment or financial-return language detected."
            )

        if found_money:

            classification_evidence.append(
                "💰 A financial transaction or investment is requested."
            )

        if found_urgency:

            classification_evidence.append(
                "🚨 Urgency is used to encourage quick investment."
            )


    elif primary_classification == "📦 Delivery Scam":

        if found_delivery:

            classification_evidence.append(
                "📦 Delivery or parcel language detected."
            )

        if found_money:

            classification_evidence.append(
                "💰 A payment or fee is associated with the delivery."
            )

        if found_urgency:

            classification_evidence.append(
                "🚨 Urgency is used to pressure the recipient."
            )

        if suspicious_url:

            classification_evidence.append(
                "🔗 A potentially suspicious tracking or payment URL is present."
            )


    elif primary_classification == "🎣 Phishing Scam":

        if urls:

            classification_evidence.append(
                "🔗 A URL is present in the message."
            )

        if suspicious_url:

            classification_evidence.append(
                "⚠️ The URL contains potentially suspicious characteristics."
            )

        if found_click:

            classification_evidence.append(
                "🖱️ The recipient is encouraged to click or follow a link."
            )

        if found_sensitive:

            classification_evidence.append(
                "🔐 Sensitive information may be requested."
            )


    elif primary_classification == (
        "🎁 Lottery / Reward Scam"
    ):

        classification_evidence.append(
            "🎁 Strong prize or reward language was detected."
        )

        if found_money:

            classification_evidence.append(
                "💰 Money or payment is associated with the reward."
            )

        if found_urgency:

            classification_evidence.append(
                "🚨 Urgency is used to encourage immediate action."
            )


    elif primary_classification == "💻 Tech-Support Scam":

        if found_tech:

            classification_evidence.append(
                "💻 Technical-support or device-security language detected."
            )

        if found_sensitive:

            classification_evidence.append(
                "🔐 Sensitive information may be requested."
            )

        if found_click:

            classification_evidence.append(
                "🖱️ The message encourages an online action."
            )

        if found_urgency:

            classification_evidence.append(
                "🚨 Urgency is used to pressure the recipient."
            )


    elif primary_classification == (
        "💳 Payment / UPI Scam"
    ):

        if found_money:

            classification_evidence.append(
                "💰 Financial or payment-related language detected."
            )

        if found_alt_payment:

            classification_evidence.append(
                "💳 An alternative payment method is mentioned."
            )

        if found_urgency:

            classification_evidence.append(
                "🚨 Urgency is used to encourage quick payment."
            )


    elif primary_classification == (
        "👤 Impersonation Scam"
    ):

        if found_organization:

            classification_evidence.append(
                "🏢 An organization or authority is referenced."
            )

        if found_money:

            classification_evidence.append(
                "💰 A financial request is present."
            )

        if found_sensitive:

            classification_evidence.append(
                "🔐 Sensitive information may be requested."
            )

        if found_threat:

            classification_evidence.append(
                "⚠️ Threatening or authoritative language is present."
            )


    elif primary_classification == (
        "💬 Romance / Social-Engineering Scam"
    ):

        if found_secrecy:

            classification_evidence.append(
                "🤫 Secrecy or isolation language detected."
            )

        if found_money:

            classification_evidence.append(
                "💰 A financial request is present."
            )

        if found_threat:

            classification_evidence.append(
                "⚠️ Threat or intimidation language detected."
            )


    else:

        classification_evidence.append(
            "⚠️ One or more potentially suspicious linguistic signals were detected."
        )


    classification_evidence = unique_list(
        classification_evidence
    )


    # ========================================================
    # WHY SUSPICIOUS
    # ========================================================

    why_suspicious = []


    if primary_classification == "🟢 Likely Legitimate":

        why_suspicious.append(
            "No strong scam indicators were detected in the message."
        )

        if found_legitimate_context:

            why_suspicious.append(
                "The wording is consistent with a routine notification or normal recruitment/banking workflow."
            )


    else:

        if found_urgency:

            why_suspicious.append(
                "The message creates urgency or pressure, which can discourage careful verification."
            )

        if found_click:

            if urls:

                why_suspicious.append(
                    "The message encourages the recipient to click or follow a link."
                )

            else:

                why_suspicious.append(
                    "The message encourages the user to click or follow a link, even though no actual URL was detected."
                )

        if found_money and not (
            found_legitimate_context
            and not strong_payment_signal
        ):

            why_suspicious.append(
                "The message contains financial or payment-related language."
            )

        if (
            found_job
            and not legitimate_job_message
        ):

            why_suspicious.append(
                "The message contains employment-related language combined with signals commonly associated with fake-job scams."
            )

        if found_prize:

            why_suspicious.append(
                "The message contains strong prize or reward language."
            )

        if found_sensitive:

            why_suspicious.append(
                "The message appears to involve sensitive personal or account information."
            )

        if (
            found_banking
            and not legitimate_banking_message
        ):

            why_suspicious.append(
                "The message contains banking or account-related language combined with stronger scam indicators."
            )

        if found_threat:

            why_suspicious.append(
                "The message uses threatening or intimidating language."
            )

        if suspicious_url:

            why_suspicious.append(
                "The detected URL has characteristics commonly associated with suspicious links."
            )

        if not why_suspicious:

            why_suspicious.append(
                "The message contains limited suspicious signals and should be verified using trusted sources."
            )


    # ========================================================
    # SUSPICIOUS PHRASES
    # ========================================================

    phrase_candidates = (
        urgency_words
        + click_words
        + [
            "registration fee",
            "joining fee",
            "application fee",
            "deposit",
            "otp",
            "password",
            "verify your account",
            "guaranteed return",
            "double your money",
            "account will be blocked",
            "account will be suspended",
            "no interview",
            "guaranteed salary",
        ]
    )

    for phrase in phrase_candidates:

        if phrase.lower() in lower:

            suspicious_phrases.append(
                phrase
            )

    suspicious_phrases = unique_list(
        suspicious_phrases
    )


    # ========================================================
    # RISK SCORE
    # ========================================================

    risk_score = min(
        100,
        total_signal_points
    )


    # Strong legitimate contexts suppress weak residual
    # points while preserving genuinely suspicious combinations.
    if (
        found_legitimate_context
        and not (
            strong_job_scam_signal
            or strong_banking_scam_signal
            or strong_otp_signal
            or strong_phishing_signal
            or strong_payment_signal
            or found_prize
            or found_investment
            or found_delivery
            or found_tech
            or found_threat
        )
    ):

        risk_score = min(
            risk_score,
            10
        )


    if risk_score >= 70:

        risk_level = "🔴 HIGH"

    elif risk_score >= 40:

        risk_level = "🟠 MEDIUM"

    else:

        risk_level = "🟢 LOW"


    # ========================================================
    # STEP 37 + STEP 38 — CONTEXT-AWARE CONFIDENCE
    # ========================================================

    independent_signal_count = sum(
        [
            found_urgency,
            found_money,
            found_job and not legitimate_job_message,
            found_banking and not legitimate_banking_message,
            found_otp,
            found_sensitive,
            found_investment,
            found_delivery,
            found_tech,
            found_prize,
            suspicious_url,
            found_alt_payment,
            found_threat,
            found_secrecy,
        ]
    )

    evidence_strength = len(
        classification_evidence
    )

    pattern_strength = len(
        advanced_patterns
    )

    confidence = 45

    confidence += min(
        25,
        independent_signal_count * 3
    )

    confidence += min(
        15,
        evidence_strength * 3
    )

    confidence += min(
        15,
        pattern_strength * 3
    )


    # Strong classification agreement bonus

    if (
        primary_classification in category_scores
        and category_scores[
            primary_classification
        ] >= 7
    ):

        confidence += 5


    # Legitimate-context confidence adjustment

    if primary_classification == "🟢 Likely Legitimate":

        confidence += min(
            10,
            benign_strength * 2
        )

        confidence -= min(
            8,
            independent_signal_count * 2
        )


    # Ambiguity penalty

    if (
        len(category_scores) >= 4
        and risk_score < 70
    ):

        confidence -= 8


    confidence = max(
        50,
        min(
            100,
            confidence
        )
    )


    # ========================================================
    # SMART RECOMMENDATIONS
    # ========================================================

    recommendations = []


    if primary_classification == "🟢 Likely Legitimate":

        recommendations.append(
            "No obvious scam indicators were detected. Continue using official channels when reviewing important notifications."
        )

        if found_banking:

            recommendations.append(
                "For banking information, access your bank through its official app or website rather than links in unexpected messages."
            )

        if found_job:

            recommendations.append(
                "For recruitment updates, use the company's official careers portal to verify application status."
            )


    else:

        if found_click or urls:

            recommendations.append(
                "Do not click suspicious links. Open the official website manually instead."
            )

        if found_money:

            recommendations.append(
                "Do not send money or make payments before independently verifying the request."
            )

        if found_urgency:

            recommendations.append(
                "Do not rush because of urgent language. Take time to verify the claim."
            )

        if job_context:

            recommendations.append(
                "Be cautious of job offers asking for registration fees, deposits or payments."
            )

        if found_otp or found_sensitive:

            recommendations.append(
                "Never share OTPs, passwords, PINs, CVVs or other sensitive credentials."
            )

        if found_banking:

            recommendations.append(
                "Verify banking alerts directly through your bank's official app or website."
            )

        if found_investment:

            recommendations.append(
                "Verify investment opportunities independently and be cautious of guaranteed returns."
            )

        if found_delivery and found_money:

            recommendations.append(
                "Verify delivery charges through the courier's official tracking system."
            )

        if found_tech:

            recommendations.append(
                "Do not provide remote access to your device unless you independently verified the support request."
            )

        if not recommendations:

            recommendations.append(
                "Verify unexpected requests through an independent, trusted source."
            )


    recommendations = unique_list(
        recommendations
    )


    # ========================================================
    # TECHNICAL DETAILS
    # ========================================================

    technical_details = {

        "Input length":
            len(text),

        "URLs detected":
            len(urls),

        "Email addresses detected":
            len(emails),

        "Phone numbers detected":
            len(phones),

        "Independent signals":
            independent_signal_count,

        "Classification evidence items":
            evidence_strength,

        "Advanced patterns":
            pattern_strength,

        "Legitimate context detected":
            "Yes" if found_legitimate_context else "No",

        "Benign context signals":
            benign_strength,

        "Total heuristic signal points":
            total_signal_points,
    }


    # ========================================================
    # URL ANALYSIS
    # ========================================================

    if urls:

        url_analysis = {

            "detected":
                True,

            "urls":
                [
                    url.rstrip(
                        ".,!?;:)"
                    )
                    for url in urls
                ],

            "suspicious":
                suspicious_url,

            "reasons":
                unique_list(
                    url_reasons
                ),
        }

    else:

        url_analysis = {

            "detected":
                False,

            "urls":
                [],

            "suspicious":
                False,

            "reasons":
                [],
        }


    # ========================================================
    # FINAL REPORT
    # ========================================================

    report = {

        "timestamp":
            datetime.datetime.now().strftime(
                "%d %b %Y, %I:%M %p"
            ),

        "input_text":
            text,

        "risk_score":
            risk_score,

        "risk_level":
            risk_level,

        "confidence":
            confidence,

        "classification":
            primary_classification,

        "classification_evidence":
            classification_evidence,

        "category_scores":
            category_scores,

        "possible_types":
            possible_types,

        "indicators":
            unique_list(
                indicators
            ),

        "smart_intents":
            unique_list(
                smart_intents
            ),

        "advanced_patterns":
            unique_list(
                advanced_patterns
            ),

        "why_suspicious":
            unique_list(
                why_suspicious
            ),

        "suspicious_phrases":
            suspicious_phrases,

        "risk_breakdown":
            risk_breakdown,

        "total_signal_points":
            total_signal_points,

        "url_analysis":
            url_analysis,

        "recommendations":
            recommendations,

        "technical_details":
            technical_details,
    }

    return report


# ============================================================
# PDF REPORT
# ============================================================

def create_pdf(report):

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "Title",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=22,
        leading=26,
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=14,
        leading=18,
        spaceBefore=12,
        spaceAfter=7,
    )

    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontSize=9.5,
        leading=13,
    )

    story = []

    story.append(
        Paragraph(
            "🛡️ ScamCheck",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Scam Awareness & Heuristic Detection Report",
            body_style
        )
    )

    story.append(
        Spacer(1, 15)
    )

    story.append(
        Paragraph(
            f"<b>Risk Level:</b> {escape(str(report['risk_level']))}",
            body_style
        )
    )

    story.append(
        Paragraph(
            f"<b>Risk Score:</b> {report['risk_score']}/100",
            body_style
        )
    )

    story.append(
        Paragraph(
            f"<b>Detection Confidence:</b> {report['confidence']}%",
            body_style
        )
    )

    story.append(
        Paragraph(
            f"<b>Primary Classification:</b> "
            f"{escape(str(report['classification']))}",
            body_style
        )
    )

    story.append(
        Paragraph(
            "<b>Classification Evidence</b>",
            heading_style
        )
    )

    for item in report[
        "classification_evidence"
    ]:

        story.append(
            Paragraph(
                "• " + escape(item),
                body_style
            )
        )


    story.append(
        Paragraph(
            "<b>Category Scores</b>",
            heading_style
        )
    )

    category_data = [
        ["Category", "Score"]
    ]

    for category, score in report[
        "category_scores"
    ].items():

        category_data.append(
            [
                category,
                str(score),
            ]
        )

    if len(category_data) == 1:

        category_data.append(
            [
                "No strong category detected",
                "0",
            ]
        )

    table = Table(
        category_data,
        colWidths=[380, 80]
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.lightgrey
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),
            ]
        )
    )

    story.append(table)


    story.append(
        Paragraph(
            "<b>Risk Breakdown</b>",
            heading_style
        )
    )

    risk_data = [
        [
            "Detection Signal",
            "Contribution"
        ]
    ]

    for item in report[
        "risk_breakdown"
    ]:

        risk_data.append(
            [
                item["signal"],
                f"+{item['points']}",
            ]
        )

    risk_data.append(
        [
            "Final Risk Score",
            f"{report['risk_score']}/100",
        ]
    )

    table = Table(
        risk_data,
        colWidths=[380, 80]
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.lightgrey
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),
            ]
        )
    )

    story.append(table)


    story.append(
        Paragraph(
            "<b>Why This Is Suspicious</b>",
            heading_style
        )
    )

    for item in report[
        "why_suspicious"
    ]:

        story.append(
            Paragraph(
                "• " + escape(item),
                body_style
            )
        )


    story.append(
        Paragraph(
            "<b>Recommendations</b>",
            heading_style
        )
    )

    for item in report[
        "recommendations"
    ]:

        story.append(
            Paragraph(
                "• " + escape(item),
                body_style
            )
        )


    story.append(
        Spacer(1, 20)
    )

    story.append(
        Paragraph(
            "ScamCheck uses heuristic analysis. Results are not a guarantee that a message is fraudulent or legitimate. Verify suspicious requests through trusted official channels.",
            body_style
        )
    )

    document.build(story)

    buffer.seek(0)

    return buffer


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ ScamCheck</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Detect possible scam indicators in messages, links, emails and phone numbers.'
    '</div>',
    unsafe_allow_html=True
)


# ============================================================
# INPUT SECTION
# ============================================================

st.markdown(
    '<div class="section-title">🔎 Enter Suspicious Content</div>',
    unsafe_allow_html=True
)

st.write(
    "Paste a suspicious message, email, phone number or link below:"
)

user_input = st.text_area(
    "Suspicious content",
    height=180,
    placeholder="Paste a suspicious message, email, phone number or link here...",
    label_visibility="collapsed"
)


# ============================================================
# ANALYZE BUTTON
# ============================================================

if st.button(
    "🔍 Analyze Message",
    width="stretch",
    type="primary",
):

    if not user_input.strip():

        st.warning(
            "Please enter a message, link, email or phone number first."
        )

    else:

        report = analyze_message(
            user_input
        )

        st.session_state.latest_report = report

        history_item = {

            "timestamp":
                report["timestamp"],

            "classification":
                report["classification"],

            "risk_score":
                report["risk_score"],

            "risk_level":
                report["risk_level"],

            "confidence":
                report["confidence"],

            "indicators":
                report["indicators"],

            "report":
                report,
        }

        st.session_state.scan_history.insert(
            0,
            history_item
        )

        st.session_state.scan_history = (
            st.session_state.scan_history[:50]
        )

        save_scan_history(
            st.session_state.scan_history
        )

        st.success(
            "Scan completed and saved to history."
        )


# ============================================================
# REPORT DISPLAY
# ============================================================

report = st.session_state.latest_report

if report:

    st.markdown(
        '<div class="section-title">🛡️ ScamCheck Report</div>',
        unsafe_allow_html=True
    )


    # ========================================================
    # OVERALL ASSESSMENT
    # ========================================================

    st.markdown(
        '<div class="section-title">🧾 Overall Assessment</div>',
        unsafe_allow_html=True
    )

    if report["classification"] == "🟢 Likely Legitimate":

        st.success(
            "🟢 LIKELY LEGITIMATE"
        )

        st.write(
            "No strong scam indicators were detected in this message. "
            "The detected wording appears consistent with a normal notification."
        )

    elif report["risk_level"] == "🔴 HIGH":

        st.error(
            "🔴 HIGH RISK"
        )

        st.write(
            "High-risk message detected. Several suspicious indicators were found."
        )

    elif report["risk_level"] == "🟠 MEDIUM":

        st.warning(
            "🟠 MEDIUM RISK"
        )

        st.write(
            "Several suspicious indicators were detected. Verify the message carefully."
        )

    else:

        st.success(
            "🟢 LOW RISK"
        )

        st.write(
            "Few suspicious indicators were detected, but normal caution is still recommended."
        )


    # ========================================================
    # DASHBOARD
    # ========================================================

    st.markdown(
        '<div class="section-title">📊 Risk Dashboard</div>',
        unsafe_allow_html=True
    )

    col1, col2, col3 = st.columns(3)

    with col1:

        st.markdown(
            f"""
            <div class="metric-card">
                <div class="dashboard-label">🎯 RISK SCORE</div>
                <div class="dashboard-number">
                    {report["risk_score"]}/100
                </div>
                <div class="small-muted">
                    {report["risk_level"]}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col2:

        st.markdown(
            f"""
            <div class="metric-card">
                <div class="dashboard-label">📊 CONFIDENCE</div>
                <div class="dashboard-number">
                    {report["confidence"]}%
                </div>
                <div class="small-muted">
                    Context-aware confidence
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col3:

        st.markdown(
            f"""
            <div class="metric-card">
                <div class="dashboard-label">🎯 CLASSIFICATION</div>
                <div class="category-name">
                    {escape(report["classification"])}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )


    # ========================================================
    # CLASSIFICATION EVIDENCE
    # ========================================================

    st.markdown(
        '<div class="section-title">🔍 Classification Evidence</div>',
        unsafe_allow_html=True
    )

    st.write(
        f"ScamCheck classified this message primarily as "
        f"**{report['classification']}** because of the following detected evidence:"
    )

    for evidence in report[
        "classification_evidence"
    ]:

        st.markdown(
            f"""
            <div class="evidence-box">
                {escape(evidence)}
            </div>
            """,
            unsafe_allow_html=True
        )


    # ========================================================
    # CATEGORY SCORES
    # ========================================================

    st.markdown(
        '<div class="section-title">📊 Category Scores</div>',
        unsafe_allow_html=True
    )

    if report["category_scores"]:

        for category, score in sorted(
            report["category_scores"].items(),
            key=lambda item: item[1],
            reverse=True
        ):

            st.markdown(
                f"""
                <div class="category-card">
                    <div class="category-name">
                        {escape(category)}
                    </div>
                    <div class="category-score">
                        Detection Score: <b>{score}</b>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

    else:

        st.info(
            "No strong scam category was detected."
        )


    # ========================================================
    # POSSIBLE SCAM TYPES
    # ========================================================

    st.markdown(
        '<div class="section-title">🕵️ Possible Scam Types</div>',
        unsafe_allow_html=True
    )

    if report["possible_types"]:

        for item in report[
            "possible_types"
        ]:

            st.write(
                f"• {item}"
            )

    else:

        st.write(
            "No specific scam type detected."
        )


    # ========================================================
    # INDICATORS
    # ========================================================

    st.markdown(
        '<div class="section-title">🚩 Scam Indicators</div>',
        unsafe_allow_html=True
    )

    if report["indicators"]:

        for item in report[
            "indicators"
        ]:

            st.write(
                f"• {item}"
            )

    else:

        st.write(
            "No major warning indicators detected."
        )


    # ========================================================
    # SMART INTENTS
    # ========================================================

    st.markdown(
        '<div class="section-title">🧠 Smart Intent Analysis</div>',
        unsafe_allow_html=True
    )

    if report["smart_intents"]:

        for item in report[
            "smart_intents"
        ]:

            st.write(
                f"• {item}"
            )

    else:

        st.write(
            "No strong suspicious intent detected."
        )


    # ========================================================
    # ADVANCED PATTERNS
    # ========================================================

    st.markdown(
        '<div class="section-title">🔬 Advanced Scam Patterns</div>',
        unsafe_allow_html=True
    )

    if report["advanced_patterns"]:

        for item in report[
            "advanced_patterns"
        ]:

            st.write(
                f"• {item}"
            )

    else:

        st.write(
            "No advanced scam pattern detected."
        )


    # ========================================================
    # WHY SUSPICIOUS
    # ========================================================

    st.markdown(
        '<div class="section-title">❓ Why This Is Suspicious?</div>',
        unsafe_allow_html=True
    )

    for item in report[
        "why_suspicious"
    ]:

        st.write(
            f"• {item}"
        )


    # ========================================================
    # SUSPICIOUS PHRASES
    # ========================================================

    st.markdown(
        '<div class="section-title">📝 Suspicious Phrases</div>',
        unsafe_allow_html=True
    )

    if report["suspicious_phrases"]:

        for phrase in report[
            "suspicious_phrases"
        ]:

            st.code(
                phrase
            )

    else:

        st.info(
            "No specific suspicious phrases identified."
        )


    # ========================================================
    # RISK BREAKDOWN
    # ========================================================

    st.markdown(
        '<div class="section-title">📈 Professional Risk Breakdown</div>',
        unsafe_allow_html=True
    )

    breakdown_data = [
        [
            "Detection Signal",
            "Contribution"
        ]
    ]

    for item in report[
        "risk_breakdown"
    ]:

        if item["points"] > 0:

            breakdown_data.append(
                [
                    item["signal"],
                    f"+{item['points']}",
                ]
            )

    if len(breakdown_data) > 1:

        st.table(
            breakdown_data
        )

    else:

        st.info(
            "No significant risk signals detected."
        )

    st.write(
        f"**Total detected signal points:** "
        f"{report['total_signal_points']}"
    )

    st.write(
        f"**Final Risk Score:** "
        f"**{report['risk_score']}/100**"
    )

    st.caption(
        "Signal points are heuristic contributions, not probability percentages. "
        "The final risk score is capped at 100."
    )


    # ========================================================
    # URL ANALYSIS
    # ========================================================

    st.markdown(
        '<div class="section-title">🔗 URL Analysis</div>',
        unsafe_allow_html=True
    )

    url_data = report[
        "url_analysis"
    ]

    if not url_data["detected"]:

        st.info(
            "No URL detected."
        )

    else:

        for url in url_data["urls"]:

            st.code(
                url
            )

        if url_data["suspicious"]:

            st.warning(
                "⚠️ Potentially suspicious URL characteristics detected."
            )

            for reason in url_data[
                "reasons"
            ]:

                st.write(
                    f"• {reason}"
                )

        else:

            st.success(
                "No obvious suspicious URL characteristics were detected."
            )


    # ========================================================
    # SMART RECOMMENDATIONS
    # ========================================================

    st.markdown(
        '<div class="section-title">💡 Smart Recommendations</div>',
        unsafe_allow_html=True
    )

    for item in report[
        "recommendations"
    ]:

        st.write(
            f"• {item}"
        )


    # ========================================================
    # TECHNICAL DETAILS
    # ========================================================

    with st.expander(
        "⚙️ Technical Detection Details"
    ):

        for key, value in report[
            "technical_details"
        ].items():

            st.write(
                f"**{key}:** {value}"
            )


    # ========================================================
    # PDF EXPORT
    # ========================================================

    st.markdown(
        '<div class="section-title">📄 Export Report</div>',
        unsafe_allow_html=True
    )

    pdf_file = create_pdf(
        report
    )

    st.download_button(
        label="📥 Download Professional PDF Report",
        data=pdf_file,
        file_name="ScamCheck_Report.pdf",
        mime="application/pdf",
        width="stretch",
    )


# ============================================================
# SCAN HISTORY
# ============================================================

st.markdown(
    '<div class="section-title">🕘 Scan History</div>',
    unsafe_allow_html=True
)

history = st.session_state.scan_history

if history:

    st.write(
        "Review previous scans and reopen complete reports saved by ScamCheck."
    )

    for index, item in enumerate(
        history,
        start=1
    ):

        classification = item.get(
            "classification",
            item.get(
                "category",
                "⚠️ Suspicious Activity"
            )
        )

        risk_score = item.get(
            "risk_score",
            0
        )

        risk_level = item.get(
            "risk_level",
            ""
        )

        confidence = item.get(
            "confidence",
            0
        )

        timestamp = item.get(
            "timestamp",
            item.get(
                "scan_time",
                "Unknown time"
            )
        )

        indicators = item.get(
            "indicators",
            []
        )

        with st.expander(
            f"Scan {index} • "
            f"{classification} • "
            f"{risk_score}/100 • "
            f"{timestamp}"
        ):

            col1, col2, col3 = st.columns(3)

            with col1:

                st.metric(
                    "Risk Score",
                    f"{risk_score}/100"
                )

            with col2:

                st.metric(
                    "Confidence",
                    f"{confidence}%"
                )

            with col3:

                st.metric(
                    "Risk Level",
                    risk_level
                    if risk_level
                    else "Unknown"
                )

            st.markdown(
                "### 🚩 Detected Indicators"
            )

            if indicators:

                for indicator in indicators:

                    st.write(
                        f"• {indicator}"
                    )

            else:

                st.info(
                    "No indicators were stored for this historical scan."
                )

            if isinstance(
                item.get("report"),
                dict
            ):

                if st.button(
                    "📂 Reopen Full Report",
                    key=f"reopen_scan_{index}",
                    width="stretch"
                ):

                    st.session_state.latest_report = (
                        item["report"]
                    )

                    st.rerun()

            else:

                st.info(
                    "Full report is not available for this older scan. "
                    "Only its saved summary information is available."
                )

    st.markdown(
        "---"
    )

    if st.button(
        "🗑️ Clear Scan History",
        width="stretch"
    ):

        st.session_state.scan_history = []

        clear_saved_history()

        st.session_state.latest_report = None

        st.success(
            "Scan history cleared successfully."
        )

        st.rerun()

else:

    st.info(
        "No scans have been saved yet."
    )


# ============================================================
# STATISTICS
# ============================================================

st.markdown(
    '<div class="section-title">📊 Scan Statistics</div>',
    unsafe_allow_html=True
)

if history:

    total_scans = len(
        history
    )

    high_count = sum(
        1
        for item in history
        if item.get(
            "risk_level"
        ) == "🔴 HIGH"
    )

    medium_count = sum(
        1
        for item in history
        if item.get(
            "risk_level"
        ) == "🟠 MEDIUM"
    )

    low_count = sum(
        1
        for item in history
        if item.get(
            "risk_level"
        ) == "🟢 LOW"
    )

    avg_confidence = (
        sum(
            item.get(
                "confidence",
                0
            )
            for item in history
        )
        / total_scans
    )

    avg_risk = (
        sum(
            item.get(
                "risk_score",
                0
            )
            for item in history
        )
        / total_scans
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "Total Scans",
            total_scans
        )

    with col2:

        st.metric(
            "🔴 High",
            high_count
        )

    with col3:

        st.metric(
            "🟠 Medium",
            medium_count
        )

    with col4:

        st.metric(
            "🟢 Low",
            low_count
        )

    st.write(
        f"**Average Detection Confidence:** "
        f"{avg_confidence:.1f}%"
    )

    st.write(
        f"**Average Risk Score:** "
        f"{avg_risk:.1f}/100"
    )


# ============================================================
# ANALYTICS DASHBOARD
# ============================================================

st.markdown(
    '<div class="section-title">📊 ScamCheck Analytics Dashboard</div>',
    unsafe_allow_html=True
)

if history:

    # --------------------------------------------------------
    # RISK DISTRIBUTION
    # --------------------------------------------------------

    st.markdown(
        "### 📊 Risk Distribution"
    )

    risk_distribution = {

        "High Risk":
            high_count,

        "Medium Risk":
            medium_count,

        "Low Risk":
            low_count,
    }

    st.bar_chart(
        risk_distribution
    )


    # --------------------------------------------------------
    # KEY METRICS
    # --------------------------------------------------------

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "🎯 Average Risk",
            f"{avg_risk:.1f}/100"
        )

    with col2:

        st.metric(
            "📊 Average Confidence",
            f"{avg_confidence:.1f}%"
        )

    with col3:

        highest_risk = max(
            item.get(
                "risk_score",
                0
            )
            for item in history
        )

        st.metric(
            "🚨 Highest Risk",
            f"{highest_risk}/100"
        )


    # --------------------------------------------------------
    # CATEGORY STATISTICS
    # --------------------------------------------------------

    st.markdown(
        "### 🏆 Most Frequently Detected Scam Category"
    )

    category_counter = Counter(
        item.get(
            "classification",
            "Unknown"
        )
        for item in history
    )

    most_common_category, most_common_count = (
        category_counter.most_common(1)[0]
    )

    st.success(
        f"🏆 **{most_common_category}** "
        f"was detected most often "
        f"({most_common_count} scans)."
    )


    st.markdown(
        "### 📈 Category Statistics"
    )

    category_table = []

    for category, count in (
        category_counter.most_common()
    ):

        percentage = (
            count
            / total_scans
        ) * 100

        category_table.append(
            {
                "Scam Category":
                    category,

                "Scans":
                    count,

                "Percentage":
                    f"{percentage:.1f}%",
            }
        )

    st.table(
        category_table
    )


    # --------------------------------------------------------
    # WARNING SIGNAL ANALYTICS
    # --------------------------------------------------------

    st.markdown(
        "### 🔥 Most Common Warning Signals"
    )

    signal_counter = Counter()

    for item in history:

        for signal in item.get(
            "indicators",
            []
        ):

            signal_counter[
                signal
            ] += 1


    if signal_counter:

        signal_table = []

        for signal, count in (
            signal_counter.most_common(10)
        ):

            percentage = (
                count
                / total_scans
            ) * 100

            signal_table.append(
                {
                    "Warning Signal":
                        signal,

                    "Scans":
                        count,

                    "Frequency":
                        f"{percentage:.1f}%",
                }
            )

        st.table(
            signal_table
        )

        top_signal = (
            signal_counter.most_common(1)[0][0]
        )

        st.info(
            f"🔥 Most frequently detected warning signal: "
            f"**{top_signal}**"
        )

    else:

        st.info(
            "Warning-signal statistics will appear after scans are recorded."
        )


    # --------------------------------------------------------
    # RISK SCORE ACTIVITY
    # --------------------------------------------------------

    st.markdown(
        "### 📉 Risk Score Activity"
    )

    risk_activity = {}

    for index, item in enumerate(
        reversed(history),
        start=1
    ):

        risk_activity[
            f"Scan {index}"
        ] = item.get(
            "risk_score",
            0
        )

    st.line_chart(
        risk_activity
    )


    # --------------------------------------------------------
    # DETAILED HISTORY
    # --------------------------------------------------------

    st.markdown(
        "### 📋 Detailed Scan History"
    )

    detailed_history = []

    for index, item in enumerate(
        history,
        start=1
    ):

        detailed_history.append(
            {
                "Scan":
                    f"Scan {index}",

                "Category":
                    item.get(
                        "classification",
                        "Unknown"
                    ),

                "Risk":
                    f"{item.get('risk_score', 0)}/100",

                "Risk Level":
                    item.get(
                        "risk_level",
                        ""
                    ),

                "Confidence":
                    f"{item.get('confidence', 0)}%",

                "Date & Time":
                    item.get(
                        "timestamp",
                        ""
                    ),
            }
        )

    st.table(
        detailed_history
    )


    # --------------------------------------------------------
    # ANALYTICS SUMMARY
    # --------------------------------------------------------

    st.markdown(
        "### 🧾 Analytics Summary"
    )

    st.write(
        f"ScamCheck has analyzed **{total_scans}** recent scans. "
        f"The average risk score is **{avg_risk:.1f}/100** "
        f"with an average detection confidence of "
        f"**{avg_confidence:.1f}%**. "
        f"There are **{high_count} high-risk**, "
        f"**{medium_count} medium-risk**, and "
        f"**{low_count} low-risk** detections."
    )

else:

    st.info(
        "Analytics will appear after you analyze some messages."
    )


# ============================================================
# SAFETY / DISCLAIMER
# ============================================================

st.markdown(
    """
    <div class="warning-box">
        <b>🛡️ ScamCheck Safety Reminder</b><br><br>
        ScamCheck provides heuristic analysis and should not be treated
        as a guarantee. Always verify suspicious requests through
        official and trusted channels.
    </div>
    """,
    unsafe_allow_html=True
)


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="footer">
        🛡️ <b>ScamCheck</b> — Scam awareness and heuristic detection tool<br>
        Built with Python & Streamlit
    </div>
    """,
    unsafe_allow_html=True
)