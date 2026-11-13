import re
import ipaddress
from typing import Optional, Tuple

# Regex patterns for validation
EMAIL_PATTERN = re.compile(r'^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$', re.I)
DOMAIN_PATTERN = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', re.I)
USERNAME_PATTERN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$')
# Phone number: allow +, digits, spaces, parentheses, dots, dashes; at least 9 digits required
PHONE_PATTERN = re.compile(r'^[+0-9() .-]*$')
# URL: must start with http:// or https://
URL_PATTERN = re.compile(r'^https?://.+', re.I)
# Person name: require at least two words with first letter capitalized (First Last), allow letters, spaces, hyphens, apostrophes, periods
PERSON_PATTERN = re.compile(r"^[A-ZÀ-ÿ][a-zÀ-ÿ]*(?:[\s\-\.'’]+[A-ZÀ-ÿ][a-zÀ-ÿ]*)+$")
# Company name: allow alphanumeric, spaces, common punctuation; at least 2 chars
COMPANY_PATTERN = re.compile(r'^[A-Za-z0-9\s\-\.\,\&\(\)]{2,200}$')

def validate_username(value: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validate a username.
    Returns (is_valid, normalized_value, error_message)
    """
    value = value.strip()
    if not value:
        return False, "", "Username cannot be empty"
    if not USERNAME_PATTERN.match(value):
        return False, "", "Username must be 3-32 characters, start with alphanumeric, and contain only alphanumerics, underscore, dot, hyphen"
    # Normalize: lowercase
    normalized = value.lower()
    return True, normalized, None

def validate_email(value: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validate an email address.
    Returns (is_valid, normalized_value, error_message)
    """
    value = value.strip()
    if not value:
        return False, "", "Email cannot be empty"
    if not EMAIL_PATTERN.match(value):
        return False, "", "Invalid email format"
    # Normalize: lowercase
    normalized = value.lower()
    return True, normalized, None

def validate_phone(value: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validate a phone number.
    Returns (is_valid, normalized_value, error_message)
    """
    value = value.strip()
    if not value:
        return False, "", "Phone number cannot be empty"
    # Basic format check: only allow +, digits, spaces, parentheses, dots, dashes
    if not PHONE_PATTERN.match(value):
        return False, "", "Phone number contains invalid characters"
    # Remove all non-digit characters except leading +
    # Keep leading + if present
    has_plus = value.startswith('+')
    digits = re.sub(r'[^\d]', '', value)
    if has_plus:
        digits = '+' + digits
    # Check if we have at least 9 digits (excluding +)
    digit_count = len(re.sub(r'[^\d]', '', value))
    if digit_count < 9:
        return False, "", "Phone number must contain at least 9 digits"
    # Normalize: keep leading + and digits
    normalized = digits
    return True, normalized, None

def validate_domain(value: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validate a domain name.
    Returns (is_valid, normalized_value, error_message)
    """
    value = value.strip()
    if not value:
        return False, "", "Domain cannot be empty"
    if not DOMAIN_PATTERN.match(value):
        return False, "", "Invalid domain format"
    # Normalize: lowercase
    normalized = value.lower()
    return True, normalized, None

def validate_url(value: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validate a URL.
    Returns (is_valid, normalized_value, error_message)
    """
    value = value.strip()
    if not value:
        return False, "", "URL cannot be empty"
    if not URL_PATTERN.match(value):
        return False, "", "URL must start with http:// or https://"
    # Normalize: strip trailing slash? Keep as is for now
    normalized = value
    return True, normalized, None

def validate_ip(value: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validate an IP address (IPv4 or IPv6).
    Returns (is_valid, normalized_value, error_message)
    """
    value = value.strip()
    if not value:
        return False, "", "IP address cannot be empty"
    try:
        ip = ipaddress.ip_address(value)
        # Normalize to the string representation
        normalized = str(ip)
        return True, normalized, None
    except ValueError:
        return False, "", "Invalid IP address format"

def validate_person(value: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validate a person name.
    Returns (is_valid, normalized_value, error_message)
    """
    value = value.strip()
    if not value:
        return False, "", "Person name cannot be empty"
    if not PERSON_PATTERN.match(value):
        return False, "", "Person name must be 2-100 characters and contain only letters, spaces, hyphens, apostrophes, and periods"
    # Normalize: title case
    normalized = ' '.join(word.capitalize() for word in value.split())
    return True, normalized, None

def validate_company(value: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validate a company/organization name.
    Returns (is_valid, normalized_value, error_message)
    """
    value = value.strip()
    if not value:
        return False, "", "Company name cannot be empty"
    if not COMPANY_PATTERN.match(value):
        return False, "", "Company name must be 2-200 characters and contain only alphanumeric characters, spaces, and common punctuation"
    # Normalize: title case
    normalized = ' '.join(word.capitalize() for word in value.split())
    return True, normalized, None

def classify_and_validate(value: str) -> Tuple[str, bool, str, Optional[str]]:
    """
    Classify and validate an input value.
    Returns (input_type, is_valid, normalized_value, error_message)
    where input_type is one of: 'username', 'email', 'phone', 'domain', 'url', 'ip', 'person', 'company', 'search'
    """
    value = value.strip()
    if not value:
        return 'search', False, "", "Input cannot be empty"

    # Try each validator in order of specificity
    # Username must be checked before person because person pattern allows similar patterns
    # Company is NOT included in auto-detect - requires explicit selection
    validators = [
        ('email', validate_email),
        ('phone', validate_phone),
        ('domain', validate_domain),
        ('url', validate_url),
        ('ip', validate_ip),
        ('username', validate_username),
        ('person', validate_person),
    ]

    for input_type, validator in validators:
        is_valid, normalized, error = validator(value)
        if is_valid:
            return input_type, True, normalized, None

    # If none matched, treat as search
    return 'search', True, value.lower(), None