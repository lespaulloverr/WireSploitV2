import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1]))

from validation import (
    validate_username,
    validate_email,
    validate_phone,
    validate_domain,
    validate_url,
    validate_ip,
    classify_and_validate,
)

def test_validate_username():
    # Valid usernames
    assert validate_username("user123") == (True, "user123", None)
    assert validate_username("user_name") == (True, "user_name", None)
    assert validate_username("user-name") == (True, "user-name", None)
    assert validate_username("user.name") == (True, "user.name", None)
    assert validate_username("a1b2c3") == (True, "a1b2c3", None)
    # Too short
    assert validate_username("ab") == (False, "", "Username must be 3-32 characters, start with alphanumeric, and contain only alphanumerics, underscore, dot, hyphen")
    # Too long (33 chars)
    assert validate_username("a" * 33) == (False, "", "Username must be 3-32 characters, start with alphanumeric, and contain only alphanumerics, underscore, dot, hyphen")
    # Invalid start
    assert validate_username("_user") == (False, "", "Username must be 3-32 characters, start with alphanumeric, and contain only alphanumerics, underscore, dot, hyphen")
    # Invalid characters
    assert validate_username("user@") == (False, "", "Username must be 3-32 characters, start with alphanumeric, and contain only alphanumerics, underscore, dot, hyphen")
    # Empty
    assert validate_username("") == (False, "", "Username cannot be empty")
    # Whitespace only
    assert validate_username("   ") == (False, "", "Username cannot be empty")

def test_validate_email():
    # Valid emails
    assert validate_email("test@example.com") == (True, "test@example.com", None)
    assert validate_email("user.name@domain.co.uk") == (True, "user.name@domain.co.uk", None)
    assert validate_email("user+tag@example.org") == (True, "user+tag@example.org", None)
    # Invalid emails
    assert validate_email("invalid") == (False, "", "Invalid email format")
    assert validate_email("@example.com") == (False, "", "Invalid email format")
    assert validate_email("test@") == (False, "", "Invalid email format")
    assert validate_email("test@example") == (False, "", "Invalid email format")
    # Empty
    assert validate_email("") == (False, "", "Email cannot be empty")

def test_validate_phone():
    # Valid phone numbers
    assert validate_phone("+1234567890") == (True, "+1234567890", None)
    assert validate_phone("123-456-7890") == (True, "1234567890", None)
    assert validate_phone("(123) 456-7890") == (True, "1234567890", None)
    assert validate_phone("123 456 7890") == (True, "1234567890", None)
    assert validate_phone("1234567890") == (True, "1234567890", None)
    # Too few digits
    assert validate_phone("123") == (False, "", "Phone number must contain at least 9 digits")
    # Invalid characters
    assert validate_phone("123@456") == (False, "", "Phone number contains invalid characters")
    # Empty
    assert validate_phone("") == (False, "", "Phone number cannot be empty")

def test_validate_domain():
    # Valid domains
    assert validate_domain("example.com") == (True, "example.com", None)
    assert validate_domain("sub.example.co.uk") == (True, "sub.example.co.uk", None)
    assert validate_domain("xn--example.com") == (True, "xn--example.com", None)  # punycode
    # Invalid domains
    assert validate_domain("example") == (False, "", "Invalid domain format")
    assert validate_domain("-example.com") == (False, "", "Invalid domain format")
    assert validate_domain("example-.com") == (False, "", "Invalid domain format")
    assert validate_domain("example..com") == (False, "", "Invalid domain format")
    # Empty
    assert validate_domain("") == (False, "", "Domain cannot be empty")

def test_validate_url():
    # Valid URLs
    assert validate_url("http://example.com") == (True, "http://example.com", None)
    assert validate_url("https://example.com/path") == (True, "https://example.com/path", None)
    assert validate_url("http://example.com:8080") == (True, "http://example.com:8080", None)
    # Invalid URLs
    assert validate_url("example.com") == (False, "", "URL must start with http:// or https://")
    assert validate_url("ftp://example.com") == (False, "", "URL must start with http:// or https://")
    assert validate_url("") == (False, "", "URL cannot be empty")

def test_validate_ip():
    # Valid IPv4
    assert validate_ip("192.168.1.1") == (True, "192.168.1.1", None)
    assert validate_ip("8.8.8.8") == (True, "8.8.8.8", None)
    assert validate_ip("127.0.0.1") == (True, "127.0.0.1", None)
    # Valid IPv6
    assert validate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == (True, "2001:db8:85a3::8a2e:370:7334", None)
    assert validate_ip("::1") == (True, "::1", None)
    # Invalid IPs
    assert validate_ip("999.999.999.999") == (False, "", "Invalid IP address format")
    assert validate_ip("192.168.1") == (False, "", "Invalid IP address format")
    assert validate_ip("") == (False, "", "IP address cannot be empty")

def test_classify_and_validate():
    # Email
    assert classify_and_validate("test@example.com") == ('email', True, 'test@example.com', None)
    # Username
    assert classify_and_validate("user123") == ('username', True, 'user123', None)
    # Phone
    assert classify_and_validate("+1234567890") == ('phone', True, '+1234567890', None)
    # Domain
    assert classify_and_validate("example.com") == ('domain', True, 'example.com', None)
    # URL
    assert classify_and_validate("http://example.com") == ('url', True, 'http://example.com', None)
    # IP
    assert classify_and_validate("8.8.8.8") == ('ip', True, '8.8.8.8', None)
    # Search (fallback)
    assert classify_and_validate("some search term") == ('search', True, 'some search term', None)
    # Invalid input (empty)
    assert classify_and_validate("") == ('search', False, "", "Input cannot be empty")
    # Invalid email: since it contains only letters, it's classified as a valid username
    assert classify_and_validate("invalid") == ('username', True, "invalid", None)