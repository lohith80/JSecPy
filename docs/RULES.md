# JSecPy rule catalog

Every finding carries a rule ID, severity, confidence, CWE list, and OWASP
Top 10 (2021) category. Injection-family rules are taint-driven (HIGH
confidence when attacker input provably reaches the sink; MEDIUM when a value
is dynamically concatenated but taint is unproven). Crypto and configuration
rules are AST pattern matches.

## Injection family (taint-driven)

### JSEC-SQLI - SQL Injection (CWE-89, A03)
Attacker-controlled or concatenated strings reaching JDBC (`Statement.execute*`,
`Connection.prepareStatement`) or JPA/Hibernate (`createQuery`,
`createNativeQuery`, `createSQLQuery`). **Fix:** parameterized queries with bind
variables; allowlist dynamic identifiers.

### JSEC-CMDI - OS Command Injection (CWE-78, A03)
Input reaching `Runtime.exec` or `ProcessBuilder.command`. **Fix:** avoid the
shell; pass a fixed program and argument array; allowlist arguments.

### JSEC-PATH - Path Traversal (CWE-22, A01)
Tainted input into `new File/FileInputStream/...`, `Paths.get`, or `Files.*`.
**Fix:** canonicalize and confirm the resolved path stays under the intended
base directory; reject separators and `..`.

### JSEC-SSRF - Server-Side Request Forgery (CWE-918, A10)
Tainted input into `new URL`, `URL.openConnection/openStream`, or a REST client.
**Fix:** allowlist hosts, block internal/link-local ranges, disable redirects.

### JSEC-LDAP - LDAP Injection (CWE-90, A03)
Tainted input into `DirContext.search`. **Fix:** escape filter metacharacters or
use parameterized filter templates.

### JSEC-XPATH - XPath Injection (CWE-643, A03)
Tainted input into `XPath.compile/evaluate`. **Fix:** bind values with an
`XPathVariableResolver` instead of concatenation.

### JSEC-REDIR - Open Redirect (CWE-601, A01)
Tainted input into `HttpServletResponse.sendRedirect`. **Fix:** map input to a
fixed set of destinations or validate a relative path on an allowlisted host.

## Cryptography (pattern-based)

### JSEC-HASH - Weak Hashing Algorithm (CWE-328/327, A02)
`MessageDigest.getInstance("MD5"|"SHA-1")`. **Fix:** SHA-256/SHA-3 for
integrity; bcrypt/scrypt/Argon2 for passwords.

### JSEC-CIPHER - Weak or Insecure Cipher (CWE-327, A02)
`Cipher.getInstance` with DES/3DES/RC2/RC4/Blowfish or ECB mode. **Fix:**
AES/GCM/NoPadding.

### JSEC-RANDOM - Insecure Randomness (CWE-330/338, A02)
`new java.util.Random()` or `Math.random()` for security values. **Fix:**
`java.security.SecureRandom`.

## Configuration and data integrity (pattern-based)

### JSEC-XXE - XML External Entity Exposure (CWE-611, A05)
An XML parser factory created via `newInstance()` with no `setFeature`/
`setAttribute` hardening. **Fix:** disable DOCTYPE and external entities.

### JSEC-DESER - Unsafe Deserialization (CWE-502, A08)
`new ObjectInputStream(...)`. **Fix:** avoid Java serialization for untrusted
data; use a schema-bound format or an `ObjectInputFilter` allowlist.

### JSEC-TLS - Disabled TLS Certificate Validation (CWE-295, A07)
A `HostnameVerifier.verify()` that unconditionally returns true, or an empty
`checkServerTrusted`/`checkClientTrusted`. **Fix:** use the default trust store;
validate the chain.

### JSEC-COOKIE - Insecure Cookie Flags (CWE-614/1004, A05)
`cookie.setSecure(false)` or `setHttpOnly(false)`. **Fix:** set both to true on
session/auth cookies.

### JSEC-SECRET - Hardcoded Secret (CWE-798/259, A07)
A secret-named field/variable assigned a string literal, or a literal matching a
known credential format (AWS key, private key block, Google/Slack token, JDBC
password). **Fix:** load from environment or a secrets manager; rotate exposed
secrets.

## Custom rules

Add organization-specific detections with YAML (`JSEC-Y-*`) or Python
(`@register`) rules - see [WRITING_RULES.md](WRITING_RULES.md).
