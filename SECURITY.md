# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ Yes |

## Reporting a Vulnerability

If you discover a security vulnerability in Hybrid R-Sentry, **do not open a public issue**.

Please report it privately by emailing: **itemsh0@gmail.com**

Include the following in your report:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive a response within 48 hours. Once confirmed, a fix will be prioritised and a patched release issued.

## Scope

This project is a **research and educational system** built as a cybersecurity capstone. It is not intended for deployment in production environments without further hardening.

Known areas that require hardening before production use:
- `SECRET_KEY` must be changed from the default value
- The agent requires `sudo` privileges — restrict access accordingly
- API keys should be rotated regularly
- The backend has no authentication layer by default
