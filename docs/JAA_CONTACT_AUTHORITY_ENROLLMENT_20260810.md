# JAA contact-authority enrollment, 10 August 2026

## Result

The production operator contact identity is enrolled. The PII-bearing contact
record, private key and signed registry remain outside the repository under a
machine-local directory with mode 0700. Key and authority files use mode 0600.
The phone field is explicitly absent.

The repository contains only the enrolled raw public-key SHA-256:
`03f20d82d47ab08d3dbcdf7ef0e7d15eebd3accf243639eb1865418c9b2d349c`.

The external authority identities are:

- contact authority: `25fffe216377f3ba63898c3673f6f7e6aab258509eb76b353e1313f83c4f6a63`;
- registry genesis: `fad7aedb97dd12553704f19c9e06817f942a2b4012b673e829f58ab8275f1de7`.

## Runtime configuration

Production commands must set:

```text
JAA_OPERATOR_CONTACT_PUBLIC_KEY=/home/gutua/.local/share/jaa/operator-contact-20260810/keys/operator-contact-public-key.pem
JAA_OPERATOR_CONTACT_REGISTRY=/home/gutua/.local/share/jaa/operator-contact-20260810/registry
```

The current authority path is recorded only in the external enrollment
manifest. Logs and repository artifacts must use its content hash rather than
copying contact values.
