"""Outbound TLS policy for every HTTP client the audit plane creates.

The audit services talk to Langfuse, Loki, decrypt-svc and (optionally) the
OpenAgent identity endpoint. In an internal deployment those are frequently
served by certificates issued by the company CA, which the container does not
trust by default — and every such call would fail at the TLS handshake.

Rather than sprinkling ``verify=`` across each call site, all clients take the
policy from one place. Verification stays ON unless a deployment explicitly
turns it off; an internal CA is meant to be *trusted*, not ignored.
"""

from __future__ import annotations

from openagent_audit.config import Settings


def httpx_tls_kwargs(settings: Settings | None) -> dict[str, object]:
    """Keyword arguments to spread into ``httpx.Client(...)``.

    - ``AUDIT_CA_BUNDLE`` (or ``REQUESTS_CA_BUNDLE`` / ``SSL_CERT_FILE``) is
      used as the trust store.
    - ``AUDIT_TLS_VERIFY=false`` disables verification — a last resort that
      emits a warning at startup (see :func:`warn_if_verification_disabled`).
    - Otherwise the system bundle is used.
    """
    if settings is None:
        return {}

    if not settings.tls_verify:
        return {"verify": False}

    if settings.ca_bundle_path:
        return {"verify": settings.ca_bundle_path}

    return {}


def warn_if_verification_disabled(settings: Settings | None, logger=None) -> None:
    """Surface the insecure setting once, loudly.

    Disabling certificate verification is not an error the code should refuse —
    some lab environments need it — but it must never be silent.
    """
    if settings is None or settings.tls_verify:
        return
    message = (
        "AUDIT_TLS_VERIFY=false: outbound TLS certificate verification is "
        "DISABLED. Use AUDIT_CA_BUNDLE with the internal CA instead."
    )
    if logger is not None:
        logger.warning(message)
    else:
        import logging

        logging.getLogger("openagent_audit.tls").warning(message)