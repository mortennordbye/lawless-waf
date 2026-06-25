"""Map a log ``matchVariableName`` to a Terraform exclusion ``match_variable`` + ``selector``.

Source of truth: the WAF tuning runbook's match-variable mapping table. Azure WAF exclusions only
support these five match variables; anything else (Method, ParseBodyError,
InitialBodyContents, URI/Path/Filename, multipart params) cannot be excluded and must be
fixed upstream — we say so explicitly so Claude Code never writes invalid HCL.
"""

from __future__ import annotations

from dataclasses import dataclass

# log prefix -> Terraform match_variable
PREFIX_MAP: dict[str, str] = {
    "CookieValue": "RequestCookieNames",
    "QueryParamValue": "QueryStringArgNames",
    "QueryStringArgNames": "QueryStringArgNames",
    "PostParamValue": "RequestBodyPostArgNames",
    "JsonValue": "RequestBodyJsonArgNames",
    "RequestHeaderValue": "RequestHeaderNames",
    "HeaderValue": "RequestHeaderNames",
    "HeaderName": "RequestHeaderNames",
}

# Match variables that exist in logs but are NOT excludable via
# the WAF firewall policy (Front Door or Application Gateway) — fix upstream instead.
NOT_EXCLUDABLE: dict[str, str] = {
    "Method": "HTTP method is not an excludable match variable; fix the client (e.g. GET->POST).",
    "ParseBodyError": "Body parse failures are not excludable; fix the malformed request body upstream.",
    "InitialBodyContents": "Multipart body contents are not excludable; fix the multipart boundary upstream.",
    "MultipartParamValue": "Multipart param values are not excludable; fix the upload client upstream.",
    "PostParamName": "Matched on a POST param *name*, not a value/selector — not excludable as-is.",
    "URI": "The request URI is not an excludable match variable.",
    "Path": "The URL path is not an excludable match variable.",
    "Filename": "The filename is not an excludable match variable.",
}


@dataclass(frozen=True)
class Mapping:
    excludable: bool
    match_variable: str | None = None
    selector: str | None = None
    reason: str | None = None


def map_match_variable(match_variable_name: str) -> Mapping:
    """Translate e.g. ``QueryParamValue:returnUrl`` -> Request/QueryStringArgNames + selector."""
    prefix, _, selector = match_variable_name.partition(":")
    selector = selector or None

    if prefix in NOT_EXCLUDABLE:
        return Mapping(excludable=False, reason=NOT_EXCLUDABLE[prefix])

    mv = PREFIX_MAP.get(prefix)
    if mv is None:
        return Mapping(
            excludable=False,
            reason=f"No known Terraform mapping for match variable prefix {prefix!r}.",
        )

    if selector is None:
        # e.g. a bare "HeaderName" missing-header check: the header name lives in the
        # value, not the match-variable name, so the selector can't be derived here.
        return Mapping(
            excludable=False,
            match_variable=mv,
            reason=f"{prefix!r} carries no selector in the match variable name; "
            "inspect the matched value to choose a selector.",
        )

    return Mapping(excludable=True, match_variable=mv, selector=selector)
