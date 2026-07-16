"""Map a log matched-variable name to a Terraform exclusion ``match_variable`` + ``selector``.

Source of truth: the WAF tuning runbook's match-variable mapping table plus the Azure exclusion
docs. The two WAF products expose *different* exclusion match-variable vocabularies, so the
mapping is WAF-type aware:

* **Front Door** (``frontdoor``) logs a ``matchVariableName`` like ``QueryParamValue:returnUrl``
  and supports five exclusion match variables (``RequestHeaderNames``, ``RequestCookieNames``,
  ``QueryStringArgNames``, ``RequestBodyPostArgNames``, ``RequestBodyJsonArgNames``).

* **Application Gateway** (``appgw``) logs the matched variable as a ModSecurity/CRS collection
  (``ARGS:name``, ``REQUEST_COOKIES:name``, ``REQUEST_HEADERS:name``, ...), which we translate
  to its exclusion vocabulary (``RequestArgNames``, ``RequestCookieNames``,
  ``RequestHeaderNames`` and their ``Keys`` variants for the ``*_NAMES`` collections).

Anything that isn't excludable (method, body/multipart contents, URI/path/filename, internal
CRS collections) is reported as such with a reason, so Claude Code never writes invalid HCL.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..duck.schema import APP_GATEWAY, FRONT_DOOR

# --- Front Door: log prefix -> Terraform match_variable ---
FRONTDOOR_PREFIX_MAP: dict[str, str] = {
    "CookieValue": "RequestCookieNames",
    "QueryParamValue": "QueryStringArgNames",
    "QueryStringArgNames": "QueryStringArgNames",
    "PostParamValue": "RequestBodyPostArgNames",
    "JsonValue": "RequestBodyJsonArgNames",
    "RequestHeaderValue": "RequestHeaderNames",
    "HeaderValue": "RequestHeaderNames",
    "HeaderName": "RequestHeaderNames",
}

FRONTDOOR_NOT_EXCLUDABLE: dict[str, str] = {
    "Method": "HTTP method is not an excludable match variable; fix the client (e.g. GET->POST).",
    "ParseBodyError": "Body parse failures are not excludable; fix the malformed request body upstream.",
    "InitialBodyContents": "Multipart body contents are not excludable; fix the multipart boundary upstream.",
    "MultipartParamValue": "Multipart param values are not excludable; fix the upload client upstream.",
    "PostParamName": "Matched on a POST param *name*, not a value/selector — not excludable as-is.",
    "URI": "The request URI is not an excludable match variable.",
    "Path": "The URL path is not an excludable match variable.",
    "Filename": "The filename is not an excludable match variable.",
}

# --- Application Gateway: CRS collection -> Terraform match_variable ---
# A value collection (ARGS, REQUEST_COOKIES, REQUEST_HEADERS) excludes the *value* of the named
# item, so it maps to the "...Names" exclusion variable; a "..._NAMES" collection matched the
# key itself, so it maps to the "...Keys" variant. ARGS covers query string, POST body, and JSON
# entities on Application Gateway, all under RequestArg*.
APPGW_PREFIX_MAP: dict[str, str] = {
    "ARGS": "RequestArgNames",
    "ARGS_GET": "RequestArgNames",
    "ARGS_POST": "RequestArgNames",
    "ARGS_NAMES": "RequestArgKeys",
    "ARGS_GET_NAMES": "RequestArgKeys",
    "ARGS_POST_NAMES": "RequestArgKeys",
    "REQUEST_COOKIES": "RequestCookieNames",
    "REQUEST_COOKIES_NAMES": "RequestCookieKeys",
    "REQUEST_HEADERS": "RequestHeaderNames",
    "REQUEST_HEADERS_NAMES": "RequestHeaderKeys",
}

APPGW_NOT_EXCLUDABLE: dict[str, str] = {
    "REQUEST_URI": "The request URI is not an excludable match variable.",
    "REQUEST_URI_RAW": "The request URI is not an excludable match variable.",
    "REQUEST_FILENAME": "The URL path/filename is not an excludable match variable.",
    "REQUEST_LINE": "The request line is not an excludable match variable.",
    "REQUEST_METHOD": "HTTP method is not an excludable match variable; fix the client.",
    "REQUEST_BODY": "Raw request-body contents are not excludable; fix the request upstream.",
    "REQUEST_PROTOCOL": "The request protocol is not an excludable match variable.",
    "MULTIPART_STRICT_ERROR": "Multipart parse failures are not excludable; fix the upload client.",
    "XML": "XML body contents are not excludable; fix the request upstream.",
    "FILES": "Uploaded file contents are not excludable; fix the upload client upstream.",
    "TX": "Internal CRS transaction variable — not a request attribute; nothing to exclude.",
    "MATCHED_VAR": "Generic CRS matched-variable placeholder — inspect the request for the real collection.",
    "MATCHED_VAR_NAME": "Generic CRS matched-variable placeholder — inspect the request for the real collection.",
}

_MAPS = {
    FRONT_DOOR: (FRONTDOOR_PREFIX_MAP, FRONTDOOR_NOT_EXCLUDABLE),
    APP_GATEWAY: (APPGW_PREFIX_MAP, APPGW_NOT_EXCLUDABLE),
}


@dataclass(frozen=True)
class Mapping:
    excludable: bool
    match_variable: str | None = None
    selector: str | None = None
    reason: str | None = None


def map_match_variable(match_variable_name: str, waf_type: str = FRONT_DOOR) -> Mapping:
    """Translate a logged matched-variable name to a Terraform exclusion.

    Front Door ``QueryParamValue:returnUrl`` -> ``QueryStringArgNames`` + selector ``returnUrl``;
    Application Gateway ``ARGS:returnUrl`` -> ``RequestArgNames`` + selector ``returnUrl``.
    """
    prefix_map, not_excludable = _MAPS.get(waf_type, _MAPS[FRONT_DOOR])
    prefix, _, selector = match_variable_name.partition(":")
    selector = selector or None

    if prefix in not_excludable:
        return Mapping(excludable=False, reason=not_excludable[prefix])

    mv = prefix_map.get(prefix)
    if mv is None:
        return Mapping(
            excludable=False,
            reason=f"No known Terraform mapping for match variable prefix {prefix!r}.",
        )

    if selector is None:
        # e.g. a bare "HeaderName" missing-header check, or a CRS collection matched with no
        # named item: the selector can't be derived from the name alone.
        return Mapping(
            excludable=False,
            match_variable=mv,
            reason=f"{prefix!r} carries no selector in the matched variable name; "
            "inspect the matched value to choose a selector.",
        )

    return Mapping(excludable=True, match_variable=mv, selector=selector)
