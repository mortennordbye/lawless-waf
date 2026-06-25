from lawless_waf.analysis import classify, exclusions, mapping, scanner
from lawless_waf.duck import queries
from lawless_waf.sample import FP_IP, SCANNER_IP


def test_scanner_segmentation(sample_path):
    report = scanner.build_report(queries.block_events(sample_path))
    assert report.scanner_ips == [SCANNER_IP]
    assert report.genuine_fp_candidate_blocks == 3  # 2 FP + 1 not-excludable
    top = report.by_ip[0]
    assert top.ip == SCANNER_IP and top.verdict == "scanner"
    assert {v.ip: v for v in report.by_ip}[FP_IP].verdict == "fp_candidate"


def test_classify_attack_vs_fp():
    assert classify.classify_value("/.env")[0] == "attack"
    assert classify.classify_value("a' UNION SELECT 1,2--")[0] == "attack"
    assert classify.classify_value("<script>alert(1)</script>")[0] == "attack"
    assert classify.classify_value("123e4567-e89b-12d3-a456-426614174000")[0] == "false_positive"


def test_classify_trusted_domain():
    url = "https://app.example.com/landing"
    assert classify.classify_value(url)[0] == "unknown"  # not trusted by default
    assert classify.classify_value(url, trusted_domains=["example.com"])[0] == "false_positive"


def test_mapping():
    m = mapping.map_match_variable("CookieValue:sessionId")
    assert m.excludable and m.match_variable == "RequestCookieNames" and m.selector == "sessionId"
    assert mapping.map_match_variable("QueryParamValue:q").match_variable == "QueryStringArgNames"
    assert mapping.map_match_variable("JsonValue:x").match_variable == "RequestBodyJsonArgNames"


def test_mapping_not_excludable():
    for mv in ("InitialBodyContents", "Method", "ParseBodyError", "URI", "Path"):
        m = mapping.map_match_variable(mv)
        assert m.excludable is False and m.reason


def test_exclusion_count_and_hints():
    tf = (
        '{ match_variable = "RequestCookieNames" operator = "Equals" selector = "optimizelySegments" }\n'
        '{ match_variable = "RequestCookieNames" operator = "Equals" selector = "optimizelyBuckets" }\n'
        '{ match_variable = "QueryStringArgNames" operator = "Equals" selector = "returnUrl" }\n'
    )
    result = exclusions.count_exclusions(tf)
    assert result["count"] == 3
    assert result["remaining"] == 97
    hints = result["consolidation_hints"]
    assert any(h["suggestion"].startswith('consolidate into one StartsWith "optimizely"') for h in hints)
