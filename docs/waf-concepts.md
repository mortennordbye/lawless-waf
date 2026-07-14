# WAF concepts this app assumes

Enough Azure WAF vocabulary to read the screens. If you tune WAFs for a living you can skip
this; if you inherited one, start here.

## Actions: why a rule can fire without blocking

Azure's default rule set is **anomaly scoring**, not one-rule-one-block. This trips people up
constantly, so it is worth being precise:

| Action in the log | What happened |
| --- | --- |
| `AnomalyScoring` | A rule matched and **added to the request's score**. On its own it blocks nothing. |
| `Block` | The combined score crossed the threshold, so the request was denied. |
| `Log` | A rule matched and was recorded. Nothing else. |

So a single request typically produces **several log rows**: one `AnomalyScoring` row per rule
that matched, plus one `Block` row (rule `949110`, group `BLOCKING-EVALUATION`) if the total
crossed the line. The block row is the verdict; the scoring rows are the reasons.

The default threshold is **5** — roughly, one "critical" rule match. The app parses the score
out of the `949110` blocking-evaluation message and shows it in the request inspector, so you
can see how much headroom a request had. A request at score 8 needs more than one exclusion
before it stops being blocked; that is why the inspector shows every rule a request tripped
rather than just the first.

Rule `949110` appearing at the top of "firing rules" is not a rule you tune. It is the
scoreboard.

## Detection vs Prevention mode

| Mode | Behaviour |
| --- | --- |
| **Detection** | Scores and logs. **Never blocks**, no matter the score. |
| **Prevention** | Actually blocks when the score crosses the threshold. |

If a policy is in Detection mode, "blocks by cause" will be empty even though rules are firing
constantly — nothing is being blocked because nothing *can* be. The app says so on the Overview
and points you at firing rules instead: those are what *would* block if you flipped to
Prevention. Tuning in Detection mode before you switch is the safe order to do this in.

The Overview shows the mode as a badge, because "why is nothing blocked?" is otherwise a
genuinely confusing five minutes.

## Exclusions: the mapping that catches everyone

An exclusion tells the WAF "do not inspect this part of the request for this rule". The catch
is that **the log names the thing that matched, and Terraform names the thing to skip** — and
they are not the same word.

The log reports `CookieValue:sessionId`, meaning "the *value* of the cookie named sessionId
matched". The exclusion you write targets the cookie **name**:

```hcl
exclusion {
  match_variable = "RequestCookieNames"   # the name, not the value
  operator       = "Equals"
  selector       = "sessionId"
}
```

This app does that translation for you (`analysis/mapping.py`). The full table:

| Log match variable | Terraform `match_variable` |
| --- | --- |
| `CookieValue` | `RequestCookieNames` |
| `QueryParamValue`, `QueryStringArgNames` | `QueryStringArgNames` |
| `PostParamValue` | `RequestBodyPostArgNames` |
| `JsonValue` | `RequestBodyJsonArgNames` |
| `RequestHeaderValue`, `HeaderValue`, `HeaderName` | `RequestHeaderNames` |

### Some things cannot be excluded at all

Not every match variable has an exclusion. When the app classifies something `not_excludable`
it tells you why rather than letting you write HCL that silently does nothing:

| Log match variable | Why not, and what to do |
| --- | --- |
| `Method` | HTTP method is not excludable; fix the client (e.g. GET→POST). |
| `URI`, `Path`, `Filename` | Not excludable match variables. |
| `InitialBodyContents` | Multipart body contents; fix the multipart boundary upstream. |
| `MultipartParamValue` | Multipart param values; fix the upload client upstream. |
| `ParseBodyError` | Body parse failures; fix the malformed body upstream. |
| `PostParamName` | Matched on a POST param *name*, not a value — not excludable as-is. |

### There are only 100 slots

Azure caps exclusions at **100 per WAF policy**. Every `exclusion` block is a slot, so writing
one per rule burns through them fast and leaves you unable to tune later. Paste your
`waf-exclusions.tf` into the coverage panel and the app counts your slots, reports what is
left, and suggests consolidations (the same selector excluded for five rules is often one
exclusion, not five).

This is why the tool pushes you to consolidate rather than generating a block per finding.

## Classification: attack, false positive, or noise

The judgement call — *is this my own traffic or someone attacking me?* — is the part that
matters and the part a machine should not make alone. The app takes a position and shows its
evidence so you can overrule it:

| Verdict | Meaning |
| --- | --- |
| `false_positive` | Looks like your own app's data (a UUID, a session token, a URL to your own domain). Candidate to exclude. |
| `attack` / `scanner_noise` | Looks like genuine attack traffic, or came overwhelmingly from a scanner IP. **Leave it blocked.** |
| `not_excludable` | No exclusion exists for this match variable (see above). |
| `unknown` | The heuristic will not guess. You decide. |

Two guardrails worth knowing:

- **Scanner segmentation runs first.** An IP hitting many rule groups across many distinct URIs
  is probing you, and its "false positives" are not false positives. Excluding a rule because a
  scanner tripped it is how you end up opening the hole the scanner was looking for. The app
  segments scanners before anything else and reports `scanner_share` per match variable.
- **`unknown` is a real answer.** The heuristic flags evidence (`uuid`, `own-domain-url`, and
  the attack patterns) rather than pretending to certainty. When it says unknown, look at the
  actual requests.

The thresholds for the scanner call (`min_blocks=20`, `min_groups=3`, `min_uris=15`) are
first-pass defaults tuned against one real dataset — see [BACKLOG.md](../BACKLOG.md).

## Where this shows up

- [Walkthrough](walkthrough.md) — all of the above on one real rule, end to end.
- The Overview's mode badges, the scanner table, and the exclusion-context classifications are
  these concepts rendered.
