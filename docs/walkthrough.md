# Walkthrough: one false positive, start to finish

This is the whole loop on the bundled sample data. No Azure, no risk, about five minutes.
Every number below is what the app actually returns for the seeded day, so you can check your
screen against the page as you go.

Either start it with one command:

```bash
docker run --rm -p 127.0.0.1:8000:8000 -e SEED_SAMPLE=true ghcr.io/mortennordbye/lawless-waf:latest
# -> http://localhost:8000
```

…or from a clone, if you want hot reload:

```bash
make seed   # writes two synthetic days: 2026-06-24 and 2026-06-25
make up     # -> http://localhost:5173
```

The two days are the before and after: `2026-06-24` has a false positive firing, and
`2026-06-25` is the same traffic with that one FP fixed. That is what makes step 5 work.

Open **Analyze** and pick `2026-06-24` from the Dataset dropdown.

---

## 1. Overview: what the WAF did

48 events: **23 blocked**, 23 anomaly-scored, 2 logged, across 3 client IPs and 4 rules.

The four coloured tiles drill down — click **Blocked** to see the 23 block events. Everything
here is scoped by the bar above (WAF policy, or several days at once).

If you are new to `Block` vs `AnomalyScoring` vs `Log`, read
[WAF concepts](waf-concepts.md) first; it is short and the rest of this makes more sense after.

## 2. Scanner segmentation: read this first

Always. This is the step that stops you punching a hole in the WAF for an attacker:

| Client IP | Blocks | Rule groups | Rules | URIs | Verdict |
| --- | --- | --- | --- | --- | --- |
| 203.0.113.7 | 20 | 3 | 3 | 20 | `scanner` |
| 198.51.100.10 | 2 | 1 | 1 | 1 | `fp_candidate` |
| 198.51.100.11 | 1 | 1 | 1 | 1 | `fp_candidate` |

`203.0.113.7` sprays 3 rule groups across 20 URIs — that is someone probing you, not your app
misbehaving. Of 23 blocks, only **3 are genuine FP candidates**. Never write an exclusion for a
scanner IP: you would be disabling a rule that is doing its job.

## 3. Blocks by cause: what blocks real traffic

With scanners excluded, one rule is left:

| Rule | Group | Message | Hits | IPs |
| --- | --- | --- | --- | --- |
| 942100 | SQLI | SQL Injection | 3 | 2 |

Click **Investigate** (or **Context**) on it.

## 4. Exclusion context: the deliverable

This is the point of the tool. Rule 942100 fires on **three different match variables**, and
they get three different verdicts:

| Match variable | Classification | Hits | Scanner share |
| --- | --- | --- | --- |
| `QueryParamValue:q` | `scanner_noise` | 7 | 100% |
| `CookieValue:sessionId` | `false_positive` | 2 | 0% |
| `InitialBodyContents` | `not_excludable` | 1 | 0% |

Read that carefully, because it is the whole argument for the tool:

- **`QueryParamValue:q`** — sample value `1 UNION SELECT password FROM users`, hit only by the
  scanner IP, across 5+ URIs. That is a real SQL injection attempt. Excluding it would be a
  genuine security hole. It has a valid Terraform mapping and it would be easy to exclude by
  mistake — the classification is what stops you.
- **`CookieValue:sessionId`** — sample value `123e4567-e89b-12d3-a456-426614174000`, evidence
  `uuid`, one URI (`/account`), no scanner traffic. That is your own session cookie tripping a
  SQLI pattern. **This is the false positive**, and the only thing here you should exclude.
- **`InitialBodyContents`** — not excludable at all. Azure has no exclusion for multipart body
  contents; the app tells you why instead of letting you write something that silently does
  nothing: *"Multipart body contents are not excludable; fix the multipart boundary upstream."*

One rule, one screen, three completely different correct actions. That is the judgement call
this app front-loads for you.

### Write the exclusion

The context hands you the mapping — log `CookieValue:sessionId` becomes Terraform
`match_variable = "RequestCookieNames"` with `selector = "sessionId"` and operator `Equals`.
You write the HCL (the app deliberately does not generate it):

```hcl
exclusion {
  match_variable = "RequestCookieNames"
  operator       = "Equals"
  selector       = "sessionId"
}
```

Note the mapping is not a rename: the log reports the *value* that matched
(`CookieValue:...`), while Terraform excludes by cookie *name* (`RequestCookieNames`). Getting
that wrong is the classic way an exclusion ends up doing nothing.

### Check it against what you already have

Paste your `waf-exclusions.tf` into **Existing exclusions coverage**. With just the block
above, the app reports `1` exclusion, `99` slots remaining, and:

| Match variable | Classification | Covered? |
| --- | --- | --- |
| `CookieValue:sessionId` | `false_positive` | covered by `RequestCookieNames` / `Equals` / `sessionId` |
| `QueryParamValue:q` | `scanner_noise` | not covered — correct, leave it |
| `InitialBodyContents` | `not_excludable` | not covered — cannot be |

So the work is done, and nothing that should stay blocked got excluded.

## 5. Verify with a diff

Apply the Terraform, wait for a fresh window, then compare. The sample fakes this for you:
`2026-06-25` is the same day with that FP fixed. In the scope bar set **Compare against**
`2026-06-25` (or hit the API directly):

Rule level:

| Rule | Group | Before | After | Status |
| --- | --- | --- | --- | --- |
| 942100 | SQLI | 11 | 9 | `reduced` |
| 949110 | BLOCKING-EVALUATION | 23 | 21 | `reduced` |
| 930100 | LFI | 6 | 6 | `unchanged` |
| 941100 | XSS | 8 | 8 | `unchanged` |

**942100 says `reduced`, not `resolved` — and that is the right answer.** The rule still fires,
because the scanner is still throwing SQL injection at you and the WAF is still blocking it.
You did not want that to stop.

Drill into the rule's own diff to see what actually changed:

| Match variable | Before | After | Status |
| --- | --- | --- | --- |
| `CookieValue:sessionId` | 2 | 0 | **`resolved`** |
| `QueryParamValue:q` | 7 | 7 | `unchanged` |
| `InitialBodyContents` | 1 | 1 | `unchanged` |

The false positive is gone, the attack is still blocked. That is what "done" looks like.

---

## Reading the events themselves

Anywhere you see a table of WAF entries:

- **Filter these rows** narrows what is already on screen — instant, no refetch, and it cannot
  push anything past the server-side cap.
- **Click any rule / IP / host** in a row to filter to it.
- **Fullscreen** expands the table to the whole window (Esc to leave). Your filter and sort
  survive the toggle.
- **Hover a row** for copy buttons on the client IP and URI.
- The **request** button opens the full request: every rule it tripped, the matched variables,
  the anomaly score, and **Copy as JSON**.

## Next

- Point it at your own logs: [README → Running against real Azure](../README.md#running-against-real-azure).
- Hand the loop to an agent: [README → Use it from an AI agent (MCP)](../README.md#use-it-from-an-ai-agent-mcp).
- Stuck: [Troubleshooting](troubleshooting.md).
