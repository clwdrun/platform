# Public Suffix List submission (draft, for the domain owner to submit)

Replace `<apps domain>` with the registered domain before submitting.

## The entry, in the PRIVATE section

```
// clwd : https://clwd.run
// Submitted by <owner name> <owner email>
*.<apps domain>
```

## PR description

**Organization website:** https://clwd.run

**Reason for PSL inclusion:** `<apps domain>` hosts applications written and
deployed by our customers at `{app}.{org}.<apps domain>`. Each application is
untrusted code serving HTML and JavaScript to its visitors. Without a PSL entry,
browsers treat all of them as one site, so one application can set cookies that
another receives, share storage and renderer processes with it, and get the whole
domain blocklisted. We need each application to be its own site, which is why the
entry is the wildcard `*.<apps domain>`: every `{org}.<apps domain>` becomes a
public suffix, and each `{app}.{org}.<apps domain>` a separate registrable domain.

This is the same isolation `github.io`, `vercel.app` and `pages.dev` rely on. It is
not to change any certificate authority's rate limits.

**DNS verification:** `_psl.<apps domain>` carries a TXT record with this PR's URL.
We will leave it in place.

**Registration:** `<apps domain>` is registered until `<date, more than two years
out>`, with auto-renew. We commit to keeping more than one year of registration at
all times.

**Expected results:**

| Input | Public suffix | Registrable domain |
|---|---|---|
| `notes.acme.<apps domain>` | `acme.<apps domain>` | `notes.acme.<apps domain>` |
| `dashboard.other.<apps domain>` | `other.<apps domain>` | `dashboard.other.<apps domain>` |
| `<apps domain>` | `<apps domain>` | (none) |

## DNS records for `<apps domain>`

```
_psl.<apps domain>.        TXT   "https://github.com/publicsuffix/list/pull/<number>"
<apps domain>.             CAA   0 issue "letsencrypt.org"
<apps domain>.             CAA   0 issuewild "letsencrypt.org"
*.<apps domain>.           (the gateway's address records, per environment)
```

The ACME DNS-01 records (`_acme-challenge.{org}.<apps domain>`) are written by the
platform with an API token scoped to this zone only.
