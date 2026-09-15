# Gallery cross-repository contract

This directory is the canonical frozen contract shared by:

- `df_blog`: Nitro `/api/gallery` and the gallery client.
- `assets-auth`: Worker `/api/gallery` and `/api/image/:key`.

The files are intentionally data-only so both repositories can copy and verify
the same bytes:

- `contract.json`: fields, cache TTLs, HTTP semantics, status mappings and
  frontend recovery actions.
- `signing-vectors.json`: deterministic HMAC-SHA-256 vectors. The secret is a
  public test value and must never be used in production.
- `response-fixtures.json`: representative success, pagination, conditional
  request, range and error payloads.

`status` changes to `frozen` only after both repositories contain byte-identical
copies and both verification commands pass.
