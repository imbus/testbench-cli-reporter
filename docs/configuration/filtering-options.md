---
sidebar_position: 2
title: FilteringOptions payload
---

Some subcommands accept `--filtering`, which is a **base64 encoded JSON** payload describing `FilteringOptions`.

## JSON shape

```json
{
  "appliedFilters": [
    {
      "name": "automatisiert keyword",
      "filterType": "TestTheme",
      "testThemeUID": "itb-TT-1234"
    }
  ]
}
```

- `filterType` must be one of: `TestTheme`, `TestCaseSet`, `TestCase`.

:::note

   At the moment `excludedTestThemes` and `labelFilter` are not supported by the CLI.

:::

## Encoding

The CLI supports standard base64 and URL-safe base64.

Example (macOS/Linux):

```bash
json='{"appliedFilters":[],"excludedTestThemes":[],"labelFilter":"smoke"}'
python - <<'PY'
import base64, os
raw = os.environ['json'].encode('utf-8')
print(base64.urlsafe_b64encode(raw).decode('ascii').rstrip('='))
PY
```

Then pass the output to `--filtering`.
