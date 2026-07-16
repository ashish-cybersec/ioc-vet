# Releasing

`ioc-vet` publishes to PyPI via [Trusted Publishing](https://docs.pypi.org/trusted-publishers/),
so there is no API token stored in this repository. PyPI verifies the exact
owner/repo/workflow/environment via OIDC and mints a short-lived credential at
publish time. Nothing to leak, nothing to rotate.

## One-time setup

Do this once, before the first release.

### 1. Reserve the name on PyPI with a pending publisher

The project doesn't exist on PyPI yet, so use a **pending publisher** — this
both reserves the name and configures publishing in one step.

Go to <https://pypi.org/manage/account/publishing/> (you'll need a PyPI account
with 2FA enabled) and add a new pending publisher:

| Field | Value |
| ----- | ----- |
| PyPI project name | `ioc-vet` |
| Owner | `ashish-cybersec` |
| Repository name | `ioc-vet` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

All five must match exactly or the OIDC handshake is rejected.

### 2. Create the `pypi` environment on GitHub

Repo **Settings → Environments → New environment**, named `pypi`.

Optional but worth considering: add yourself as a required reviewer. Publishing
to PyPI is irreversible — a version number can never be reused, even after
deletion — so a manual approval gate before the upload is cheap insurance.

## Cutting a release

1. Bump `version` in `pyproject.toml` (e.g. `0.1.0` → `0.2.0`).
2. Commit it: `git commit -am "chore: bump version to 0.2.0"`
3. Push to `main`.
4. Tag and push the tag:

   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

The `Release` workflow then runs the full 3.10/3.11/3.12 test matrix, verifies
the tag matches `pyproject.toml`, builds an sdist and wheel, runs `twine check`,
and publishes.

The tag must match the version in `pyproject.toml` — the workflow fails loudly
if they disagree, rather than quietly shipping the wrong version number.

## License metadata

`pyproject.toml` declares the license as a PEP 639 SPDX expression
(`license = "MIT"` plus `license-files = ["LICENSE"]`), and deliberately does
**not** carry a `License :: OSI Approved :: MIT License` classifier.

That's not a style preference. PEP 639 requires PyPI to *reject* any upload
that includes both a `License-Expression` field and a license classifier, and
`twine check` does not catch the conflict — so it would only surface at upload
time, after the full test matrix had passed. The release workflow checks the
built metadata for this explicitly. Don't re-add the classifier.

## Versioning

[Semantic versioning](https://semver.org/). While at `0.x`, the CLI surface is
still allowed to change; treat verdict-mapping changes as breaking, since
people pipe `--json` and gate CI on `--fail-on-malicious`.

## If a release goes wrong

You **cannot** re-upload a version that already exists on PyPI, even if you
delete it. Bump to the next patch version and tag again.
