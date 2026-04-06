# Contributing

Thanks for contributing to FlameGuard.

## Ground Rules

- Keep the repository safe for public open-source distribution.
- Do not commit secrets, tokens, certificates, populated `.env` files, or private keys.
- Do not commit real subscription IDs, workspace customer IDs, tenant-specific hostnames, internal email addresses, or deployment inventory copied from live environments.
- Do not commit raw customer or internal firewall exports unless they are fully sanitized.

## Before Opening a Pull Request

- Replace live cloud identifiers with placeholders.
- Sanitize sample JSON before adding it to the repo.
- Replace live firewall resource IDs, workspace IDs, and policy names in Azure Firewall log fixtures with synthetic placeholders.
- Keep deployment-specific changes in local override files such as `*.local.yaml`.
- Update documentation when behavior, configuration, or deployment steps change.
- Preserve the existing code style and keep changes focused.

## Development Notes

- Use [.env.example](.env.example) as the configuration template.
- Use the manifests in the repo as examples, not as a place to store live deployment values.
- If you add new fixtures, document whether they are synthetic or sanitized.
- Keep local export scratch data in ignored folders such as azure-exports/ or private/ rather than tracked fixtures.
- If you change LLM-bound payload construction, preserve the Azure identifier redaction in `backend/app/privacy.py` or replace it with an equivalent sanitizer.
- If you change deterministic checks, add or update tests under `backend/tests/test_analysis/`.

## Pull Request Checklist

- Code builds and relevant tests pass.
- Docs are current.
- No confidential or tenant-specific information is included.
- New public-facing files are compatible with the MIT license in [LICENSE](LICENSE).

Recommended verification commands:

```bash
cd backend
python -m pytest tests/ -q

cd ../frontend
npm run build
```