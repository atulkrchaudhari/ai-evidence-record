# Contributing

AER is a draft. The most useful contributions right now are critical readings of the specification.

## Commenting on the specification

Open an issue that names the section and says what is unclear, wrong or missing. Useful questions to test it against:

- Could two careful implementers read this section differently?
- Is there an attack on the log that verification does not report?
- Is there something a real system needs to record that has no place in a record and does not belong in `ext`?

## Changing the specification

A change to `SPEC.md` that affects what is valid needs, in the same pull request,

1. the matching change to the reference implementation in `src/aer/`,
2. the matching change to the JSON Schemas in `schema/`,
3. new or updated cases in `test-vectors/generate.py`, with the vectors regenerated, and
4. an entry in `CHANGELOG.md`.

The test suite checks that the schemas and the reference validator agree, and that the committed vectors match what the generator produces.

## Other implementations

If you implement AER in another language, open an issue with a link. Conforming implementations will be listed in the README.

## Code

```
pip install -e ".[dev]"
ruff check .
pytest
```

- The core (`canonical`, `record`, `chain`) uses the standard library only. Keep it that way.
- Test vectors use reserved example domains and published test keys. Never commit a real key or real personal data.
