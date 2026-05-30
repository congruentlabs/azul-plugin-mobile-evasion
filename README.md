# azul-plugin-mobile-evasion

Azul plugin for identifying mobile anti-analysis and environment-evasion indicators in Android and iOS app packages.

The plugin performs static evidence scanning across APK/IPA contents and reports indicators such as:

- Android emulator checks
- Android root checks
- Android app integrity and attestation checks
- iOS simulator checks
- iOS jailbreak checks
- debugger and instrumentation checks

The plugin is intentionally separate from `azul-plugin-mobsf` so MobSF can remain focused on MobSF report extraction while this plugin owns mobile evasion-specific detection logic.

## Development

Create a Python 3.12 virtual environment and install development dependencies:

```bash
python -m pip install uv
uv sync --group dev
```

Run tests and style checks:

```bash
tox -e test
tox -e style
```
