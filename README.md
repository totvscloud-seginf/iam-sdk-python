# iam-sdk-python

## Getting Started
Assuming that you have a supported version of Python installed, you can first
set up your environment with:

```sh
$ python -m venv .venv
...
$ . .venv/bin/activate
```

Then, install the SDK from the GitHub repository (pin a release tag, e.g. `0.5.0`, tags have no `v` prefix):

```sh
# pip
$ python -m pip install "iam-sdk-python @ git+https://github.com/totvscloud-seginf/iam-sdk-python.git@0.5.0"

# uv
$ uv add "iam-sdk-python @ git+https://github.com/totvscloud-seginf/iam-sdk-python.git@0.5.0"
```

In `pyproject.toml` (PEP 621):

```toml
dependencies = [
    "iam-sdk-python @ git+https://github.com/totvscloud-seginf/iam-sdk-python.git@0.5.0",
]
```

With Poetry:

```toml
iam-sdk-python = { git = "https://github.com/totvscloud-seginf/iam-sdk-python.git", tag = "0.5.0" }
```

Wheels and sdists are also attached to each GitHub Release, and can be installed
directly from the asset URL:

```sh
$ python -m pip install https://github.com/totvscloud-seginf/iam-sdk-python/releases/download/0.5.0/iam_sdk_python-0.5.0-py3-none-any.whl
```

> **Note:** new versions are no longer published to PyPI. Replace any
> `iam-sdk-python>=x.y` requirement that resolves from PyPI with one of the
> GitHub references above, otherwise you will stay on the last PyPI release.


## Using the SDK

More examples [docs/example.md](docs/example.md)

```python
import iam_sdk

username = "fcd1e1..."
password = "dd16b1..."

client = iam_sdk.client(
    api_access_key=username,
    api_secret_key=password,
)

client.login()
```

## Debug logging

Credentials and tokens are redacted from the SDK logs, so enabling
`logging.DEBUG` is safe by default:

```
DEBUG:iam_sdk.api:Body request: {'username': 'fcd1e1c8...', 'password': '***REDACTED***'}
```

To see the real values while troubleshooting, pass
`unsafe_debug_logging=True` to `iam_sdk.client()` or export
`IAM_SDK_UNSAFE_DEBUG_LOGGING=true`. A warning is logged when it is enabled -
never use it in production.

To keep an audit trail of *who* performed each action without exposing the
token, the SDK logs the identity claims of the token at INFO (enabled by
default):

```
INFO:iam_sdk.api:login requested by: {'username': 'userapi', 'email': 'luser@totvs.com.br', 'tenant': 'cseinf', ...}
```

Those claims may carry personal data, so pass `log_caller_identity=False` or
export `IAM_SDK_LOG_CALLER_IDENTITY=false` to turn the trail off.

See [docs/example.md](docs/example.md) for details.
