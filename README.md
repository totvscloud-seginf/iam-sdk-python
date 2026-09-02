# iam-sdk-python

## Getting Started
Assuming that you have a supported version of Python installed, you can first
set up your environment with:

```sh
$ python -m venv .venv
...
$ . .venv/bin/activate
```

Then, you can install boto3 from PyPI with:

```sh
$ python -m pip install iam-sdk-python
```


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
