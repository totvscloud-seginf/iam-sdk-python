# Example

## Using the SDK


### Login

```python
import logging
import iam_sdk_python

logging.basicConfig()

logging.getLogger().setLevel(logging.DEBUG)

username = "fcd1e1c88bbe4053a8117aa070595065"
password = "dd16b129283964f76c0114b3dec93eed40d0a5871cf94c0e971ac192f3c8d854"

client = iam_sdk_python.client(
    api_access_key=username,
    api_secret_key=password,
)

client.login()
print(client.token)
'''
DEBUG:urllib3.connectionpool:Starting new HTTP connection (1): localhost:9000
DEBUG:urllib3.connectionpool:http://localhost:9000 "POST /api/login HTTP/1.1" 200 1438
DEBUG:iam_sdk_python.api:validate login response
eyJhbGciOiJSUzI1NiIsImtpZCI6IjkyZDA0ZTk4LTgxMTEtNGZkMi04M2IxLTNiNThkYTI1NDhjNyIsInR5cCI6IkpXVCJ9.eyJhdWQiOltdLCJjbGllbnRfaWQiOiI1M2ExNDE3Yi01NjI1LTQ3YTEtOTcxNy1hMjhhNDcwYmIxNDkiLCJleHAiOjE2OTkwMjc4OTIsImV4dCI6eyJtZmEiOiJ1bmtub3duIiwicHJpbmNpcGFsIjoidHJuOjp0Y2xvdWQ6OmlhbTo6Ojpjc2VpbmY6OnVzZXI6OlwidXNlcmFwaTJcIiIsInRlbmFudCI6ImNzZWluZiIsInVzZXJfaWQiOiJkNGUxNzkxOC01YzAzLTRlNTYtYmJlNy01YTVkNDBkOWU3MjQiLCJ1c2VybmFtZSI6InVzZXJhcGkyIn0sImlhdCI6MTY5OTAyNDI5MiwiaXNzIjoiaHR0cDovLzEyNy4wLjAuMTo0NDQ0IiwianRpIjoiNjFhOGQzMzktOTk4OS00ODRjLWFkM2QtMWM1ZWZhYTRhZjAxIiwibmJmIjoxNjk5MDI0MjkyLCJzY3AiOltdLCJzdWIiOiI1M2ExNDE3Yi01NjI1LTQ3YTEtOTcxNy1hMjhhNDcwYmIxNDkifQ.kxRzNYxxlrCDCxlFzPpmRF_V0bHXRfo1SSNy520MGYGOhvzIQzqVyPLPliVv3MFGvHVwGOstGBgXaIGhGMnuPCYHU6Xv5BYjlpF4qa4KvaamuEV4v0JOjIzZ0b5gDE0GrG4dit_INnwxDr8D1fCKk_UOdUy6-1jXktbbSvIIrxlKpfI3E2GqfrCx7zMVSyCPf7OrlHvYOCMKYF1FFSjxlkcvT2kc4UIL1W_MUi4Egd9kT1Rwygy4f0JSMtD2oQ_DtDQTyvKOMrF-mHgN4VhuQOHNuS8b1xxItNacFQO-ktTpDG3flLJLQypCMqmbRiQrwX5vlxw0xrysKdhy7BGu0Yj25IoDH1TbnaQWwZpxtaeChf3DsEsr2qRIn_9Ygn_wnNiSoiqtlgZqRjxgQLck6JUV1U1fw3GclbUmQi3QzxBkWrk-t4hkjzYbVJNhNZT5dNrUKPcvCQPX2KMykB4mXTPY9sUMGJxXFmM07DqmGrdfStZQ1POStloUekydcjbrDm7wSjQUmvJegXkoiPsYJaLJgDwgvCpQSlco0fxd3l23ixLB_ZpZJtzlCaQntqeqydhUOM2ESP7uczfi9Je1XJT3j1jJaSLmTqOTE4QQFRS-9Fe5Y3Nfk0VSIPZAj2HVQK5_2mYyZ2REGQwcWHM2n1u5gYEz80aCrLvUFDrIzIw
'''

```

### Validate token

```python

client.validate_token()

'''
DEBUG:iam_sdk_python.api:requesting validate token
DEBUG:urllib3.connectionpool:Starting new HTTP connection (1): localhost:9000
DEBUG:urllib3.connectionpool:http://localhost:9000 "GET /api/oauth2/introspection HTTP/1.1" 200 459
DEBUG:iam_sdk_python.api:validate introspection response
{'aud': [],
 'client_id': '53a1417b-5625-47a1-9717-a28a470bb149',
 'exp': 1699027892,
 'ext': {'mfa': 'unknown',
  'principal': 'trn::tcloud::iam::::cseinf::user::"userapi2"',
  'tenant': 'cseinf',
  'user_id': 'd4e17918-5c03-4e56-bbe7-5a5d40d9e724',
  'username': 'userapi2'},
 'iat': 1699024292,
 'iss': 'http://127.0.0.1:4444',
 'jti': '61a8d339-9989-484c-ad3d-1c5efaa4af01',
 'nbf': 1699024292,
 'scp': [],
 'sub': '53a1417b-5625-47a1-9717-a28a470bb149'}
'''
```

### List roles

```python

client.list_my_roles()
'''
INFO:iam_sdk_python.api:requesting user roles
DEBUG:urllib3.connectionpool:Starting new HTTP connection (1): localhost:9000
DEBUG:urllib3.connectionpool:http://localhost:9000 "GET /api/me/roles HTTP/1.1" 200 118
DEBUG:iam_sdk_python.api:validate my roles response
[{'rolename': 'teste', 'tenant_id': 'cseinf', 'session_duration': 1}]
'''

```

### Assume role

```python

client.assume_role(role_name="teste", tenant="cseinf").validate_token()
'''
DEBUG:iam_sdk_python.api:requesting assume role
DEBUG:urllib3.connectionpool:Starting new HTTP connection (1): localhost:9000
DEBUG:urllib3.connectionpool:http://localhost:9000 "POST /api/login/assumerole HTTP/1.1" 200 1800
DEBUG:iam_sdk_python.api:validate assume role response
DEBUG:iam_sdk_python.api:requesting validate token
DEBUG:urllib3.connectionpool:Starting new HTTP connection (1): localhost:9000
DEBUG:urllib3.connectionpool:http://localhost:9000 "GET /api/oauth2/introspection HTTP/1.1" 200 731
DEBUG:iam_sdk_python.api:validate introspection response
{'aud': [],
 'client_id': '8f311f1b-0d49-4a35-8cc1-0a4dac4bd2aa',
 'exp': 1699028285,
 'ext': {'client_id': '53a1417b-5625-47a1-9717-a28a470bb149',
  'mfa': 'unknown',
  'previous_session': {'mfa': 'unknown',
   'principal': 'trn::tcloud::iam::::cseinf::user::"userapi2"',
   'tenant': 'cseinf',
   'user_id': 'd4e17918-5c03-4e56-bbe7-5a5d40d9e724',
   'username': 'userapi2'},
  'principal': 'trn::tcloud::iam::::cseinf::role::"role/teste"',
  'scp': [],
  'sub': '53a1417b-5625-47a1-9717-a28a470bb149',
  'tenant': 'cseinf',
  'user_id': 'd4e17918-5c03-4e56-bbe7-5a5d40d9e724'},
 'iat': 1699024685,
 'iss': 'http://127.0.0.1:4444',
 'jti': '689570e5-0be9-4ee5-9e73-3bb5381baa95',
 'nbf': 1699024685,
 'scp': [],
 'sub': '8f311f1b-0d49-4a35-8cc1-0a4dac4bd2aa'}
'''

```

### Check authorization / permission

```python
import iam_sdk_python
from iam_sdk_python.context import ContextCallerForward

client = iam_sdk_python.client(
    api_access_key=api_access_key,
    api_secret_key=api_secret_key,
).login()

caller_context = ContextCallerForward(
    caller_token_jwt="eyJhbGciOiJIUzI1Ni....",
    caller_source_ip="192.0.0.1",
    caller_user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
    caller_referer="localhost",
    caller_resource_tenant="CCODE9",
)

action = 'Service::Nostromos::Action::"CreateDatabase2"'
resource = 'Database::"Mysql"'
additional_context = {"requestedRegion": "tesp1"}

# bool response
valid = client.is_authorized_to_call_action(
    caller=caller_context,
    action=action,
    resource=resource,
    additional_context=additional_context,
)

```


### Exception when listing roles

```python

# try to list which roles, the assume role can use
# must happen an exception
client.list_my_roles()
'''
INFO:iam_sdk_python.api:requesting user roles
DEBUG:urllib3.connectionpool:Starting new HTTP connection (1): localhost:9000
DEBUG:urllib3.connectionpool:http://localhost:9000 "GET /api/me/roles HTTP/1.1" 400 43
DEBUG:iam_sdk_python.api:validate my roles response
ERROR:iam_sdk_python.api:my roles contains invalid response
{
	"name": "InvalidRequestError",
	"message": "(InvalidRequestError(...), 'Invalid API Request, received http 400\
API Response: {\"error\":true,\"message\":\"malformed token\"}\
')",
	"stack": "---------------------------------------------------------------------------
InvalidRequestError                       Traceback (most recent call last)
c:\\project\\iam--sdk-python\\test.ipynb Cell 8 line <cell line: 1>()
----> <a href='vscode-notebook-cell:/c%3A/project/iam--sdk-python/test.ipynb#X13sZmlsZQ%3D%3D?line=0'>1</a> client.list_my_roles()

File c:\\project\\iam--sdk-python\\iam_sdk_python\\api.py:122, in Client.list_my_roles(self)
    114 logger.info(\"requesting user roles\")
    116 resp = requests.get(
    117     url,
    118     headers={\"Authorization\": f\"Bearer {self._token}\"},
    119     verify=self._validate_ssl,
    120 )
--> 122 roles = self._validate_api_response(\"my roles\", resp)[\"data\"][\"roles\"]
    124 return roles

File c:\\project\\iam--sdk-python\\iam_sdk_python\\api.py:176, in Client._validate_api_response(self, api_name, resp)
    170         raise NotAuthorizedException(message=api_response_text)
    172     if (
    173         api_status_code == HTTPStatus.BAD_REQUEST
    174         or api_status_code >= HTTPStatus.INTERNAL_SERVER_ERROR
    175     ):
--> 176         raise InvalidRequestError(
    177             status_code=api_status_code, message=api_response_text
    178         )
    180 return resp.json()

InvalidRequestError: (InvalidRequestError(...), 'Invalid API Request, received http 400\
API Response: {\"error\":true,\"message\":\"malformed token\"}\
')"
}
'''

```
