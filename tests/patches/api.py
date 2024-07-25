import json
from tests.patches.http import FakeObject


def mock_get(url, **kargs):
    if url.endswith("/me/roles"):
        response = json.dumps(
            {
                "data": {
                    "roles": [
                        {
                            "role": "trn:tcloud:iam::cseinf:role/role_client_123",
                            "rolename": "role_client_123",
                            "tenant_id": "cseinf",
                            "session_duration": 1,
                        }
                    ]
                },
                "error": False,
                "message": "success",
            }
        )
        return FakeObject(
            response=response,
            status_code=200,
            headers={
                "x-content-type-options": "nosniff",
            },
        )

    if url.endswith("/token/validate"):
        response = json.dumps(
            {
                "data": {
                    "active": True,
                    "aud": [],
                    "client_id": "d517a500-5a84-430f-9f14-27946af6bdf1",
                    "exp": 1692310848,
                    "ext": {
                        "at_hash": "y928EynecGd71lf65yhmrA",
                        "email": "luser@totvs.com.br",
                        "email_verified": True,
                        "role": "role1",
                        "sub": "ChpsZWFuZHJvLmNvc3RhQHRvdHZzLmNvbS5ichIkOTc4MTdlMmUtZjJiMy00ODRjLWJiMjUtYWU2OTk2MTUwNTA1",
                        "tenant": "cseinf",
                    },
                    "iat": 1692307248,
                    "iss": "http://127.0.0.1:4444",
                    "nbf": 1692307248,
                    "sub": "d517a500-5a84-430f-9f14-27946af6bdf1",
                    "token_type": "Bearer",
                    "token_use": "access_token",
                },
                "error": False,
                "message": "success",
            }
        )
        return FakeObject(
            response=response,
            status_code=200,
            headers={
                "x-content-type-options": "nosniff",
            },
        )

    raise Exception("endpoint mock not found")


def mock_get_invalid_token(url, **kargs):
    if url.endswith("/token/validate"):
        response = json.dumps("")
        return FakeObject(
            response=response,
            status_code=401,
            headers={
                "x-content-type-options": "nosniff",
            },
        )

    raise Exception("endpoint mock not found")


def mock_post(url, **kargs):
    if url.endswith("/is_authorized"):
        # {"decision": "Allow", "diagnostics": {"reason": ["ebbae3f4-9228-4f53-b953-5759bd1e9a1c"],"errors": []}}
        response = json.dumps(
            {"decision": "Deny", "diagnostics": {"reason": [], "errors": []}}
        )
        return FakeObject(
            response=response,
            status_code=200,
            headers={
                "content-type": "application/json",
                "server": "Rocket",
                "x-frame-options": "SAMEORIGIN",
                "permissions-policy": "interest-cohort=()",
                "x-content-type-options": "nosniff",
                "content-length": "59",
                "content-length": "59",
                "date": "Thu, 23 Nov 2023 13:20:59 GMT",
            },
        )

    if url.endswith("/login"):
        response = json.dumps(
            {
                "data": {
                    "access_token": "token jwt",
                    "expires_in": 3599,
                    "token_type": "bearer",
                },
                "error": False,
                "message": "success",
            }
        )
        return FakeObject(
            response=response,
            status_code=200,
            headers={
                "content-type": "application/json",
            },
        )

    if url.endswith("/users/mock/accesskey"):
        response = '{"status": "success", "message": "ok", "data": {"accessSecretKey": "uniqSecret", "accessKeyId": "uniqId"}}'
        return FakeObject(response=response, status_code=200)

    raise Exception("endpoint mock not found")


def mock_post_login_invalid(url, **kargs):
    if url.endswith("/login"):
        response = json.dumps(
            {"error": True, "message": "invalid username or password"}
        )
        return FakeObject(
            response=response,
            status_code=400,
            headers={
                "content-type": "application/json",
            },
        )

    raise Exception("endpoint mock not found")


def mock_post_assumerole(url, **kargs):
    if url.endswith("/login"):
        response = json.dumps(
            {
                "data": {
                    "access_token": "token jwt",
                    "expires_in": 3599,
                    "token_type": "bearer",
                },
                "error": False,
                "message": "success",
            }
        )
        return FakeObject(
            response=response,
            status_code=200,
            headers={
                "content-type": "application/json",
            },
        )

    if url.endswith("/login/assumerole"):
        response = json.dumps(
            {
                "data": {
                    "access_token": "token jwt",
                    "expires_in": 3599,
                    "token_type": "bearer",
                },
                "error": False,
                "message": "success",
            }
        )
        return FakeObject(
            response=response,
            status_code=200,
            headers={
                "content-type": "application/json",
            },
        )

    raise Exception("endpoint mock not found")


def mock_post_assumerole_forbidden(url, **kargs):
    if url.endswith("/login"):
        response = json.dumps(
            {
                "data": {
                    "access_token": "token jwt",
                    "expires_in": 3599,
                    "token_type": "bearer",
                },
                "error": False,
                "message": "success",
            }
        )
        return FakeObject(
            response=response,
            status_code=200,
            headers={
                "content-type": "application/json",
            },
        )

    if url.endswith("/login/assumerole"):
        response = json.dumps(
            {"error": True, "message": "not authorized to assume role"}
        )
        return FakeObject(
            response=response,
            status_code=403,
            headers={
                "content-type": "application/json",
            },
        )

    raise Exception("endpoint mock not found")


def mock_generic_get(url, **kargs):
    response = json.dumps(
        {
            "data": [{"fake": True}],
            "meta": {
                "size": 10,
                "page": 1,
                "total": 10,
                "totalPages": 1,
                "links": {
                    "self": "/roles/object/policies?page[number]=1&page[size]=10",
                    "first": "/roles/object/policies?page[number]=1&page[size]=10",
                    "prev": None,
                    "next": None,
                    "last": "/roles/object/policies?page[number]=1&page[size]=10",
                },
            },
            "error": False,
            "message": "success",
        }
    )
    return FakeObject(
        response=response,
        status_code=200,
        headers={},
    )


def mock_generic_post(url, **kargs):
    response = json.dumps(
        {
            "error": False,
            "message": "success",
            "username": "",
            "data": {
                "fake": True,
            },
        }
    )
    return FakeObject(
        response=response,
        status_code=200,
        headers={},
    )
