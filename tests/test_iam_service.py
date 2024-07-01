import unittest
import traceback
from unittest.mock import patch

from tests.patches import api as patch_api

import iam_sdk


class TestIamServiceApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = iam_sdk.client(
            endpoint_authn="http://localhost:80",
            endpoint_authz="http://localhost:80",
            endpoint_cp="http://localhost:80",
            api_access_key="a",
            api_secret_key="a",
            validate_ssl=False,
        )

    @patch("iam_sdk.api.requests.post", patch_api.mock_post)
    def test_iam_api_create_user_access_key(self):
        client = self.client.iam
        try:
            resp = client.create_user_access_key("mock", " ")
            self.assertEqual(
                resp["accessKeyId"], "uniqId", "expected result from dict is invalid"
            )
            self.assertEqual(
                resp["accessSecretKey"],
                "uniqSecret",
                "expected result from dict is invalid",
            )
        except Exception:
            self.fail(
                f"create_user_access_key() got exception: {traceback.format_exc()}"
            )

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_attach_role_policies(self):
        try:
            client = self.client.iam
            client.attach_role_policies(
                role_name="name", policies_trn=["trn:tenant::iam::global:policy/name"]
            )
        except Exception:
            self.fail(f"attach_role_policies() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_attach_user_groups(self):
        try:
            client = self.client.iam
            client.attach_user_groups(username="name", groups=["group"])
        except Exception:
            self.fail(f"attach_user_groups() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_attach_user_policies(self):
        try:
            client = self.client.iam
            client.attach_user_policies(
                username="name", policies_trn=["trn:tenant::iam::global:policy/name"]
            )
        except Exception:
            self.fail(f"attach_user_policies() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_create_group(self):
        try:
            client = self.client.iam
            client.create_group(name="name", description="teste")
        except Exception:
            self.fail(f"create_group() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_create_policy(self):
        try:
            client = self.client.iam
            client.create_policy(
                name="name",
                description="teste",
                policies_statements=[
                    {
                        "Effect": "permit",
                        "Principal": "*",
                        "Action": "*",
                        "Resource": "*",
                        "Condition": [],
                    }
                ],
            )
        except Exception:
            self.fail(f"create_policy() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_create_role(self):
        try:
            client = self.client.iam
            client.create_role(
                name="name",
                role_type="role",
                trust_policy={
                    "Effect": "permit",
                    "Principal": "*",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": [],
                },
            )
        except Exception:
            self.fail(f"create_role() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_create_service(self):
        try:
            client = self.client.iam
            client.create_service(
                name="name", service_type="global", permission_manifest=[]
            )
        except Exception:
            self.fail(f"create_service() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_create_user(self):
        try:
            client = self.client.iam
            client.create_user(username="name")
        except Exception:
            self.fail(f"create_user() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_create_user_access_key(self):
        try:
            client = self.client.iam
            client.create_user_access_key(username="name", description="test")
        except Exception:
            self.fail(
                f"create_user_access_key() got exception: {traceback.format_exc()}"
            )

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.delete", patch_api.mock_generic_post)
    def test_delete_group(self):
        try:
            client = self.client.iam
            client.delete_group(group_name="group")
        except Exception:
            self.fail(f"delete_group() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.delete", patch_api.mock_generic_post)
    def test_delete_policy(self):
        try:
            client = self.client.iam
            client.delete_policy(policy_trn="trn:tenant::iam::global:policy/name")
        except Exception:
            self.fail(f"delete_policy() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.delete", patch_api.mock_generic_post)
    def test_delete_role(self):
        try:
            client = self.client.iam
            client.delete_role(role_name="role")
        except Exception:
            self.fail(f"delete_role() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.delete", patch_api.mock_generic_post)
    def test_delete_service(self):
        try:
            client = self.client.iam
            client.delete_service(service_name="name")
        except Exception:
            self.fail(f"delete_service() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.delete", patch_api.mock_generic_post)
    def test_delete_user(self):
        try:
            client = self.client.iam
            client.delete_user(username="user")
        except Exception:
            self.fail(f"delete_user() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.delete", patch_api.mock_generic_post)
    def test_delete_user_access_key(self):
        try:
            client = self.client.iam
            client.delete_user_access_key(username="user", access_key_id="id")
        except Exception:
            self.fail(
                f"delete_user_access_key() got exception: {traceback.format_exc()}"
            )

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.delete", patch_api.mock_generic_post)
    def test_detach_role_policy(self):
        try:
            client = self.client.iam
            client.detach_role_policy(
                role_name="name", policy_trn="trn:tenant::iam::global:policy/name"
            )
        except Exception:
            self.fail(f"detach_role_policy() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.delete", patch_api.mock_generic_post)
    def test_detach_user_group(self):
        try:
            client = self.client.iam
            client.detach_user_group(username="name", group_name="name")
        except Exception:
            self.fail(f"detach_user_group() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.delete", patch_api.mock_generic_post)
    def test_detach_user_policy(self):
        try:
            client = self.client.iam
            client.detach_user_policy(
                username="name", policy_trn="trn:tenant::iam::global:policy/name"
            )
        except Exception:
            self.fail(f"detach_user_policy() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_get_group(self):
        try:
            client = self.client.iam
            client.get_group(group_name="name")
        except Exception:
            self.fail(f"get_group() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_get_policy(self):
        try:
            client = self.client.iam
            client.get_policy(policy_trn="trn:tenant::iam::global:policy/name")
        except Exception:
            self.fail(f"get_policy() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_get_role(self):
        try:
            client = self.client.iam
            client.get_role(role_name="name")
        except Exception:
            self.fail(f"get_role() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_get_service(self):
        try:
            client = self.client.iam
            client.get_service(service_name="name")
        except Exception:
            self.fail(f"get_service() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_get_user(self):
        try:
            client = self.client.iam
            client.get_user(username="name")
        except Exception:
            self.fail(f"get_user() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_list_attached_user_groups(self):
        try:
            client = self.client.iam
            client.list_attached_user_groups(username="name", page=2, size=1)
        except Exception:
            self.fail(
                f"list_attached_user_groups() got exception: {traceback.format_exc()}"
            )

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_list_attached_role_policies(self):
        try:
            client = self.client.iam
            client.list_attached_role_policies(role_name="name", page=2, size=1)
        except Exception:
            self.fail(
                f"list_attached_role_policies() got exception: {traceback.format_exc()}"
            )

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_list_attached_user_policies(self):
        try:
            client = self.client.iam
            client.list_attached_user_policies(username="name", page=2, size=1)
        except Exception:
            self.fail(
                f"list_attached_user_policies() got exception: {traceback.format_exc()}"
            )

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_list_group_policies(self):
        try:
            client = self.client.iam
            client.list_group_policies(group_name="name", size=2, page=1)
        except Exception:
            self.fail(f"list_group_policies() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_list_group_users(self):
        try:
            client = self.client.iam
            client.list_group_users(group_name="name", size=2, page=1)
        except Exception:
            self.fail(f"list_group_users() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_list_policies(self):
        try:
            client = self.client.iam
            client.list_policies(page=2, size=1)
        except Exception:
            self.fail(f"list_policies() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_list_roles(self):
        try:
            client = self.client.iam
            client.list_roles(page=2, size=1)
        except Exception:
            self.fail(f"list_roles() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_list_services(self):
        try:
            client = self.client.iam
            client.list_services(page=2, size=1)
        except Exception:
            self.fail(f"list_services() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_generic_post)
    def test_list_users(self):
        try:
            client = self.client.iam
            client.list_users(page=2, size=1)
        except Exception:
            self.fail(f"list_users() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.put", patch_api.mock_generic_post)
    def test_update_group(self):
        try:
            client = self.client.iam
            client.update_group(group_name="name", description="test")
        except Exception:
            self.fail(f"update_group() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.put", patch_api.mock_generic_post)
    def test_update_policy(self):
        try:
            client = self.client.iam
            client.update_policy(
                policy_trn="trn:tenant::iam::global:policy/name",
                policies_statements=[],
                description="as",
            )
        except Exception:
            self.fail(f"update_policy() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_generic_get)
    @patch("iam_sdk.api.requests.put", patch_api.mock_generic_post)
    def test_update_role(self):
        try:
            client = self.client.iam
            client.update_role(
                role_name="name", description="asd", role_type="role", trust_policy={}
            )
        except Exception:
            self.fail(f"update_role() got exception: {traceback.format_exc()}")
