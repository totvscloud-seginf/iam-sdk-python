import requests
import logging
import urllib.parse
from typing import Dict, Any, List, Literal
from ..domain.client_repository import ClientRepository

logger = logging.getLogger(__name__)


class IAM:
    def __init__(self, client: ClientRepository) -> None:
        self._client = client
        logger.setLevel(client.get_log_level())

    def attach_role_policies(
        self, role_name: str, policies_trn: List[str]
    ) -> Dict[str, Any]:
        role_name = urllib.parse.quote_plus(role_name)
        url = (
            f"{self._client.get_config().get_endpoint_cp()}/roles/{role_name}/policies"
        )

        logger.debug("requesting attach_role_policies")
        payload = {"policies": policies_trn}

        logger.debug("Body request: %s", payload)

        resp = requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("attach_role_policies", resp)

    def attach_user_groups(self, username: str, groups: List[str]) -> Dict[str, Any]:
        username = urllib.parse.quote_plus(username)
        url = f"{self._client.get_config().get_endpoint_cp()}/users/{username}/groups"

        logger.debug("requesting attach_user_groups")
        payload = {"groups": groups}

        logger.debug("Body request: %s", payload)

        resp = requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("attach_user_groups", resp)

    def attach_user_policies(
        self, username: str, policies_trn: List[str]
    ) -> Dict[str, Any]:
        username = urllib.parse.quote_plus(username)
        url = f"{self._client.get_config().get_endpoint_cp()}/users/{username}/policies"

        logger.debug("requesting attach_user_policies")
        payload = {"policies": policies_trn}

        logger.debug("Body request: %s", payload)

        resp = requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("attach_user_policies", resp)

    def create_group(
        self,
        name: str,
        description: str,
    ) -> Dict[str, Any]:
        url = f"{self._client.get_config().get_endpoint_cp()}/groups"

        logger.debug("requesting create_group")
        payload = {
            "name": name,
            "description": description,
        }
        logger.debug(f"payload: {payload}")

        resp = requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("create_group", resp)

    def create_policy(
        self,
        name: str,
        description: str,
        policies_statements: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        url = f"{self._client.get_config().get_endpoint_cp()}/policies"

        logger.debug("requesting create_policy")
        payload = {
            "name": name,
            "policyType": "tenant",
            "description": description,
            "engineVersion": "2023-09-18",
            "statements": policies_statements,
        }
        logger.debug(f"payload: {payload}")

        resp = requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("create_policy", resp)

    def create_role(
        self,
        name: str,
        role_type: Literal["role", "federatedRole", "serviceRole"],
        trust_policy: Dict[str, Any],
        description="",
    ) -> Dict[str, Any]:
        url = f"{self._client.get_config().get_endpoint_cp()}/roles"

        logger.debug("requesting create_role")
        payload = {
            "name": name,
            "type": role_type,
            "description": description,
            "trustPolicy": trust_policy,
            "trustPolicyEngineVersion": "2023-09-18",
        }
        logger.debug(f"payload: {payload}")

        resp = requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("create_role", resp)

    def create_service(
        self,
        name: str,
        service_type: Literal["tenant", "global"],
        permission_manifest: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        url = f"{self._client.get_config().get_endpoint_cp()}/services"

        logger.debug("requesting create_service")
        payload = {
            "name": name,
            "type": service_type,
            "permissionsManifest": permission_manifest,
        }
        logger.debug(f"payload: {payload}")

        resp = requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("create_service", resp)

    def create_user(self, username) -> str:
        url = f"{self._client.get_config().get_endpoint_cp()}/users"

        logger.debug("requesting create user")
        payload = {"username": username}

        logger.debug("Body request: %s", payload)

        resp = requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        resp = self._client.validate_api_response("create_user", resp)

        return resp["username"]

    def create_user_access_key(self, username: str, description) -> dict[str, Any]:
        username = urllib.parse.quote_plus(username)
        url = (
            f"{self._client.get_config().get_endpoint_cp()}/users/{username}/accesskey"
        )

        logger.debug("requesting delete user")
        payload = {"description": description}

        logger.debug("Body request: %s", payload)

        resp = requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("create_user_access_key", resp)[
            "data"
        ]

    def delete_group(self, group_name: str) -> Dict[str, Any]:
        group_name = urllib.parse.quote_plus(group_name)
        url = f"{self._client.get_config().get_endpoint_cp()}/groups/{group_name}"

        logger.debug("requesting delete_group")

        resp = requests.delete(
            url,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("delete_group", resp)

    def delete_policy(self, policy_trn: str) -> Dict[str, Any]:
        policy_trn = urllib.parse.quote_plus(policy_trn)
        url = f"{self._client.get_config().get_endpoint_cp()}/policies/{policy_trn}"

        logger.debug("requesting delete_policy")

        resp = requests.delete(
            url,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("delete_policy", resp)

    def delete_role(self, role_name: str) -> Dict[str, Any]:
        role_name = urllib.parse.quote_plus(role_name)
        url = f"{self._client.get_config().get_endpoint_cp()}/roles/{role_name}"

        logger.debug("requesting delete_role")

        resp = requests.delete(
            url,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("delete_role", resp)

    def delete_service(self, service_name: str) -> Dict[str, Any]:
        service_name = urllib.parse.quote_plus(service_name)
        url = f"{self._client.get_config().get_endpoint_cp()}/services/{service_name}"

        logger.debug("requesting delete_service")

        resp = requests.delete(
            url,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("delete_service", resp)

    def delete_user(self, username) -> Dict[str, Any]:
        username = urllib.parse.quote_plus(username)
        url = f"{self._client.get_config().get_endpoint_cp()}/users/{username}"

        logger.debug("requesting delete user")
        payload = {"username": username}

        logger.debug("Body request: %s", payload)

        resp = requests.delete(
            url,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("delete_user", resp)

    def delete_user_access_key(
        self, username: str, access_key_id: str
    ) -> Dict[str, Any]:
        access_key_id = urllib.parse.quote_plus(access_key_id)
        url = f"{self._client.get_config().get_endpoint_cp()}/users/{username}/accesskey/{access_key_id}"

        logger.debug("requesting delete_user_access_key")

        resp = requests.delete(
            url,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("delete_user_access_key", resp)

    def detach_role_policy(self, role_name: str, policy_trn: str) -> Dict[str, Any]:
        role_name = urllib.parse.quote_plus(role_name)
        policy_trn = urllib.parse.quote_plus(policy_trn)
        url = f"{self._client.get_config().get_endpoint_cp()}/roles/{role_name}/policies/{policy_trn}"

        logger.debug("requesting detach_role_policy")

        resp = requests.delete(
            url,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("detach_role_policy", resp)

    def detach_user_group(self, username: str, group_name: str) -> Dict[str, Any]:
        username = urllib.parse.quote_plus(username)
        group_name = urllib.parse.quote_plus(group_name)
        url = f"{self._client.get_config().get_endpoint_cp()}/users/{username}/groups/{group_name}"

        logger.debug("requesting detach_user_group")

        resp = requests.delete(
            url,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("detach_user_group", resp)

    def detach_user_policy(self, username: str, policy_trn: str) -> Dict[str, Any]:
        username = urllib.parse.quote_plus(username)
        policy_trn = urllib.parse.quote_plus(policy_trn)
        url = f"{self._client.get_config().get_endpoint_cp()}/users/{username}/policies/{policy_trn}"

        logger.debug("requesting detach_user_policy")

        resp = requests.delete(
            url,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("detach_user_policy", resp)

    def get_group(self, group_name: str) -> Dict[str, Any]:
        group_name = urllib.parse.quote_plus(group_name)
        url = f"{self._client.get_config().get_endpoint_cp()}/groups/{group_name}"

        logger.debug("requesting get_group")

        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("get_group", resp)["data"]

    def get_policy(self, policy_trn: str) -> Dict[str, Any]:
        policy_trn = urllib.parse.quote_plus(policy_trn)
        url = f"{self._client.get_config().get_endpoint_cp()}/policies/{policy_trn}"

        logger.debug("requesting get_policy")

        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("get_policy", resp)["data"]

    def get_role(self, role_name: str) -> Dict[str, Any]:
        role_name = urllib.parse.quote_plus(role_name)
        url = f"{self._client.get_config().get_endpoint_cp()}/roles/{role_name}"

        logger.debug("requesting get_role")

        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("get_role", resp)["data"]

    def get_service(self, service_name: str) -> Dict[str, Any]:
        service_name = urllib.parse.quote_plus(service_name)
        url = f"{self._client.get_config().get_endpoint_cp()}/services/{service_name}"

        logger.debug("requesting get_service")

        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("get_service", resp)["data"]

    def get_user(self, username: str) -> Dict[str, Any]:
        username = urllib.parse.quote_plus(username)
        url = f"{self._client.get_config().get_endpoint_cp()}/users/{username}"

        logger.debug("requesting delete user")

        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("get_user", resp)["data"]

    def list_attached_user_groups(self, username, page=1, size=10) -> Dict[str, Any]:
        """
        :param page: page index
        :param size: 1-200 results per page
        """
        username = urllib.parse.quote_plus(username)
        url = f"{self._client.get_config().get_endpoint_cp()}/users/{username}/groups"

        logger.debug("requesting list_attached_user_groups")
        args = {
            "page[number]": page,
            "page[size]": size,
        }
        logger.debug(f"query parameters: {args}")

        resp = requests.get(
            url,
            params=args,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("list_attached_user_groups", resp)

    def list_attached_role_policies(self, role_name, page=1, size=10) -> Dict[str, Any]:
        """
        :param page: page index
        :param size: 1-200 results per page
        """
        role_name = urllib.parse.quote_plus(role_name)
        url = (
            f"{self._client.get_config().get_endpoint_cp()}/roles/{role_name}/policies"
        )

        logger.debug("requesting list_attached_role_policies")
        args = {
            "page[number]": page,
            "page[size]": size,
        }
        logger.debug(f"query parameters: {args}")

        resp = requests.get(
            url,
            params=args,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("list_attached_role_policies", resp)

    def list_attached_user_policies(self, username, page=1, size=10) -> Dict[str, Any]:
        """
        :param page: page index
        :param size: 1-200 results per page
        """
        username = urllib.parse.quote_plus(username)
        url = f"{self._client.get_config().get_endpoint_cp()}/users/{username}/policies"

        logger.debug("requesting list_attached_user_policies")
        args = {
            "page[number]": page,
            "page[size]": size,
        }
        logger.debug(f"query parameters: {args}")

        resp = requests.get(
            url,
            params=args,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("list_attached_user_policies", resp)

    def list_group_policies(self, group_name, page=1, size=10) -> Dict[str, Any]:
        """
        :param page: page index
        :param size: 1-200 results per page
        """
        group_name = urllib.parse.quote_plus(group_name)
        url = f"{self._client.get_config().get_endpoint_cp()}/groups/{group_name}/policies"

        logger.debug("requesting list_group_policies")
        args = {
            "page[number]": page,
            "page[size]": size,
        }
        logger.debug(f"query parameters: {args}")

        resp = requests.get(
            url,
            params=args,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("list_group_policies", resp)

    def list_group_users(self, group_name, page=1, size=10) -> Dict[str, Any]:
        """
        :param page: page index
        :param size: 1-200 results per page
        """
        group_name = urllib.parse.quote_plus(group_name)
        url = f"{self._client.get_config().get_endpoint_cp()}/groups/{group_name}/users"

        logger.debug("requesting list_group_users")
        args = {
            "page[number]": page,
            "page[size]": size,
        }
        logger.debug(f"query parameters: {args}")

        resp = requests.get(
            url,
            params=args,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("list_group_users", resp)

    def list_policies(self, page=1, size=10) -> Dict[str, Any]:
        """
        :param page: page index
        :param size: 1-200 results per page
        """
        url = f"{self._client.get_config().get_endpoint_cp()}/policies"

        logger.debug("requesting list_policies")
        args = {
            "page[number]": page,
            "page[size]": size,
        }
        logger.debug(f"query parameters: {args}")

        resp = requests.get(
            url,
            params=args,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("list_policies", resp)

    def list_roles(self, page=1, size=10) -> Dict[str, Any]:
        """
        :param page: page index
        :param size: 1-200 results per page
        """
        url = f"{self._client.get_config().get_endpoint_cp()}/roles"

        logger.debug("requesting list_roles")
        args = {
            "page[number]": page,
            "page[size]": size,
        }
        logger.debug(f"query parameters: {args}")

        resp = requests.get(
            url,
            params=args,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("list_roles", resp)

    def list_services(self, page=1, size=10) -> Dict[str, Any]:
        """
        :param page: page index
        :param size: 1-200 results per page
        """
        url = f"{self._client.get_config().get_endpoint_cp()}/services"

        logger.debug("requesting list_services")
        args = {
            "page[number]": page,
            "page[size]": size,
        }
        logger.debug(f"query parameters: {args}")

        resp = requests.get(
            url,
            params=args,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("list_services", resp)

    def list_users(self, page=1, size=10) -> Dict[str, Any]:
        """
        :param page: page index
        :param size: 1-200 results per page
        """
        url = f"{self._client.get_config().get_endpoint_cp()}/users"

        logger.debug("requesting list user")
        args = {
            "page[number]": page,
            "page[size]": size,
        }
        logger.debug(f"query parameters: {args}")

        resp = requests.get(
            url,
            params=args,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("list_users", resp)

    def update_group(self, group_name, description) -> Dict[str, Any]:
        group_name = urllib.parse.quote_plus(group_name)
        url = f"{self._client.get_config().get_endpoint_cp()}/groups/{group_name}"

        logger.debug("requesting update_group")

        payload = {
            "description": description,
        }
        logger.debug(f"payload: {payload}")

        resp = requests.put(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("update_group", resp)

    def update_policy(
        self, policy_trn, description, policies_statements
    ) -> Dict[str, Any]:
        policy_trn = urllib.parse.quote_plus(policy_trn)
        url = f"{self._client.get_config().get_endpoint_cp()}/policies/{policy_trn}"

        logger.debug("requesting update_policy")

        payload = {
            "policyType": "tenant",
            "description": description,
            "engineVersion": "2023-09-18",
            "statements": policies_statements,
        }
        logger.debug(f"payload: {payload}")

        resp = requests.put(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("update_policy", resp)

    def update_role(
        self,
        role_name,
        role_type: Literal["role", "federatedRole", "serviceRole"],
        trust_policy: Dict[str, Any],
        description="",
    ) -> Dict[str, Any]:
        """
        Must pass all the values to update role
        """
        role_name = urllib.parse.quote_plus(role_name)
        url = f"{self._client.get_config().get_endpoint_cp()}/roles/{role_name}"

        logger.debug("requesting update_role")

        payload = {
            "type": role_type,
            "description": description,
            "trustPolicy": trust_policy,
            "trustPolicyEngineVersion": "2023-09-18",
        }
        logger.debug(f"payload: {payload}")

        resp = requests.put(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {self._client.get_token()}"},
            verify=self._client.get_validate_ssl(),
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self._client.validate_api_response("update_role", resp)
