# Example using IAM api

```python

>>> client = iam_sdk.client(**args)
>>> client.login()
>>> client.iam.list_users()
{'status': 'success', 'message': '', 'data': [{'id': 'id1', 'trn': 'trn:tcloud:iam::tenant:user/mock', 'username': 'mock', 'tenant': 'tenant', 'createdAt': 1711108762, 'active': True, 'lastModifiedAt': 1711108762, 'accessKeys': ['123345-1e46-4948-b030-75b6a900e54aaaaaaa'], 'policies': ['policyid1'], 'groups': []}], 'meta': {'size': 10, 'page': 1, 'total': 3, 'totalPages': 1, 'links': {'self': '/users', 'first': '/users?page[number]=1&page[size]=10', 'prev': None, 'next': None, 'last': '/users?page[number]=1&page[size]=10'}}}
>>> client.iam.create_user("mock-teste")
'mock-teste'
>>> client.iam.create_user_access_key("mock-teste", description=" ")
>>> client.iam.attach_user_policy("mock-teste", [policy_arn])
>>> client.iam.get_user("mock-teste")
{'status': 'success',
 'message': 'ok',
 'data': {'id': 'uniqId',
  'trn': 'trn:tcloud:iam::tenant:user/mock-teste',
  'username': 'mock-teste',
  'tenant': 'tenant',
  'createdAt': 1719432704,
  'active': True,
  'lastModifiedAt': 1719432704,
  'policies': [{'id': 'uniqId',
    'description': "Policy used to grant full access to manage IAM's users"}],
  'groups': [],
  'accessKeys': [{'id': 'mock123-3766-4bf1-a5f1-bbbbbbb',
    'status': 'active',
    'description': ' ',
    'createdAt': 1719432747}]}}
>>> client.iam.delete_user_access_key("mock-teste", "mock123-3766-4bf1-a5f1-bbbbbbb")
>>> client.iam.detach_user_policy("mock-teste", policy_arn)
>>> client.iam.delete_user("mock-teste")
>>> client.iam.create_policy("teste-mock2", "teste", [{"Effect": "permit", "Action": "*", "Resource": "*"}])
>>> client.iam.list_policies()
>>> client.iam.get_policy("trn:tcloud:iam::tenant:policy/teste-mock2")
>>> client.iam.update_policy("trn:tcloud:iam::tenant:policy/teste-mock2", "teste", [{"Effect": "forbid", "Action": "*", "Resource": "*"}])
>>> client.iam.delete_policy("trn:tcloud:iam::tenant:policy/teste-mock2")

```