import json


class FakeObject:
    def __init__(self, response, status_code=200, headers={}) -> None:
        self._text = response
        self._status_code = status_code
        self._headers = headers
        self.content = response.encode()

    def json(self):
        return json.loads(self.text)

    @property
    def status_code(self):
        return self._status_code

    @property
    def text(self):
        return self._text

    @property
    def headers(self):
        return self._headers
