import logging
from .client import Client


def client(*args, **kargs):
    return Client(**kargs).client(*args, **kargs)


# Set up logging to ``/dev/null`` like a library is supposed to.
# https://docs.python.org/3.3/howto/logging.html#configuring-logging-for-a-library
class NullHandler(logging.Handler):
    def emit(self, record):
        pass


logging.getLogger("boto3").addHandler(NullHandler())
