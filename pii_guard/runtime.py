"""Format before redacting so objects and exception text are covered."""
import json
import logging
import sys
import traceback
from .detectors import redact


class JsonFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({"source": record.pathname, "line": record.lineno,
                           "level": record.levelname, "message": super().format(record)})


def safe_log(method, message, *args, **kwargs):
    record = logging.LogRecord("pii_guard", logging.INFO, "", 0, message, args, None)
    rendered = record.getMessage()
    exc_info = kwargs.pop("exc_info", getattr(method, "__name__", "") == "exception")
    if exc_info:
        if isinstance(exc_info, BaseException):
            exc_info = (type(exc_info), exc_info, exc_info.__traceback__)
        elif not isinstance(exc_info, tuple):
            exc_info = sys.exc_info()
        rendered += "\n" + "".join(traceback.format_exception(*exc_info))
    if kwargs.pop("stack_info", False):
        rendered += "\n" + "".join(traceback.format_stack()[:-1])
    # logger.exception defaults exc_info to True, so explicitly disable it.
    kwargs["exc_info"] = False
    kwargs["stacklevel"] = kwargs.get("stacklevel", 1) + 1
    method(redact(rendered), **kwargs)
