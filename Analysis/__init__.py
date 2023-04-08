from Analysis.IPChecker import is_IP_safe, InvalidIPException
from Analysis.listBasedAnalyzer import ListBasedAnalyzer
from io import StringIO
import email

__all__ = ["is_IP_safe", "InvalidIPException", "ListBasedAnalyzer", "analyze_request"]

def analyze_request(request):
    request = format_request(request)

    return True


def format_request(data: bytes) -> dict:
    decoded = data.decode()
    status_line, request = decoded.split('\r\n', 1)
    headers, body = request.split('\r\n\r\n', 1)
    message = email.message_from_file(StringIO(headers))
    request = dict(message.items())
    request["body"] = body
    request["status_line"] = status_line
    return request
