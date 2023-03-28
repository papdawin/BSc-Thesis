import email
import re
from io import StringIO


class ListBasedAnalyzer:
    def __init__(self):
        self.config = {}
        self.rules = {}
        self.set_ruleset()
        # print("[Initialized Analyzer]")
    def set_options(self, config):
        self.config = config
    def set_ruleset(self):
        self.rules["XSS"] = re.compile("(<)+(\s)*(script|body|img|image|irame|input|link|table|div|object|svg|html|iframe|video|audio|frameset)*.*[\x3E|&gt]+", re.I)
        self.rules["SQLi"] = re.compile("('(''|[^'])*').*;.*(\b(ALTER|CREATE|DELETE|DROP|EXEC(UTE)?|INSERT( +INTO)?|MERGE|SELECT|UPDATE|UNION( +ALL)?)\b)", re.I)
        self.rules["Prototype_pollution"] = re.compile("{(\S|\s)*__proto__", re.I)
        # TODO: add more rules
    def is_secure(self, text, territory) -> bool:
        for attack_type in self.config["protect_against"]:
            if self.rules.get(attack_type).search(text):
                # TODO: use it in logger
                print(f"[{attack_type}] detected in {territory}: {text}")
                return False
        return True
    def analyze_parts(self, request: dict) -> bool:
        # returns false if request is not secure
        if self.config["parts_of_request_to_check"]["status_line"] and not self.is_secure(request["status_line"], "URL"):
            return False
        if self.config["parts_of_request_to_check"]["cookie"] and not self.is_secure(request["Cookie"], "cookies"):
            return False
        if self.config["parts_of_request_to_check"]["body"] and not self.is_secure(request["body"], "body"):
            return False
        return True
    def format_request(self, data: bytes) -> dict:
        decoded = data.decode()
        status_line, request = decoded.split('\r\n', 1)
        headers, body = request.split('\r\n\r\n', 1)
        message = email.message_from_file(StringIO(headers))
        request = dict(message.items())
        request["body"] = body
        request["status_line"] = status_line
        return request

    # with open('config.json', 'r') as f:
    #     config = json.load(f)
    #     analyzer = ListBasedAnalyzer()
    #     analyzer.set_options(config)
    #     print(analyzer.analyze_parts(request))


# check_request(b'GET / HTTP/1.1\r\nHost: localhost:8080\r\nConnection: keep-alive\r\nCache-Control: '
#               b'max-age=0\r\nsec-ch-ua: "Chromium";v="110", "Not A(Brand";v="24", '
#               b'"Brave";v="110"\r\nsec-ch-ua-mobile: ?0\r\nsec-ch-ua-platform: '
#               b'"Windows"\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
#               b'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36\r\nAccept: text/html,'
#               b'application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\nSec-GPC: '
#               b'1\r\nSec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-User: ?1\r\nSec-Fetch-Dest: '
#               b'document\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.9,hu-HU;q=0.8,'
#               b'hu;q=0.7\r\nCookie: wordpress_test_cookie=WP%20Cookie%20check; '
#               b'PHPSESSID=8765192bb66ebca42aaf908529de140f\r\nIf-None-Match: "2d-432a5e4a73a80"\r\nIf-Modified-Since: '
#               b'Mon, 11 Jun 2007 18:53:14 GMT\r\n\r\n')
