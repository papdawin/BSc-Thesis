import json
from sqlalchemy.orm import declarative_base, Session
from Analysis.IPChecker import is_IP_safe, InvalidIPException, db
from Analysis.listBasedAnalyzer import contains_vector
from Data import config
from io import StringIO
import email
import logging

__all__ = ["is_IP_safe", "InvalidIPException", "analyze_request"]

def analyze_request(request, address):
    request = format_request(request)
    if config["ruleset"].get('use_manual'):
        if msg := manual_approach(request):
            if config["analysis"].get('block_malicious_IP'):
                # Save IP into database, and log offense
                new_entry = db.IPBlackList(
                    ip_address=address[0],
                    reason="malicious payload",
                    source="local_exemption"
                )
                with Session(db.engine) as session:
                    session.add(new_entry)
                    session.commit()
            logging.critical(msg)
            return False
    if config["ruleset"].get('use_ML'):
        if msg := ML_approach():
            pass
    return True

def manual_approach(request):
    request_filter = json.loads(config['analysis']['request'].replace("'", '"'))
    request_type = request["status_line"].split(" ", 1)[0]
    if request_type not in request_filter["type"]:
        # skipping analysis for unspecified types
        return None
    for part in request_filter["part"]:
        if msg := contains_vector(part=request.get(part), part_name=part):
            return msg
    # Contains no attack vectors
    return None

def ML_approach():
    pass

def format_request(data: bytes) -> dict:
    decoded = data.decode()
    status_line, request = decoded.split('\r\n', 1)
    headers, body = request.split('\r\n\r\n', 1)
    message = email.message_from_file(StringIO(headers))
    request = dict(message.items())
    request["body"] = body
    request["status_line"] = status_line
    return request
