from sqlalchemy.orm import declarative_base, Session
from Analysis.IPChecker import is_IP_safe, InvalidIPException
from Analysis.listBasedAnalyzer import *
from Data import config
from IPChecker import db
from io import StringIO
import email
import logging

__all__ = ["is_IP_safe", "InvalidIPException", "ListBasedAnalyzer", "analyze_request"]

def analyze_request(request, address):
    request = format_request(request)
    if config["ruleset"].get('use_manual'):
        if msg := manual_approach():
            # Save IP into database, and log offense
            new_entry = db.IPBlackList(
                ip_address=address,
                reason="Malicious payload",
                source="local_entry"
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

def manual_approach():
    if 
    pass

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
