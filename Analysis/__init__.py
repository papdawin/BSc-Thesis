import json
from sqlalchemy.orm import declarative_base, Session
from Analysis.IPChecker import is_IP_safe, InvalidIPException, db
from Analysis.helperFunctions import contains_vector, pipeline, format_request
from Data import config
import logging

__all__ = ["is_IP_safe", "InvalidIPException", "analyze_request"]

def analyze_request(request, address):
    request = format_request(request)
    if config["ruleset"].getboolean('use_manual'):
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
    if config["ruleset"].getboolean('use_ML'):
        if msg := ML_approach(request):
            logging.critical(msg)
            return False
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

def ML_approach(request):
    request_filter = json.loads(config['analysis']['request'].replace("'", '"'))
    request_type = request["status_line"].split(" ", 1)[0]
    if request_type not in request_filter["type"]:
        # skipping analysis for unspecified types
        return None
    for part in request_filter["part"]:
        if pipeline.predict([request.get(part) or " "])[0] == 1:
            return f"Attack vector detected by AI in {part}"
    return None


