from sqlalchemy import Column, Integer, String, create_engine, DateTime, func
from sqlalchemy.orm import declarative_base, Session
from pydnsbl import DNSBLIpChecker
import logging

class DBHandler:
    Base = declarative_base()
    class IPBlackList(Base):
        __tablename__ = "ip_blacklist"

        blacklistID = Column("blacklistID", Integer, primary_key=True)
        ip_address = Column("ip_address", String)
        reason = Column("reason", String)
        source = Column("source", String)
        detected_at = Column("detected_at", DateTime(timezone=True), server_default=func.now())

        def __init__(self, ip_address, reason, source):
            self.ip_address = ip_address
            self.reason = reason
            self.source = source

        def __repr__(self):
            return f"[{self.detected_at}] {self.ip_address} - {self.reason}: {self.source}"
    engine = create_engine("sqlite:///storage.db", echo=False)
    Base.metadata.create_all(engine)


logging.basicConfig(filename='trace.log',
                    filemode='a',
                    level=20,
                    format='[%(asctime)s] %(levelname)s - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S')
db = DBHandler()

def is_IP_safe(addressport):
    address, port = addressport
    if address == 'localhost' or '127.0.0.1':
        logging.info("Connection established from local machine")
        return True
    if msg := found_IP_locally(address):
        logging.warning(msg)
        return False
    if msg := found_IP_online(address):
        logging.warning(msg)
        return False
    return True

def found_IP_locally(address):
    with Session(db.engine) as session:
        res = session.query(db.IPBlackList).filter_by(ip_address=address).first()
        if res:
            msg = f"Connection from {res.ip_address} terminated, found in local blocklist" \
                  f"\nreason(s): [{res.reason}]" \
                  f"\nsource(s): [{res.source}]"
            return msg
    return None

def found_IP_online(address):
    result = DNSBLIpChecker().check(address)
    if result.blacklisted:
        reason = ', '.join(result.categories)
        source = ', '.join([x.host for x in result.providers])
        new_entry = db.IPBlackList(
            ip_address=address,
            reason=reason,
            source=source
        )
        with Session(db.engine) as session:
            session.add(new_entry)
            session.commit()
        print(result.categories)
        msg = f"Connection from {address} terminated, found in online blocklist" \
            f"\nreason(s): [{reason}]" \
            f"\nsource(s): [{source}]"
        return msg
    return None


class InvalidIPException(Exception):
    def __init__(self):
        super().__init__("invalid IP provided")

