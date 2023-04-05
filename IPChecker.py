import pydnsbl
from sqlalchemy import Column, Integer, String, create_engine, DateTime, func
from sqlalchemy.orm import declarative_base, Session
class IPChecker:
    def __init__(self):
        self.ip_checker = pydnsbl.DNSBLIpChecker()
        self.db = DBHandler()
    def IP_is_safe(self, addressport):
        address, port = addressport
        if address == 'localhost' or '127.0.0.1':
            return True
        if self.found_IP_locally(address):
            return False
        if self.found_IP_online(address):
            return False
        return True
    def found_IP_locally(self, address):
        with Session(self.db.engine) as session:
            res = session.query(self.db.IPBlackList).filter_by(ip_address=address).first()
            if res:
                # TODO:log (ip already found in db as malicious)
                return False
        return True
    def found_IP_online(self, address):
        result = self.ip_checker.check(address)
        if result.blacklisted:
            new_entry = self.db.IPBlackList(
                ip_address=address,
                reason=''.join(result.categories),
                source=''.join([x.host for x in result.providers])
            )
            with Session(self.db.engine) as session:
                session.add(new_entry)
                session.commit()
            # TODO:log (ip already found online as malicious and added to db)
            return False
        return True


class InvalidIPException(Exception):
    def __init__(self):
        super().__init__("invalid IP provided")

def singleton(class_):
    instances = {}
    def getinstance(*args, **kwargs):
        if class_ not in instances:
            instances[class_] = class_(*args, **kwargs)
        return instances[class_]
    return getinstance
@singleton
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
    def __init__(self):
        pass
        # with Session(self.engine) as session:
        #     ip1 = self.IPBlackList(
        #         ip_address="89.23.211.54",
        #         reason="spam",
        #         source="local_exemption"
        #     )
        #     session.add(ip1)
        #     session.commit()
    # TODO megírni szépen szeparálva
    # def get(self):
    #     with Session(self.engine) as session:
    #         res = session.query(self.IPBlackList).filter(self.IPBlackList.ip_address == "80.223.1.4")
    #         print(res[0])

