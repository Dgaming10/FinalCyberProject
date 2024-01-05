import datetime


class Mail:
    def __init__(self, sender, recipients, subject, message, mongo_id):
        self._sender = sender
        self._recipients = recipients
        self._subject = subject
        self._message = message
        self._creation_date = datetime.datetime.now()
        self._mongo_id = mongo_id

    @property
    def recipients(self) -> [str]:
        return self._recipients

    @property
    def message(self) -> str:
        return self._message

    @property
    def sender(self) -> str:
        return self._sender

    @property
    def subject(self) -> str:
        return self._subject

    @property
    def creation_date(self) -> datetime.date:
        return self._creation_date

    @property
    def mongo_id(self) -> str:
        return self._mongo_id