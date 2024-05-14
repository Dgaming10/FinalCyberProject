import datetime


class Email:
    """
    A class representing an email.

    Attributes:
    - _sender (str): Sender's email address.
    - _recipients (list): List of recipient email addresses.
    - _subject (str): Email subject.
    - _message (str): Email message.
    - _creation_date (datetime.date): Email creation date.
    - _mongo_id (str): MongoDB ID for the email.
    """

    def __init__(self, sender, recipients, subject, message, creation_date=None, mongo_id=None,
                 files_info=None):
        """
        Initializes an email instance.

        Parameters:
        - sender (str): Sender's email address.
        - recipients (list): List of recipient email addresses.
        - subject (str): Email subject.
        - message (str): Email message.
        - creation_date (datetime.date): Email creation date.
        - mongo_id (str): MongoDB ID for the email (default is None).
        """
        if files_info is None:
            files_info = []
        self._sender = sender
        self._recipients = recipients
        self._subject = subject
        self._message = message
        self._creation_date = creation_date
        self._mongo_id = mongo_id
        self._files_info = files_info

    @property
    def recipients(self) -> [str]:
        """
        Gets the list of recipient email addresses.

        Returns:
        list: List of recipient email addresses.
        """
        return self._recipients

    @property
    def message(self) -> str:
        """
        Gets the email message.

        Returns:
        str: Email message.
        """
        return self._message

    @property
    def sender(self) -> str:
        """
        Gets the sender's email address.

        Returns:
        str: Sender's email address.
        """
        return self._sender

    @property
    def subject(self) -> str:
        """
        Gets the email subject.

        Returns:
        str: Email subject.
        """
        return self._subject

    @property
    def creation_date(self) -> datetime.date:
        """
        Gets the email creation date.

        Returns:
        datetime.date: Email creation date.
        """
        return self._creation_date

    @property
    def mongo_id(self) -> str:
        """
        Gets the MongoDB ID for the email.

        Returns:
        str: MongoDB ID for the email.
        """
        return self._mongo_id

    @property
    def files_info(self) -> list:
        """
        Gets the files info for the email.

        Returns:
        list: Files info for the email.
        """
        return self._files_info

    @mongo_id.setter
    def mongo_id(self, value):
        """
        Sets the MongoDB ID for the email.

        Parameters:
        - value (str): MongoDB ID to set.
        """
        self._mongo_id = value

    @files_info.setter
    def files_info(self, value):
        """
        Sets the files info for the email.

        Parameters:
        - value (list): Files info to set.
        """
        self._files_info = value

    def update_creation_date(self):
        """
        Sets the creation date of the email to the current date.
        """
        self._creation_date = datetime.datetime.now()
