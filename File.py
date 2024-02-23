class File:
    def __init__(self, name: str, extension: str, content: bytes):
        self._name = name
        self._extension = extension
        self._content = content

    @property
    def name(self):
        return self._name

    @property
    def extension(self):
        return self._extension

    @property
    def content(self):
        return self._content

    @name.setter
    def name(self, value):
        self._name = value

    @extension.setter
    def extension(self, value):
        self._extension = value

    @content.setter
    def content(self, value):
        self._content = value


