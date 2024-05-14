#TODO - add annotations
class File:
    def __init__(self, name: str, extension: str, content: bytes, file_key: bytes):
        self._name = name
        self._extension = extension
        self._content = content
        self._file_key = file_key

    @property
    def name(self):
        return self._name

    @property
    def extension(self):
        return self._extension

    @property
    def content(self):
        return self._content

    @property
    def file_key(self):
        return self._file_key

    @name.setter
    def name(self, value):
        self._name = value

    @extension.setter
    def extension(self, value):
        self._extension = value

    @content.setter
    def content(self, value):
        self._content = value

    @file_key.setter
    def file_key(self, value):
        self._file_key = value


