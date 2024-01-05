from tkinter import Label


class CustomLabel(Label):
    def __init__(self, master=None, mongoID=None, cnf={}, **kwargs):
        super().__init__(master, cnf, **kwargs)
        self._mongoID = mongoID
