from checkov.common.models.enums import CheckCategories


class BaseSastCheck():
    def __init__(self, name: str, id: str, severity = None) -> None:
        self.name = name
        self.id = id
        self.categories = [CheckCategories.SAST]
        # TODO
        self.guideline = ''
        self.severity = severity
        self.bc_id = ''
