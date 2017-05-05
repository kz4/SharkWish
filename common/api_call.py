class ApiCall(object):
    def parse(self):
        raise NotImplementedError

    def validate(self):
        raise NotImplementedError

    def run(self):
        raise NotImplementedError
