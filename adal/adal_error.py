class AdalError(Exception):
    def __init__(self, error_msg, error_response=None):
        super(AdalError, self).__init__(error_msg)
        self.error_response = error_response
