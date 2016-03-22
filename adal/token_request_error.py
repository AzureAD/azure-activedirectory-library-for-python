class TokenRequestError(Exception):
    def __init__(self, error_msg, error_response=None, **kwargs):
        self.error_msg = error_msg
        self.error_response = error_response
        return super().__init__(**kwargs)

class MexDiscoverError(Exception):
    def __init__(self, error_msg, error_response=None, **kwargs):
        self.error_msg = error_msg
        self.error_response = error_response
        return super().__init__(**kwargs)

class MexParseError(Exception):
    def __init__(self, error_msg, **kwargs):
        self.error_msg = error_msg
        return super().__init__(**kwargs)

class DeviceCodeRequestError(Exception):
    def __init__(self, error_msg, **kwargs):
        self.error_msg = error_msg
        return super().__init__(**kwargs)

class AuthorityValidationError(Exception):
    def __init__(self, error_msg, error_response = None, **kwargs):
        self.error_msg = error_msg
        self.error_response = error_response
        return super().__init__(**kwargs)

class UserRealmDiscoverError(Exception):
    def __init__(self, error_msg, error_response = None, **kwargs):
        self.error_msg = error_msg
        self.error_response = error_response
        return super().__init__(**kwargs)