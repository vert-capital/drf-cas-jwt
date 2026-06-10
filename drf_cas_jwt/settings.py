from django.conf import settings as dj_settings

DEFAULTS = {
    "CAS_JWT_LOGOUT_REDIRECT": "/",
    "CAS_JWT_LOGIN_REDIRECT": "/",
}


class Settings:
    """
    Lazy settings wrapper, for use in app-specific conf.py files
    """

    def __init__(self, defaults):
        """
        Constructor

        :param defaults: default values for settings, will be return if
                         not overridden in the project settings
        :type defaults: dict
        """
        self.defaults = defaults

    def __getattr__(self, name):
        """
        Return the setting with the specified name, from the project settings
        (if overridden), else from the default values passed in during
        construction.

        :param name: name of the setting to return
        :type name: str
        :return: the named setting
        :raises: AttributeError -- if the named setting is not found
        """
        if hasattr(dj_settings, name):
            return getattr(dj_settings, name)

        if name in self.defaults:
            return self.defaults[name]

        raise AttributeError("'{name}' setting not found".format(name=name))


settings = Settings(DEFAULTS)
