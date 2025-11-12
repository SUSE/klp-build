import logging
import logging.config
import sys


class LevelFormatter(logging.Formatter):
    """
    A custom formatter that adds the level name ONLY for
    log messages with the level WARNING, ERROR and CRITICAL.
    """
    default_format = "%(message)s"
    level_format = "%(levelname)s: %(message)s"

    def __init__(self):
        super().__init__(fmt=self.default_format, datefmt=None, style='%')

    def format(self, record):
        # Save original format
        original_fmt = self._fmt
        original_style = self._style

        if record.levelno >= logging.WARNING:
            self._fmt = self.level_format
        else:
            self._fmt = self.default_format

        self._style = logging.PercentStyle(self._fmt)

        result = super().format(record)

        # Restore original format
        self._fmt = original_fmt
        self._style = original_style

        return result


LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,

    'formatters': {
        'custom_level': {
            '()': LevelFormatter,
        },
    },

    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'custom_level',
            'stream': sys.stdout,
        },
    },

    'root': {
        'level': 'INFO',
        'handlers': ['console'],
    },
}


def load_config():
    logging.config.dictConfig(LOGGING_CONFIG)
