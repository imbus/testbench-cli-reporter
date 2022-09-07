import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .config_model import loggingConfiguration

logger = logging.Logger("testbench-reporter", logging.DEBUG)


def setup_logger(config: loggingConfiguration):
    console_handler = logging.StreamHandler()
    console_handler.setLevel(config.console.logLevel.value)
    console_handler.setFormatter(logging.Formatter(config.console.logFormat))
    logger.addHandler(console_handler)
    if config.file:
        log_file_path = Path(config.file.fileName)
        if not log_file_path.parent.is_dir():
            log_file_path.parent.mkdir(parents=True)
        file_handler = RotatingFileHandler(
            filename=log_file_path,
            mode="a",
            maxBytes=1 * 1024 * 1024,
            backupCount=2,
            encoding="utf_8",
            delay=False,
        )
        file_handler.setLevel(config.file.logLevel.value)
        file_handler.setFormatter(logging.Formatter(config.file.logFormat))
        logger.addHandler(file_handler)
