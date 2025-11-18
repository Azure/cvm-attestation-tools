# logger.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import logging
import os

class Logger:
    def __init__(self, name, log_to_file=False, filename='out.log'):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(funcName)s - %(levelname)s - %(message)s')

        if log_to_file:
            # Ensure the directory for the log file exists
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            file_handler = logging.FileHandler(filename)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
        else:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

    def get_logger(self):
        return self.logger
