# -*- coding: utf-8 -*-
# ########################################################################
# Program: Metasign
# Author: "CRash"
# Version: "1.1.0"
# Date: 09/14/21
# #########################################################################
# logger.py - Controls all aspects of logging for the Metasign.
#
# Description:
# This module allows customized logging of all i/o throughout Metasign.
# #########################################################################
import os
import sys
from datetime import datetime
from utils import SystemUtils
from colors import Colors

# Obtains the current working directory and appends the log folder and current datetime as the log file.
_default_log_path = f"{sys.path[0]}\\logs\\" if SystemUtils().get_system() == SystemUtils().windows else f"{sys.path[0]}/logs/"
_default_log_file = f"{_default_log_path}system-{datetime.now().strftime('%Y-%m-%d')}.txt"

class Logger(object):
    """Logging class with a high degree of customization."""
    
    class Verbosity:
        """Encapsulates the varying degrees of logging output detail."""
        low = 0
        default = 1
        high = 2
        debug = 3
        
    def __init__(self: "Logger", module_name: __name__, write_output: bool = True, log_path: str = _default_log_path, log_file: str = _default_log_file):
        """Creates a custom logger object with the provided parameters.

        Parameters
        ----------
        :param module_name: The name of the module calling the logging object.
        :type message: str\n
        :param write_output: A boolean, `True` for writing the message to the log file, or `False` if not.
        :type write_output: bool, optional\n
        :param log_path: The path of the log file directory to write log messages to.
        :type log_path: str, optional\n
        :param log_fle: The path of the log file itself to write log messages to.
        :type log_file: str, optional
        """
        self.module_name = module_name
        self.write_output = write_output
        self.log_path = log_path
        self.log_file = log_file
        self.divider = "\\" if SystemUtils().get_system() == SystemUtils().windows else "/"
        if not self.log_path.endswith(self.divider):
            self.log_path += f"{self.log_path}{self.divider}"

    def _write(self: "Logger", entry: str, context = None) -> bool:
        """Internal method which allows the writing of a string message to a file.
        
        Parameters
        ----------
        :param entry: The message to log to the local system and or file.
        :type entry: str\n
        :param context: Any object that can be parsed through the context manager.
        :type context: object, optional

        Returns
        ----------
        :rtype: bool
        :return: A boolean, `True` if the operation completed successfully, or `False` if not.
        """
        # Check if the log file is the default one and create its directory if it doesn't exist.
        def parse_context(context):
            """Check for a custom log type or another context object."""
            if isinstance(context, str):
                if context.lower() == "debug":
                    debug_path = f"{self.log_path}debug{self.divider}"
                    if not os.path.exists(debug_path):
                        os.mkdir(debug_path)
                    self.log_file = f"{debug_path}debug-{datetime.now().strftime('%Y-%m-%d')}.txt"
                    return True
            return False
        original_log_path = self.log_path
        try: #* Parse the location of the data to be logged.
            if self.log_file != _default_log_file:
                if not self.log_path.startswith(f"{sys.path[0]}"):
                    self.log_path = f"{sys.path[0]}{self.log_path}"
            #? Make sure that the logging directory exists.
            if not os.path.exists(self.log_path):
                os.mkdir(self.log_path)
            #! Alter the original logging paths if there's a contextual component.
            if context is not None: parse_context(context)
        except Exception as e: print(e); pass
        try: #* Log the data to the appropriate location.
            with open(self.log_file, "a") as log:
                log.write(entry + "\n")
                self.log_path = original_log_path #? Prevent future entry locations from being appended.
                return True
        except: self.error(f"The log file or its directory does not exist: {self.log_file}", write_output=False)
        self.log_path = original_log_path #? Prevent future entry locations from being appended.
        return False

    def info(self: "Logger", message: str, write_output: bool = True, print_output: bool = True, context = None) -> None:
        """Displays and or writes a non-critical information based message to the console and or a logging file.
        
        Parameters
        ----------
        :param message: The message to log to the local system and or log file.
        :type message: str\n
        :param write_output: A boolean, `True` for writing the message to a log file, or `False` if not.
        :type write_output: bool, optional\n
        :param print_output: A boolean, `True` for printing the message to the console, or `False` if not.
        :type print_output: bool, optional\n
        :param context: Any object that can be parsed through traditional inspection.
        :type context: object, optional\n
        """
        timestamp = datetime.now().strftime("%Y-%m-%d @ %H:%M:%S")
        entry = (f"{Colors.Foreground.pink}{timestamp}{Colors.reset} | {Colors.Foreground.darkgrey}INFO{Colors.reset} | {Colors.Foreground.blue}{self.module_name}{Colors.reset} > {message}")
        if (write_output):
            if (self.write_output): # Make sure the global flag allows us to print.
                self._write(entry, context=context) if context is not None else self._write(entry)
        if print_output: print(entry)

    def note(self: "Logger", message: str, write_output: bool = True, print_output: bool = True, context = None) -> None:
        """Displays and or writes a note-worthy information based message to the console and or a logging file.
        
        Parameters
        ----------
        :param message: The message to log to the local system and or log file.
        :type message: str\n
        :param write_output: A boolean, `True` for writing the message to a log file, or `False` if not.
        :type write_output: bool, optional\n
        :param print_output: A boolean, `True` for printing the message to the console, or `False` if not.
        :type print_output: bool, optional\n
        :param context: Any object that can be parsed through traditional inspection.
        :type context: object, optional\n
        """
        timestamp = datetime.now().strftime("%Y-%m-%d @ %H:%M:%S")
        entry = (f"{Colors.Foreground.pink}{timestamp}{Colors.reset} | {Colors.Foreground.lightgrey}NOTE{Colors.reset} | {Colors.Foreground.blue}{self.module_name}{Colors.reset} > {message}")
        if (write_output):
            if (self.write_output): # Make sure the global flag allows us to print.
                self._write(entry, context=context) if context is not None else self._write(entry)
        if print_output: print(entry)

    def success(self: "Logger", message: str, write_output: bool = True, print_output: bool = True, context = None) -> None:
        """Displays and or writes a success message to the console and or a logging file.
        
        Parameters
        ----------
        :param message: The message to log to the local system and or log file.
        :type message: str\n
        :param write_output: A boolean, `True` for writing the message to a log file, or `False` if not.
        :type write_output: bool, optional\n
        :param print_output: A boolean, `True` for printing the message to the console, or `False` if not.
        :type print_output: bool, optional\n
        :param context: Any object that can be parsed through traditional inspection.
        :type context: object, optional\n
        """
        timestamp = datetime.now().strftime("%Y-%m-%d @ %H:%M:%S")
        entry = (f"{Colors.Foreground.pink}{timestamp}{Colors.reset} | {Colors.Foreground.green}PASS{Colors.reset} | {Colors.Foreground.blue}{self.module_name}{Colors.reset} > {message}")
        if (write_output):
            if (self.write_output): # Make sure the global flag allows us to print.
                self._write(entry, context=context) if context is not None else self._write(entry)
        if print_output: print(entry)

    def warning(self: "Logger", message: str, write_output: bool = True, print_output: bool = True, context = None) -> None:
        """Displays and or writes a warning message to the console and or a logging file.
        
        Parameters
        ----------
        :param message: The message to log to the local system and or log file.
        :type message: str\n
        :param write_output: A boolean, `True` for writing the message to a log file, or `False` if not.
        :type write_output: bool, optional\n
        :param print_output: A boolean, `True` for printing the message to the console, or `False` if not.
        :type print_output: bool, optional\n
        :param context: Any object that can be parsed through traditional inspection.
        :type context: object, optional\n
        """
        timestamp = datetime.now().strftime("%Y-%m-%d @ %H:%M:%S")
        entry = (f"{Colors.Foreground.pink}{timestamp}{Colors.reset} | {Colors.Foreground.yellow}WARN{Colors.reset} | {Colors.Foreground.blue}{self.module_name}{Colors.reset} > {message}")
        if (write_output):
            if (self.write_output): # Make sure the global flag allows us to print.
                self._write(entry, context=context) if context is not None else self._write(entry)
        if print_output: print(entry)

    def error(self: "Logger", message: str, write_output: bool = True, print_output: bool = True, context = None) -> None:
        """Displays and or writes an error based message to the console and or a logging file.
        
        Parameters
        ----------
        :param message: The message to log to the local system and or log file.
        :type message: str\n
        :param write_output: A boolean, `True` for writing the message to a log file, or `False` if not.
        :type write_output: bool, optional\n
        :param print_output: A boolean, `True` for printing the message to the console, or `False` if not.
        :type print_output: bool, optional\n
        :param context: Any object that can be parsed through traditional inspection.
        :type context: object, optional\n
        """
        timestamp = datetime.now().strftime("%Y-%m-%d @ %H:%M:%S")
        entry = (f"{Colors.Foreground.pink}{timestamp}{Colors.reset} | {Colors.Foreground.red}FAIL{Colors.reset} | {Colors.Foreground.blue}{self.module_name}{Colors.reset} > {Colors.Foreground.red}{message}{Colors.reset}")
        if (write_output):
            if (self.write_output): # Make sure the global flag allows us to print.
                self._write(entry, context=context) if context is not None else self._write(entry)
        if print_output: print(entry)

    def private(self: "Logger", message: str, write_output: bool = True, print_output: bool = True, context = None) -> None:
        """Displays and or writes a debug based message to the console and or a logging file.
        
        Parameters
        ----------
        :param message: The message to log to the local system and or log file.
        :type message: str\n
        :param write_output: A boolean, `True` for writing the message to a log file, or `False` if not.
        :type write_output: bool, optional\n
        :param print_output: A boolean, `True` for printing the message to the console, or `False` if not.
        :type print_output: bool, optional\n
        :param context: Any object that can be parsed through traditional inspection.
        :type context: object, optional\n
        """
        timestamp = datetime.now().strftime("%Y-%m-%d @ %H:%M:%S")
        entry = (f"{Colors.Foreground.pink}{timestamp}{Colors.reset} | {Colors.Foreground.orange}{Colors.bold}PRIV{Colors.reset} | {Colors.Foreground.blue}{Colors.bold}{self.module_name}{Colors.reset} > {Colors.Foreground.orange}{message}{Colors.reset}")
        if (write_output):
            if (self.write_output): # Make sure the global flag allows us to print.
                self._write(entry, context=context) if context is not None else self._write(entry)
        if print_output: print(entry)

    def debug(self: "Logger", message: str, write_output: bool = True, print_output: bool = True, context = None) -> None:
        """Displays and or writes a debug based message to the console and or a logging file.
        
        Parameters
        ----------
        :param message: The message to log to the local system and or log file.
        :type message: str\n
        :param write_output: A boolean, `True` for writing the message to a log file, or `False` if not.
        :type write_output: bool, optional\n
        :param print_output: A boolean, `True` for printing the message to the console, or `False` if not.
        :type print_output: bool, optional\n
        :param context: Any object that can be parsed through traditional inspection.
        :type context: object, optional\n
        """
        timestamp = datetime.now().strftime("%Y-%m-%d @ %H:%M:%S")
        entry = (f"{Colors.Foreground.pink}{timestamp}{Colors.reset} | {Colors.Foreground.pink}{Colors.bold}DEVS{Colors.reset} | {Colors.Foreground.pink}{Colors.bold}{self.module_name}{Colors.reset} > {Colors.Foreground.pink}{message}{Colors.reset}")
        if (write_output):
            if (self.write_output): # Make sure the global flag allows us to print.
                self._write(entry, context=context) if context is not None else self._write(entry)
        if print_output: print(entry)