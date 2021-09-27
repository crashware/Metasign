# -*- coding: utf-8 -*-
# ########################################################################
# Program: Metasign
# Author: "CRash"
# Version: "1.1.0"
# Date: 09/14/21
# #########################################################################
# utils.py - Contains common tools and reusable functionality.
#
# Description:
# This module encapsulates functions that are used globally throughout
# the script, sentinel instances, or other project modules.
# #########################################################################
import os
import re
import base64
import string
import secrets
from random import randint

class SystemUtils:
    """Encapsulation of common operating system identifiers."""
    windows = "nt"
    linux = "posix"
    macos = "posix"
    cygwin = "posix"

    @staticmethod
    def get_system() -> str:
        """Returns the name of the currently running operating system."""
        return os.name

    @staticmethod
    def get_line(filepath: str) -> str:
        """Returns the first line of a provided file in a read-only fashion.
        
        Parameters
        ----------
        :param filepath: The path of the file to read a line.
        :type filepath: str

        Raises
        ------
        :class:`IOError`: The file could not be read.
        :class:`OSError`: The file could not opened or read.
        :class:`Exception`: The file could not be read in general.

        Returns
        -------
        :rtype: str
        :return: The line that was read from the file.
        """
        if os.path.exists(filepath):
            try:
                with open(filepath, "r") as f:
                    return f.readline().replace('\n', '') # Make sure to trim newlines because they can break db connections.
            except IOError: raise IOError(f"The file '{filepath}' could not be read.")
            except OSError: raise OSError(f"The file '{filepath}' could not be opened or read.")
            except: raise Exception(f"The file '{filepath}' could not be read.")
        else: return None

    @staticmethod
    def read_from_file(filepath: str) -> str:
        """Returns all data of a provided file in a read-only fashion.
        
        Parameters
        ----------
        :param filepath: The path of the file to read.
        :type filepath: str

        Raises
        ------
        :class: `IOError`: The file could not be read.
        :class: `OSError`: The file could not opened or read.
        :class: `Exception`: The file could not be read in general.

        Returns
        -------
        :rtype: str
        :return: Data that was read from the file.
        """
        if os.path.exists(filepath):
            try:
                with open(filepath, "r") as f:
                    details = f.read()
                    return details
            except IOError: raise IOError(f"The file '{filepath}' could not be read.")
            except OSError: raise OSError(f"The file '{filepath}' could not be opened or read.")
            except: raise Exception(f"The file '{filepath}' could not be read.")
        else: return None            

    @staticmethod
    def write_to_file(filepath: str, data: str) -> int:
        """Writes all data to the provided file in a truncated fashion.
        
        Parameters
        ----------
        :param filepath: The path of the file to write.
        :type filepath: str

        Raises
        ------
        :class: `IOError`: The file could not be written.
        :class: `OSError`: The file could not opened or written.
        :class: `Exception`: The file could not be written in general.

        Returns
        -------
        :rtype: int
        :return: The return value of the `open.write()` function.
        """
        try:
            if not os.path.exists(os.path.dirname(os.path.abspath(filepath))):
                os.makedirs(os.path.dirname(os.path.abspath(filepath)))
            with open(filepath, "w") as f:
                details = f.write(data)
                return details
        except IOError: raise IOError(f"The file '{filepath}' could not be written.")
        except OSError: raise OSError(f"The file '{filepath}' could not be opened or written.")
        except: raise Exception(f"The file '{filepath}' could not be written.")

class ConversionUtils:
    """Contains a collection of tools that allows easier conversion of types and values."""
    @staticmethod
    def bool_to_int(value: bool) -> int:
        """
        Converts a boolean value into a integer.

        Parameters
        ----------
        :param value: The boolean flag to convert.
        :type value: bool

        Returns
        ----------
        :rtype: int
        :return: The integer value of the boolean.
        """
        if value is True:
            return 1
        else:
            return 0

    @staticmethod
    def int_to_bool(value: int) -> bool:
        """
        Converts a integer into a boolean value.

        Parameters
        ----------
        :param value: The integer value to convert.
        :type value: int

        Returns
        ----------
        :rtype: int
        :return: The boolean value of the integer.
        """
        if value is None or value == 0:
            return False
        else:
            return True

class FormatUtils:
    """Encapsulates a collection of formatting variables and functionality which make output cleaner."""
    SYMBOLS = {
    'asterisk': '\u002A',
    'bullet': '\u2022',
    'hollow': '\u25E6',
    'hyphen': '\u2043',
    'triangle': '\u2023'
    }

    def _get_symbol(self: "FormatUtils", symbol: str) -> str:
        """
        A function to check for the existence of a specified symbol.

        Parameters
        ----------
        :param symbol: String representation of a symbol to search for.
        :type symbol: str

        Returns
        ----------
        :rtype: str
        :return: The symbol if one is found, else `None` is returned.
        """
        if symbol in self.SYMBOLS and symbol is not None:
            symbol = self.SYMBOLS.get(symbol, None)
        return symbol

    def format_list(self: "FormatUtils", items: list, **kwargs) -> str:
        """
        A function to format a list so it is more readable when it is displayed.

        Parameters
        ----------
        :param items: A collection of strings to join in a nice list.
        :type items: list\n
        :param **kwargs: A collection of strings to join in a nice list.
        :type **kwargs: dict

        Returns
        ----------
        :rtype: str
        :return: A formatted string containing all of the list items.
        """
        sort = kwargs.get('sort')
        enumerate = kwargs.get('enumerate')
        symbol = kwargs.get('symbol')
        symbol = self._get_symbol(symbol)
        if sort:
            items = sorted(items)
        if enumerate:
            return '\n'.join(items)
        if symbol is not None:
            result = []
            for item in items:
                if symbol == '*':
                    result.append(f"{symbol}{item}")
                else:
                    result.append(f"{symbol} {item}")
            return '\n'.join(result)
        return ', '.join(items)

class TextUtils:
    """Contains a collection of text formatting utilities such as random case conversion and making a input alphanumeric only."""
    @staticmethod
    def generate_id(length: int = 10) -> str:
        """Allows the creation of an alphanumeric string for sentinel identification.
        
        Parameters
        ----------
        :param length: The length of the identifier to be generated.
        :type length: int, optional

        Returns
        ----------
        :rtype: str
        :return: The generated id of a specified length.
        """
        characters = string.ascii_letters + string.digits
        result = ''.join((secrets.choice(characters) for i in range(length)))
        return result

    @staticmethod
    def generate_cid(length: int = 64) -> str:
        """Returns a Base64 encoded cryptographically strong random identifier.
        
        Parameters
        ----------
        :param length: The length of the identifier to be generated.
        :type length: int, optional

        Returns
        ----------
        :rtype: str
        :return: The generated cryptographic id of a specified length.
        """
        return base64.b64encode(str.encode(TextUtils.generate_id(length))).decode('utf-8')

    @staticmethod
    def escape_md(text: str) -> str:
        """
        Formats input so that any markdown tags are removed.

        Parameters
        ----------
        :param text: String to escape markdown.
        :type text: str

        Returns
        ----------
        :rtype: str
        :return: The escaped string.
        """
        markdown = ['*', '`', '_', '~', '\\', '||']
        result = ""
        for c in text:
            if not c in markdown:
                result += c
        return result

    @staticmethod
    def alphabet(text: str) -> str:
        """
        A function to filter a string to only allow alphabetical characters.

        Parameters
        ----------
        :param text: String to convert to alphabetical chars only
        :type text: str

        Returns
        ----------
        :rtype: str
        :return: Formatted alphabetical string
        """
        pattern = re.compile('[^a-zA-Z]+')
        return pattern.sub('', text)

    @staticmethod
    def alphabet_and_spaces(text: str) -> str:
        """
        A function to filter a string to only allow alphabetical characters and spaces.

        Parameters
        ----------
        :param text: String to convert to alphabetical chars and spaces only
        :type text: str

        Returns
        -------
        :rtype: str
        :return: Formatted alphbetical string with spaces
        """
        pattern = re.compile('[^a-zA-Z ]+')
        return pattern.sub('', text)

    @staticmethod
    def random_case(text: str) -> str:
        """
        A function to convert a string to "random case".\n

        Parameters
        ----------
        :param text: String to convert to "random case"
        :type text: str

        Returns
        -------
        :rtype: str
        :return: Formatted string that's in "random case"
        """
        result = ''
        for index, character in enumerate(text, 1):
            if character == 'i' or index == 1:
                result += character.lower()
            else:
                integer = randint(0, 1)
                result += character.upper() if integer == 0 else character.lower()
        return result

class EncodingUtils:
    class Unicode:
        """Encapsulates variables and functionality relating to malformed or Zalgo text."""
        zalgo_up = [0x030d, 0x030e, 0x0304, 0x0305,
                    0x033f, 0x0311, 0x0306, 0x0310,
                    0x0352, 0x0357, 0x0351, 0x0307,
                    0x0308, 0x030a, 0x0342, 0x0343,
                    0x0344, 0x034a, 0x034b, 0x034c,
                    0x0303, 0x0302, 0x030c, 0x0350,
                    0x0300, 0x0301, 0x030b, 0x030f,
                    0x0312, 0x0313, 0x0314, 0x033d,
                    0x0309, 0x0363, 0x0364, 0x0365,
                    0x0366, 0x0367, 0x0368, 0x0369,
                    0x036a, 0x036b, 0x036c, 0x036d,
                    0x036e, 0x036f, 0x033e, 0x035b]
        zalgo_down = [0x0316, 0x0317, 0x0318, 0x0319,
                    0x031c, 0x031d, 0x031e, 0x031f,
                    0x0320, 0x0324, 0x0325, 0x0326,
                    0x0329, 0x032a, 0x032b, 0x032c,
                    0x0331, 0x0332, 0x0333, 0x0339,
                    0x032d, 0x032e, 0x032f, 0x0330,
                    0x032d, 0x032e, 0x032f, 0x0330,
                    0x032d, 0x032e, 0x032f, 0x0330,
                    0x033a, 0x033b, 0x033c, 0x0345,
                    0x0347, 0x0348, 0x0349, 0x034d,
                    0x034e, 0x0353, 0x0354, 0x0355,
                    0x0356, 0x0359, 0x035a, 0x0323]
        zalgo_mid = [0x0315, 0x031b, 0x0340, 0x0341,
                    0x0358, 0x0321, 0x0322, 0x0327,
                    0x0328, 0x0334, 0x0335, 0x0336,
                    0x034f, 0x035c, 0x035d, 0x035e,
                    0x035f, 0x0360, 0x0362, 0x0338,
                    0x0337, 0x0361, 0x0489]

        def is_zalgo_character(self: "EncodingUtils", character: str) -> bool:
            """Checks a pre-defined list of unicode characters to see if the provided character is Zalgo.
            
            Parameters
            ----------
            :param character: The character to check against ordinals.
            :type character: str

            Returns
            ----------
            :rtype: bool
            :return: A boolean, `True` if the character is found, or `False` if not.
            """
            if ord(character) in self.zalgo_up: return True
            if ord(character) in self.zalgo_down: return True
            if ord(character) in self.zalgo_mid: return True
            return False

        @staticmethod
        def is_asian_character(character: str) -> bool:
            """Checks if a character is an Asian character.
            
            Parameters
            ----------
            :param char: The character to check against ordinals.
            :type char: str

            Returns
            ----------
            :rtype: bool
            :return: A boolean, `True` if the character is found, or `False` if not.
            """
            ranges = [
            {"from": ord(u"\u3300"), "to": ord(u"\u33ff")},         # compatibility ideographs
            {"from": ord(u"\ufe30"), "to": ord(u"\ufe4f")},         # compatibility ideographs
            {"from": ord(u"\uf900"), "to": ord(u"\ufaff")},         # compatibility ideographs
            {"from": ord(u"\U0002F800"), "to": ord(u"\U0002fa1f")}, # compatibility ideographs
            {'from': ord(u'\u3040'), 'to': ord(u'\u309f')},         # Japanese Hiragana
            {"from": ord(u"\u30a0"), "to": ord(u"\u30ff")},         # Japanese Katakana
            {"from": ord(u"\u2e80"), "to": ord(u"\u2eff")},         # cjk radicals supplement
            {"from": ord(u"\u4e00"), "to": ord(u"\u9fff")},
            {"from": ord(u"\u3400"), "to": ord(u"\u4dbf")},
            {"from": ord(u"\U00020000"), "to": ord(u"\U0002a6df")},
            {"from": ord(u"\U0002a700"), "to": ord(u"\U0002b73f")},
            {"from": ord(u"\U0002b740"), "to": ord(u"\U0002b81f")},
            {"from": ord(u"\U0002b820"), "to": ord(u"\U0002ceaf")}  # included as of Unicode 8.0
            ]
            return any([range["from"] <= ord(character) <= range["to"] for range in ranges])
