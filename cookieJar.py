# import necessary libraries
import base64
import configparser
import contextlib
import glob
import http.cookiejar
import json
import os
import struct
import subprocess
import sys
import tempfile
from io import BytesIO
from typing import Union

try:
    from pysqlite2 import dbapi2 as sqlite3
except ImportError:
    import sqlite3

if sys.platform.startswith('linux') or 'bsd' in sys.platform.lower():
    try:
        import dbus
        USE_DBUS_LINUX = True
    except ImportError:
        import jeepney
        from jeepney.io.blocking import open_dbus_connection
        USE_DBUS_LINUX = False

import lz4.block
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Util.Padding import unpad

# set the docstring for the module
__doc__ = 'Load browser cookies into a cookiejar'  # module description

# define a constant for the default Chromium password
CHROMIUM_DEFAULT_PASSWORD = b'peanuts'  # default password for Chromium

# define a custom exception for browser cookie errors
class BrowserCookieError(Exception):  # custom exception class
    pass  # no additional functionality needed

# define a function to create a local copy of the cookie file
def _create_local_copy(cookie_file):
    """Make a local copy of the sqlite cookie database and return the new filename.
    This is necessary in case this database is still being written to while the user browses
    to avoid sqlite locking errors.
    """
    # check if the cookie file exists
    if os.path.exists(cookie_file):  # if the file exists
        # create a temporary file in the system's temp directory
        tmp_cookie_file = tempfile.NamedTemporaryFile(suffix='.sqlite').name  # create a temp file with a .sqlite extension
        # open the temp file in write-binary mode and the cookie file in read-binary mode
        with open(tmp_cookie_file, "wb") as f1, open(cookie_file, "rb") as f2:  # open both files
            f1.write(f2.read())  # read the cookie file and write its contents to the temp file
        return tmp_cookie_file  # return the name of the temp file
    else:  # if the file doesn't exist
        # raise a custom exception
        raise BrowserCookieError('Can not find cookie file at: ' + cookie_file)  # raise an error

# define a function to get the path of the cookie file on Windows
def _windows_group_policy_path():
    # import the necessary Windows registry functions
    from winreg import (HKEY_LOCAL_MACHINE, REG_EXPAND_SZ, REG_SZ,
                        ConnectRegistry, OpenKeyEx, QueryValueEx)  # import Windows registry functions
    try:
        # connect to the local machine registry
        root = ConnectRegistry(None, HKEY_LOCAL_MACHINE)  # connect to the local machine registry
        # open the key for Google Chrome's policies
        policy_key = OpenKeyEx(root, r"SOFTWARE\Policies\Google\Chrome")  # open the Chrome policy key
        # query the value of the "UserDataDir" entry
        user_data_dir, type_ = QueryValueEx(policy_key, "UserDataDir")  # get the user data directory
        # if the type of the entry is REG_EXPAND_SZ, expand any environment variables in the value
        if type_ == REG_EXPAND_SZ:  # if the type is REG_EXPAND_SZ
            user_data_dir = os.path.expandvars(user_data_dir)  # expand environment variables
        # if the type of the entry is not REG_SZ, return None
        elif type_ != REG_SZ:  # if the type is not REG_SZ
            return None  # return None
    # if there's an OSError (e.g., the key doesn't exist), return None
    except OSError:  # if there's an OSError
        return None  # return None
    # return the path of the "Cookies" file in the user data directory
    return os.path.join(user_data_dir, "Default", "Cookies")  # return the path of the Cookies file

# define a function to decrypt data on Windows
def _crypt_unprotect_data(
        cipher_text=b'', entropy=b'', reserved=None, prompt_struct=None, is_key=False
):
    # import the necessary ctypes functions
    import ctypes
    import ctypes.wintypes  # import ctypes for Windows types

    # define a ctypes Structure for a data blob
    class DataBlob(ctypes.Structure):  # define a ctypes Structure
        _fields_ = [
            ('cbData', ctypes.wintypes.DWORD),  # size of the data
            ('pbData', ctypes.POINTER(ctypes.c_char))  # pointer to the data
        ]

    # create DataBlob objects for the input, entropy, and output
    blob_in, blob_entropy, blob_out = map(
        lambda x: DataBlob(len(x), ctypes.create_string_buffer(x)),  # create a DataBlob for each item
        [cipher_text, entropy, b'']  # the items to create DataBlobs for
    )

    # create a ctypes string buffer for the description
    desc = ctypes.c_wchar_p()  # create a ctypes string buffer

    # define a constant for the CryptUnprotectData function
    CRYPTPROTECT_UI_FORBIDDEN = 0x01  # constant for CryptUnprotectData

    # call the CryptUnprotectData function
    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), ctypes.byref(desc), ctypes.byref(blob_entropy),
            reserved, prompt_struct, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out)
    ):
        # if the function fails, raise a RuntimeError
        raise RuntimeError('Failed to decrypt the cipher text with DPAPI')  # raise an error

    # get the description and output data
    description = desc.value  # get the description
    buffer_out = ctypes.create_string_buffer(int(blob_out.cbData))  # create a buffer for the output data
    ctypes.memmove(buffer_out, blob_out.pbData, blob_out.cbData)  # copy the output data to the buffer
    map(ctypes.windll.kernel32.LocalFree, [desc, blob_out.pbData])  # free the memory used by the description and output data

    # if the data is a key, return the raw data; otherwise, return the string value
    if is_key:  # if the data is a key
        return description, buffer_out.raw  # return the raw data
    else:  # if the data is not a key
        return description, buffer_out.value  # return the string value

# define a function to retrieve the password from the OSX keychain
def _get_osx_keychain_password(osx_key_service, osx_key_user):
    """Retrieve password used to encrypt cookies from OSX Keychain"""
    # define the command to retrieve the password
    cmd = ['/usr/bin/security', '-q', 'find-generic-password', '-w', '-a', osx_key_user, '-s', osx_key_service]  # command to retrieve the password
    # execute the command
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # execute the command
    # get the output and error of the command
    out, err = proc.communicate()  # get the output and error
    # if the command failed, return the default Chromium password
    if proc.returncode != 0:  # if the command failed
        return CHROMIUM_DEFAULT_PASSWORD  # return the default password
    # otherwise, return the password
    return out.strip()  # return the password