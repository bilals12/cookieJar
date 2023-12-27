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

# define a function to expand a Windows path
def _expand_win_path(path: Union[dict, str]):
    # if the path is not a dictionary, convert it to a dictionary
    if not isinstance(path, dict):  # if the path is not a dictionary
        path = {'path': path}  # convert the path to a dictionary
    # return the expanded path
    return os.path.join(os.getenv(path['env'], ''), path['path'])  # return the expanded path

# define a function to expand paths on different operating systems
def _expand_paths_impl(paths: list, os_name: str):
    """Expands user paths on Linux, OSX, and windows"""
    # convert the os_name to lowercase
    os_name = os_name.lower()  # convert to lowercase
    # assert that the os_name is one of the expected values
    assert os_name in ['windows', 'osx', 'linux']  # check that the os_name is valid

    # if paths is not a list, convert it to a list
    if not isinstance(paths, list):  # if paths is not a list
        paths = [paths]  # convert paths to a list

    # if the os_name is 'windows', expand the paths using _expand_win_path
    if os_name == 'windows':  # if the os_name is 'windows'
        paths = map(_expand_win_path, paths)  # expand the paths
    # otherwise, expand the paths using os.path.expanduser
    else:  # if the os_name is not 'windows'
        paths = map(os.path.expanduser, paths)  # expand the paths

    # for each path in paths
    for path in paths:  # for each path
        # for each file in the sorted list of files that match the path
        for i in sorted(glob.glob(path)):  # for each file
            # yield the file
            yield i  # yield the file

# define a function to expand paths and return the first result
def _expand_paths(paths: list, os_name: str):
    # return the first result from _expand_paths_impl, or None if there are no results
    return next(_expand_paths_impl(paths, os_name), None)  # return the first result or None

# define a function to normalize paths and channels for Chromium
def _normalize_genarate_paths_chromium(paths: Union[str, list], channel: Union[str, list] = None):
    # if channel is None, set it to an empty string
    channel = channel or ['']  # set default channel
    # if channel is not a list, convert it to a list
    if not isinstance(channel, list):  # if channel is not a list
        channel = [channel]  # convert channel to a list
    # if paths is not a list, convert it to a list
    if not isinstance(paths, list):  # if paths is not a list
        paths = [paths]  # convert paths to a list
    # return the paths and channel
    return paths, channel  # return the paths and channel

# define a function to generate paths for Chromium on *nix systems
def _genarate_nix_paths_chromium(paths: Union[str, list], channel: Union[str, list] = None):
    """Generate paths for chromium based browsers on *nix systems."""
    # normalize the paths and channel
    paths, channel = _normalize_genarate_paths_chromium(paths, channel)  # normalize the paths and channel
    # initialize an empty list to hold the generated paths
    genararated_paths = []  # initialize an empty list
    # for each channel in the channel list
    for chan in channel:  # for each channel
        # for each path in the paths list
        for path in paths:  # for each path
            # append the path with the channel formatted into it to the list of generated paths
            genararated_paths.append(path.format(channel=chan))  # append the path
    # return the list of generated paths
    return genararated_paths  # return the generated paths

# define a function to generate paths for Chromium on Windows
def _genarate_win_paths_chromium(paths: Union[str, list], channel: Union[str, list] = None):
    """Generate paths for chromium based browsers on windows"""
    # normalize the paths and channel
    paths, channel = _normalize_genarate_paths_chromium(paths, channel)  # normalize the paths and channel
    # initialize an empty list to hold the generated paths
    genararated_paths = []  # initialize an empty list
    # for each channel in the channel list
    for chan in channel:  # for each channel
        # for each path in the paths list
        for path in paths:  # for each path
            # append the path with the channel formatted into it to the list of generated paths
            # for each of the three possible environment variables
            genararated_paths.append({'env': 'APPDATA', 'path': '..\\Local\\' + path.format(channel=chan)})  # append the path
            genararated_paths.append({'env': 'LOCALAPPDATA', 'path': path.format(channel=chan)})  # append the path
            genararated_paths.append({'env': 'APPDATA', 'path': path.format(channel=chan)})  # append the path
    # return the list of generated paths
    return genararated_paths  # return the generated paths

# define a function to decode data as UTF-8
def _text_factory(data):
    # try to decode the data as UTF-8
    try:  # try to decode
        return data.decode('utf-8')  # return the decoded data
    # if a UnicodeDecodeError is raised, return the original data
    except UnicodeDecodeError:  # if a UnicodeDecodeError is raised
        return data  # return the original data


# define a class to manage a Jeepney connection
class _JeepneyConnection:
    # initialize the connection
    def __init__(self, object_path, bus_name, interface):
        # store the DBus address
        self.__dbus_address = jeepney.DBusAddress(object_path, bus_name, interface)

    # enter the context of the connection
    def __enter__(self):
        # open the connection
        self.__connection = open_dbus_connection()
        # return the connection
        return self

    # exit the context of the connection
    def __exit__(self, exc_type, exc_value, traceback):
        # close the connection
        self.__connection.close()

    # define a method to close the connection
    def close(self):
        # close the connection
        self.__connection.close()

    # define a method to call a method on the DBus address
    def call_method(self, method_name, signature=None, *args):
        # create a new method call
        method = jeepney.new_method_call(self.__dbus_address, method_name, signature, args)
        # send the method call and get the reply
        response = self.__connection.send_and_get_reply(method)
        # if the response is an error, raise a RuntimeError
        if response.header.message_type == jeepney.MessageType.error:
            raise RuntimeError(response.body[0])
        # return the body of the response
        return response.body[0] if len(response.body) == 1 else response.body

# define a class to manage passwords on Linux
class _LinuxPasswordManager:
    """Retrieve password used to encrypt cookies from KDE Wallet or SecretService"""
    # define the application ID
    _APP_ID = 'browser-cookie3'

    # initialize the password manager
    def __init__(self, use_dbus):
        # if use_dbus is True, use the DBus methods
        if use_dbus:
            self.__methods_map = {
                'kwallet': self.__get_kdewallet_password_dbus,
                'secretstorage': self.__get_secretstorage_item_dbus
            }
        # otherwise, use the Jeepney methods
        else:
            self.__methods_map = {
                'kwallet': self.__get_kdewallet_password_jeepney,
                'secretstorage': self.__get_secretstorage_item_jeepney
            }

    # define a method to get the password
    def get_password(self, os_crypt_name):
        # try to get the password from SecretStorage
        try:
            return self.__get_secretstorage_password(os_crypt_name)
        except RuntimeError:
            pass
        # if that fails, try to get the password from KWallet
        try:
            return self.__methods_map.get('kwallet')(os_crypt_name)
        except RuntimeError:
            pass
        # if that fails, return the default Chromium password
        return CHROMIUM_DEFAULT_PASSWORD

    def __get_secretstorage_password(self, os_crypt_name):
    # define schemas to be used
    schemas = ['chrome_libsecret_os_crypt_password_v2', 'chrome_libsecret_os_crypt_password_v1']
    # iterate over schemas
    for schema in schemas:
        try:
            # try to get password using the current schema
            return self.__methods_map.get('secretstorage')(schema, os_crypt_name)
        except RuntimeError:
            # if an error occurs, continue to the next schema
            pass
    # if no password is found, raise an error
    raise RuntimeError(f'Can not find secret for {os_crypt_name}')

    def __get_secretstorage_item_dbus(self, schema: str, application: str):
        # open a DBus connection
        with contextlib.closing(dbus.SessionBus()) as connection:
            try:
                # try to get the secret service object
                secret_service = dbus.Interface(
                    connection.get_object('org.freedesktop.secrets', '/org/freedesktop/secrets', False),
                    'org.freedesktop.Secret.Service',
                )
            except dbus.exceptions.DBusException:
                # if an error occurs, raise an error
                raise RuntimeError("The name org.freedesktop.secrets was not provided by any .service files")
            # search for items matching the schema and application
            object_path = secret_service.SearchItems({
                'xdg:schema': schema,
                'application': application,
            })
            # filter out empty paths
            object_path = list(filter(lambda x: len(x), object_path))
            # if no paths were found, raise an error
            if len(object_path) == 0:
                raise RuntimeError(f'Can not find secret for {application}')
            # get the first path
            object_path = object_path[0][0]

            # unlock the secret service
            secret_service.Unlock([object_path])
            # open a session with the secret service
            _, session = secret_service.OpenSession('plain', dbus.String('', variant_level=1))
            # get the secrets from the secret service
            _, _, secret, _ = secret_service.GetSecrets([object_path], session)[object_path]
            # return the secret
            return bytes(secret)

    def __get_kdewallet_password_dbus(self, os_crypt_name):
        # define the folder and key to be used
        folder = f'{os_crypt_name.capitalize()} Keys'
        key = f'{os_crypt_name.capitalize()} Safe Storage'
        # open a DBus connection
        with contextlib.closing(dbus.SessionBus()) as connection:
            try:
                # try to get the kwalletd5 object
                kwalletd5_object = connection.get_object('org.kde.kwalletd5', '/modules/kwalletd5', False)
            except dbus.exceptions.DBusException:
                # if an error occurs, raise an error
                raise RuntimeError("The name org.kde.kwalletd5 was not provided by any .service files")
            # get the kwalletd5 interface
            kwalletd5 = dbus.Interface(kwalletd5_object, 'org.kde.KWallet')
            # open the wallet
            handle = kwalletd5.open(kwalletd5.networkWallet(), dbus.Int64(0), self._APP_ID)
            # if the folder does not exist, raise an error
            if not kwalletd5.hasFolder(handle, folder, self._APP_ID):
                kwalletd5.close(handle, False, self._APP_ID)
                raise RuntimeError(f'KDE Wallet folder {folder} not found.')
            # read the password from the wallet
            password = kwalletd5.readPassword(handle, folder, key, self._APP_ID)
            # close the wallet
            kwalletd5.close(handle, False, self._APP_ID)
            # return the password
            return password.encode('utf-8')

    def __get_secretstorage_item_jeepney(self, schema: str, application: str):
        # open a Jeepney connection to the SecretService
        with _JeepneyConnection('/org/freedesktop/secrets', 'org.freedesktop.secrets', 'org.freedesktop.Secret.Service') as connection:
            # search for items matching the schema and application
            object_path = connection.call_method('SearchItems', 'a{ss}', {'xdg:schema': schema, 'application': application})
            # filter out empty paths
            object_path = list(filter(lambda x: len(x), object_path))
            # if no paths were found, raise an error
            if len(object_path) == 0:
                raise RuntimeError(f'Can not find secret for {application}')
            # get the first path
            object_path = object_path[0][0]

            # unlock the secret service
            connection.call_method('Unlock', 'ao', [object_path])
            # open a session with the secret service
            _, session = connection.call_method('OpenSession', 'sv', 'plain', '')
            # get the secrets from the secret service
            _, _, secret, _ = connection.call_method('GetSecrets', 'aoo', [object_path], session)[object_path]
            # return the secret
            return bytes(secret)

    def __get_kdewallet_password_jeepney(self, os_crypt_name):
        # define the folder and key to be used
        folder = f'{os_crypt_name.capitalize()} Keys'
        key = f'{os_crypt_name.capitalize()} Safe Storage'
        # open a Jeepney connection to the KDE Wallet
        with _JeepneyConnection('/modules/kwalletd5', 'org.kde.KWallet', 'org.kde.KWallet') as connection:
            # open the wallet
            handle = connection.call_method('open', 'ssq', connection.call_method('networkWallet', ''), 0, self._APP_ID)
            # if the folder does not exist, raise an error
            if not connection.call_method('hasFolder', 'iqss', handle, folder, self._APP_ID):
                connection.call_method('close', 'iqs', handle, False, self._APP_ID)
                raise RuntimeError(f'KDE Wallet folder {folder} not found.')
            # read the password from the wallet
            password = connection.call_method('readPassword', 'iqsss', handle, folder, key, self._APP_ID)
            # close the wallet
            connection.call_method('close', 'iqs', handle, False, self._APP_ID)
            # return the password
            return password.encode('utf-8')

# define a class for Chromium-based browsers
class ChromiumBasedBrowser:

    UNIX_TO_NT_EPOCH_OFFSET = 11644473600  # seconds from 1601-01-01T00:00:00Z to 1970-01-01T00:00:00Z
    # initialize the browser
    def __init__(self, browser: str, cookie_file=None, domain_name="", key_file=None, **kwargs):
        # Initialize the salt, iv, and length for encryption/decryption
        self.salt = b'saltysalt'
        self.iv = b' ' * 16
        self.length = 16

        # Store the browser name, cookie file path, domain name, and key file path
        self.browser = browser
        self.cookie_file = cookie_file
        self.domain_name = domain_name
        self.key_file = key_file

        # Add the key and cookie file based on the operating system
        self.__add_key_and_cookie_file(**kwargs)

    def __add_key_and_cookie_file(self,
                              linux_cookies=None, windows_cookies=None, osx_cookies=None,
                              windows_keys=None, os_crypt_name=None, osx_key_service=None, osx_key_user=None):
        # Check the operating system
        if sys.platform == 'darwin':
            # If it's OSX, get the password from the OSX keychain
            password = _get_osx_keychain_password(osx_key_service, osx_key_user)
            iterations = 1003  # number of pbkdf2 iterations on mac
            # Generate the key
            self.v10_key = PBKDF2(password, self.salt, self.length, iterations)
            # Get the cookie file
            cookie_file = self.cookie_file or _expand_paths(osx_cookies, 'osx')

        elif sys.platform.startswith('linux') or 'bsd' in sys.platform.lower():
            # If it's Linux or BSD, get the password from the Linux password manager
            password = _LinuxPasswordManager(USE_DBUS_LINUX).get_password(os_crypt_name)
            iterations = 1
            # Generate the keys
            self.v10_key = PBKDF2(CHROMIUM_DEFAULT_PASSWORD, self.salt, self.length, iterations)
            self.v11_key = PBKDF2(password, self.salt, self.length, iterations)

            # Get the cookie file
            cookie_file = self.cookie_file or _expand_paths(linux_cookies, 'linux')

        elif sys.platform == "win32":
            # If it's Windows, get the key file
            key_file = self.key_file or _expand_paths(windows_keys, 'windows')

            if key_file:
                # If there's a key file, open it and get the key
                with open(key_file, 'rb') as f:
                    key_file_json = json.load(f)
                    key64 = key_file_json['os_crypt']['encrypted_key'].encode('utf-8')

                    # Decode Key, get rid of DPAPI prefix, unprotect data
                    keydpapi = base64.standard_b64decode(key64)[5:]
                    _, self.v10_key = _crypt_unprotect_data(keydpapi, is_key=True)

            # get cookie file from APPDATA
            cookie_file = self.cookie_file

            if not cookie_file:
                if self.browser.lower() == 'chrome' and _windows_group_policy_path():
                    cookie_file = _windows_group_policy_path()
                else:
                    cookie_file = _expand_paths(windows_cookies, 'windows')

            else:
                # if the operating system is not recognized, raise an error
                raise BrowserCookieError(
                "OS not recognized. Works on OSX, Windows, and Linux.")

            if not cookie_file:
                # if no cookie file is found, raise an error
                raise BrowserCookieError('Failed to find {} cookie'.format(self.browser))

            # create a local copy of the cookie file
            self.tmp_cookie_file = _create_local_copy(cookie_file)

    def __del__(self):
        # check if the temporary cookie file attribute exists
        if hasattr(self, 'tmp_cookie_file'):
            # if it does, remove the temporary cookie file
            os.remove(self.tmp_cookie_file)

    def __str__(self):
        # return the name of the browser when the object is converted to a string
        return self.browser

    def load(self):
        # connect to the temporary cookie file with sqlite3
        con = sqlite3.connect(self.tmp_cookie_file)
        # set the text factory to handle different text encodings
        con.text_factory = _text_factory
        # create a cursor to execute SQL commands
        cur = con.cursor()
        try:
            # try to select cookies from Chrome version <=55
            cur.execute('SELECT host_key, path, secure, expires_utc, name, value, encrypted_value, is_httponly '
                        'FROM cookies WHERE host_key like ?;', ('%{}%'.format(self.domain_name),))
        except sqlite3.OperationalError:
            # if that fails, select cookies from Chrome version >=56
            cur.execute('SELECT host_key, path, is_secure, expires_utc, name, value, encrypted_value, is_httponly '
                        'FROM cookies WHERE host_key like ?;', ('%{}%'.format(self.domain_name),))

        # create a new cookie jar
        cj = http.cookiejar.CookieJar()

        # iterate over all selected cookies
        for item in cur.fetchall():
            host, path, secure, expires_nt_time_epoch, name, value, enc_value, http_only = item
            # convert the expiration time from NT epoch to Unix epoch
            if (expires_nt_time_epoch == 0):
                expires = None
            else:
                expires = (expires_nt_time_epoch / 1000000) - self.UNIX_TO_NT_EPOCH_OFFSET

            # decrypt the cookie value
            value = self._decrypt(value, enc_value)
            # create a new cookie and add it to the jar
            c = create_cookie(host, path, secure, expires, name, value, http_only)
            cj.set_cookie(c)
        # close the sqlite3 connection
        con.close()
        # return the cookie jar
        return cj

    @staticmethod
    def _decrypt_windows_chromium(value, encrypted_value):
        # if the value is not empty, return it as is
        if len(value) != 0:
            return value

        # if the encrypted value is empty, return an empty string
        if encrypted_value == "":
            return ""

        # decrypt the encrypted value using the Windows CryptProtectData function
        _, data = _crypt_unprotect_data(encrypted_value)
        # make sure the decrypted data is bytes
        assert isinstance(data, bytes)
        # decode the bytes to a string and return it
        return data.decode()

    def _decrypt(self, value, encrypted_value):
    # method to decrypt encoded cookies

        # if the platform is Windows
        if sys.platform == 'win32':
            try:
                # try to decrypt using the Windows Chromium method
                return self._decrypt_windows_chromium(value, encrypted_value)

            # if decryption fails, handle the error
            except RuntimeError:  # Failed to decrypt the cipher text with DPAPI
                # if there's no AES key, raise an error
                if not self.v10_key:
                    raise RuntimeError(
                        'Failed to decrypt the cipher text with DPAPI and no AES key.')
                # strip off the 'v10' prefix from the encrypted value
                encrypted_value = encrypted_value[3:]
                # split the encrypted value into nonce and tag
                nonce, tag = encrypted_value[:12], encrypted_value[-16:]
                # create a new AES cipher
                aes = AES.new(self.v10_key, AES.MODE_GCM, nonce=nonce)

                # try to decrypt and verify the encrypted value
                try:
                    data = aes.decrypt_and_verify(encrypted_value[12:-16], tag)
                except ValueError:
                    # if decryption fails, raise an error
                    raise BrowserCookieError('Unable to get key for cookie decryption')
                # return the decrypted data as a string
                return data.decode()

        # if the value is not empty or the encrypted value doesn't start with 'v10' or 'v11', return the value
        if value or (encrypted_value[:3] not in [b'v11', b'v10']):
            return value

        # choose the key based on the prefix of the encrypted value
        key = self.v11_key if encrypted_value[:3] == b'v11' else self.v10_key
        # strip off the prefix from the encrypted value
        encrypted_value = encrypted_value[3:]
        # create a new AES cipher
        cipher = AES.new(key, AES.MODE_CBC, self.iv)

        # try to decrypt and unpad the encrypted value
        try:
            decrypted = unpad(cipher.decrypt(encrypted_value), AES.block_size)
        except ValueError:
            # if decryption fails, raise an error
            raise BrowserCookieError('Unable to get key for cookie decryption')
        # return the decrypted data as a string
        return decrypted.decode('utf-8')

