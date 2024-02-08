#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  vmwarevmx.py : VMwareVMX
#
#  Written 2018-2024 by Robert Federle <r.federle3@gmx.de>
#
"""
VMware VMX Crypto Module

VMware VMX configuration files are encrypted when the virtual machine is
encrypted, too. Making specific changes by hand to these files was not
possible until the user fully decrypted the virtual machine (including all
virtual disks) and, after the modification was done, re-encrypted the whole
virtual machine again. Until this little module was written, which implements
the methods to decrypt and encrypt the configuration data.

Public attributes:

    There are seven public attributes available which can be used to specify
    certain parameters for the encryption process. After a successful
    decryption, they contain the values of the current configuration. These
    attributes can be set to user-specified values or to None which means
    that a new random value should be automatically generated.

Public constants:

    HASH_ROUNDS
        The number of hash rounds for the PBKDF2-HMAC-SHA-1 hashing algorithm

    IDENTIFIER_SIZE:
        The fixed size of the unique identifier in bytes

    SALT_SIZE:
        The fixed size of the password salt in bytes

    AES_IV_SIZE:
        The fixed size of both AES IVs in bytes

    AES_KEY_SIZE:
        The fixed size of the AES-256 Key in bytes

    XTS_KEY_SIZE:
        The fixed size of the XTS-AES-256 Key in bytes
"""

__version__ = '1.0.6'

import hashlib
import hmac
import re

from base64 import b64decode, b64encode
from binascii import hexlify
try:
    from Crypto import Random
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
except ImportError:
    from Cryptodome import Random
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import pad
from functools import reduce
from urllib.parse import unquote

class VMwareVMX(object):
    """VMware VMX Crypto Module"""

    # Public constants
    HASH_ROUNDS = 10000
    IDENTIFIER_SIZE = 8
    SALT_SIZE = 16
    AES_IV_SIZE = AES.block_size
    AES_KEY_SIZE = 256 // 8  # AES-256
    XTS_KEY_SIZE = AES_KEY_SIZE * 2  # AES-256 * 2

    # Private constants
    __AES_MODE = AES.MODE_CBC
    __HASH_SIZE = 20  # sha1
    __DICT_AES_SIZE = AES_IV_SIZE + 48 + AES_KEY_SIZE + __HASH_SIZE
    __DICT_XTS_SIZE = AES_IV_SIZE + 64 + XTS_KEY_SIZE + __HASH_SIZE

    def __init__(self):
        """Initialize the public attributes

        Sets the public attributes to their default values
        """
        self.cipher = "AES-256"
        self.hash_rounds = None
        self.identifier = None
        self.salt = None
        self.dict_aes_iv = None
        self.config_aes_iv = None
        self.config_key = None

    @classmethod
    def new(cls):
        """Return a new class instance

        Returns:
            VMwareVMX: the created class instance.
        """
        return cls()

    @staticmethod
    def __check_attr(attr, length, name_s):
        """Check if an attribute has the right type and length if it's not None

        An attribute can either be None, which means a random value is created
        and assigned before encryption, or a sequence of bytes of a specific
        length.

        Args:
            attr (bytes): the attribute to be checked or None.
            length (int): the expected length in bytes.
            name_s (str): the name of the public attribute.

        Returns:
            bytes: the checked attribute (can be None)

        Raises:
            TypeError: if attribute has the wrong type.
            ValueError: if attribute has an incorrect length.
        """
        if attr is None:
            return attr
        elif isinstance(attr, bytes):
            if len(attr) == length:
                return attr
            else:
                msg = 'Attribute {} has incorrect length: {}'.format(name_s, len(attr))
                raise ValueError(msg)
        elif isinstance(attr, str):
            if length > 0 and len(attr) != length:
                msg = 'Attribute {} has incorrect length: {}'.format(name_s, len(attr))
                raise ValueError(msg)
            return attr
        else:
            msg = 'Attribute {} has wrong type'.format(name_s)
            raise TypeError(msg)

    """cipher(string):
        Contains the cipher used for encryption of the configuration.
        It is either AES-256 or XTS-AES-256. Changing its value also
        initializes the internal variables __dict_size (dictionary size)
        and __aes_key_size (AES key size).
    """
    @property
    def cipher(self):
        return self.__cipher

    @cipher.setter
    def cipher(self, value):
        self.__cipher = self.__check_attr(value, 0, 'cipher')
        if value == "AES-256":
            self.__dict_size = self.__DICT_AES_SIZE
            self.__aes_key_size = self.AES_KEY_SIZE
        elif value == "XTS-AES-256":
            self.__dict_size = self.__DICT_XTS_SIZE
            self.__aes_key_size = self.XTS_KEY_SIZE
        else:
            msg = 'Unsupported configuration encryption algorithm: ' + value
            raise ValueError(msg)

    """hash_rounds(integer):
        Contains the number of hash rounds for the PBKDF2-HMAC-SHA-1 hashing
        algorithm to prevent brute force attacks.
    """
    @property
    def hash_rounds(self):
        return self.__hash_rounds

    @hash_rounds.setter
    def hash_rounds(self, value):
        if value is not None:
            if not isinstance(value, int):
                msg = 'Attribute {} has wrong type'.format('hash_rounds')
                raise TypeError(msg)
            if value <= 0:
                msg = 'Password hash rounds must be a positive non-zero value'
                raise ValueError(msg)
        self.__hash_rounds = value

    """identifier(bytes):
        Contains the unique identifier after a successful decryption.
        This identifier must be 8 bytes long and is just a random number.

        If the value is None, the identifier will be created with random
        data on encryption. If the size isn't right, an exception of type
        ValueError will be the result. If it's not of type bytes, an
        exception of type TypeError will be the result.
    """
    @property
    def identifier(self):
        return self.__identifier

    @identifier.setter
    def identifier(self, value):
        self.__identifier = self.__check_attr(value, self.IDENTIFIER_SIZE, 'identifier')

    """salt(bytes):
        Contains the password salt after a successful decryption.
        The salt parameter is used with the password for the PBKDF2-HMAC-SHA-1
        hashing algorithm to prevent brute force attacks. The result of the
        hashing algorithm is a 32 bytes AES-256 key to decrypt the so-called
        dictionary.

        If the value is None, the password salt will be created with random
        data on encryption. If the size isn't right, an exception of type
        ValueError will be the result. If it's not of type bytes, an
        exception of type TypeError will be the result.
    """
    @property
    def salt(self):
        return self.__salt

    @salt.setter
    def salt(self, value):
        self.__salt = self.__check_attr(value, self.SALT_SIZE, 'salt')

    """dict_aes_iv(bytes):
        Contains the first AES IV after a successful decryption.
        These 16 random bytes are used as the Initialization Vector to decrypt
        the dictionary which contains the second AES Key, which is then used
        to decrypt the configuration itself.

        If the value is None, the first AES IV will be created with random
        data on encryption. If the size of the value isn't right, an exception
        of type ValueError will be the result. If it's not of type bytes, an
        exception of type TypeError will be the result.
    """
    @property
    def dict_aes_iv(self):
        return self.__dict_aes_iv

    @dict_aes_iv.setter
    def dict_aes_iv(self, value):
        self.__dict_aes_iv = self.__check_attr(value, self.AES_IV_SIZE, 'dict_aes_iv')

    """config_aes_iv(bytes):
        Contains the second AES IV after a successful decryption.
        These 16 random bytes are used as the Initialization Vector to
        decrypt the configuration with the second AES Key which is retrieved
        from the dictionary.

        If the value is None, the second AES IV will be created with random
        data on encryption. If the size of the value isn't right, an exception
        of type ValueError will be the result. If it's not of type bytes, an
        exception of type TypeError will be the result.
    """
    @property
    def config_aes_iv(self):
        return self.__config_aes_iv

    @config_aes_iv.setter
    def config_aes_iv(self, value):
        self.__config_aes_iv = self.__check_attr(value, self.AES_IV_SIZE, 'config_aes_iv')

    """config_key(bytes):
        Contains the second AES Key after a successful decryption.
        This is either a 32 bytes (cipher AES-256) or 64 bytes key (cipher
        XTS-AES-256). The first 32 bytes (256 bits) are used as an AES-256 key
        to decrypt the configuration together with the second AES IV. If the
        cipher is XTS-AES-256, the second 32 bytes are used for the HMAC
        algorithm.

        If the value is None, the second AES Key will be created with random
        data on encryption. If the size of the value isn't right, an exception
        of type ValueError will be the result. If it's not of type bytes, an
        exception of type TypeError will be the result.
    """
    @property
    def config_key(self):
        return self.__config_key

    @config_key.setter
    def config_key(self, value):
        self.__config_key = self.__check_attr(value, self.__aes_key_size, 'config_key')


    #--------------------------------------------------------------------------

    def reinit(self):
        """Reinitializes the public attributes

        Returns:
            VMwareVMX: current class instance.
        """
        self.__init__()
        return self

    def copy(self, source):
        """Copies the public attributes from another instance

        Copies the public attributes from another instance (source) to the
        current instance.

        Args:
            source (VMwareVMX): class instance where attributes are copied from

        Returns:
            VMwareVMX: current class instance.
        """
        self.hash_rounds = source.hash_rounds
        self.identifier = source.identifier
        self.salt = source.salt
        self.cipher = source.cipher
        self.dict_aes_iv = source.dict_aes_iv
        self.config_aes_iv = source.config_aes_iv
        self.config_key = source.config_key
        return self

    #--------------------------------------------------------------------------

    def decrypt(self, password_s, keysafe_s, data_s, encoding_s = "utf-8", ignore_errors = False):
        """Decrypts the dictionary and the configuration section

        Decrypts the configuration in data_s with information retrieved from
        the decrypted dictionary in keysafe_s. If the dictionary can't be
        decrypted, most likely the given password is invalid.

        Args:
            password_s (str): the password to decrypt the configuration.
            keysafe_s (str): part one of the configuration; contains the
                so-called dictionary which contains the key to decrypt the
                configuration.
            data_s (str): part two of the configuration; contains the
                encrypted configuration data.
            encoding_s (str): encoding to be used for the configuration;
                default is UTF-8

        Returns:
            str: either the decrypted configuration or None if the given
                password is invalid. Also sets the public attributes with
                the parameters used if the decryption was successful.

        Raises:
            ValueError: when the dictionary or configuration has invalid
                values and can't be decoded.
        """
        BASE64_RE  = '([a-zA-Z0-9\+/=]+)'
        CIPHER_RE  = '([A-Z0-9\-]+)'
        HASH_RE    = '([A-Z0-9\-]+)'
        QUOTED_RE  = '([a-zA-Z0-9\+/%]+)'
        ROUNDS_RE  = '([0-9]+)'
        TYPE_RE    = '([a-z]+)'

        DATA_RE    = '.*\"' + BASE64_RE + '\"'
        DATA2_RE   = '.*\"' + BASE64_RE
        DICT_RE    = 'type=' + TYPE_RE \
                   + ':cipher=' + CIPHER_RE \
                   + ':key=' + QUOTED_RE
        KEYSAFE_RE = '.+phrase/' + BASE64_RE \
                   + '/pass2key=' + HASH_RE \
                   + ':cipher=' + CIPHER_RE \
                   + ':rounds=' + ROUNDS_RE \
                   + ':salt=' + QUOTED_RE \
                   + ',' + HASH_RE \
                   + ',' + BASE64_RE + '\)'

        def decode_base64(string):
            """Decode a BASE64 string

            Args:
                string (str): the BASE64 string to be decoded

            Returns:
                bytes: the decoded string or None if the string is invalid.
            """
            try:
                return bytes(b64decode(string))
            except (TypeError, ValueError):
                return None

        # Unquote, analyze and split encryption.keySafe line
        keysafe_s = unquote(keysafe_s)
        match = re.match(KEYSAFE_RE, keysafe_s)
        if not match:
            msg = 'Unsupported format of the encryption.keySafe line:\n' + keysafe_s
            raise ValueError(msg)

        # Get and decode the identifier
        identifier_s = match.group(1)
        self.identifier = decode_base64(identifier_s)
        if self.identifier is None:
            msg = 'Invalid identifier: ' + identifier_s
            raise ValueError(msg)

        # Only the PBKDF2-HMAC-SHA-1 hash algorithm is supported for the password
        password_hash_s = match.group(2)
        if password_hash_s != 'PBKDF2-HMAC-SHA-1':
            msg = 'Unsupported password hash algorithm: ' + password_hash_s
            raise ValueError(msg)

        # Get the encryption algorithm for the dictionary
        dict_cipher_s = match.group(3)

        # Store the encryption algorithm. This automatically checks for supported algorithms
        # and initializes the internal variables __dict_size and __aes_key_size accordingly.
        self.cipher = dict_cipher_s

        # Get and check the number of hash rounds for validity
        self.hash_rounds = int(match.group(4))

        # Get, unquote and decode the password salt
        salt_s = unquote(match.group(5))
        self.salt = decode_base64(salt_s)
        if self.salt is None:
            msg = 'Password salt is not a valid BASE64 string: ' + salt_s
            raise ValueError(msg)

        # Only the HMAC-SHA-1 hash algorithm is supported for the configuration
        config_hash_s = match.group(6)
        if config_hash_s != 'HMAC-SHA-1':
            msg = 'Unsupported configuration hash algorithm: ' + config_hash_s
            raise ValueError(msg)

        # Get and decode the dictionary
        dict_s = match.group(7)
        dict_enc = decode_base64(dict_s)
        if dict_enc is None:
            msg = 'Dictionary is not a valid BASE64 string:\n' + dict_s
            raise ValueError(msg)

        # The dictionary must have the right size else something is wrong
        if len(dict_enc) != self.__dict_size:
            msg = 'Dictionary has incorrect length: {}'.format(len(dict_enc))
            raise ValueError(msg)

        # Create the dictionary AES Key with PBKDF2-HMAC-SHA-1
        dict_key = hashlib.pbkdf2_hmac('sha1', password_s.encode(), self.salt,
                                       self.hash_rounds, self.__aes_key_size)

        # Check if the result is an AES-256 key
        if len(dict_key) != self.__aes_key_size:
            msg = 'Dictionary AES key has incorrect length: {}'.format(len(dict_key))
            raise ValueError(msg)

        # Get the AES IV and decrypt the dictionary (skip AES IV and hash)
        # Layout of dict_enc: AES IV | Encrypted Dictionary | HASH
        self.dict_aes_iv = dict_enc[:self.AES_IV_SIZE]
        cipher = AES.new(dict_key[:self.AES_KEY_SIZE], self.__AES_MODE, self.dict_aes_iv)
        dict_dec = cipher.decrypt(dict_enc[self.AES_IV_SIZE : -(self.__HASH_SIZE)])
        del cipher

        # check if the decrypted dictionary is in ASCII
        try:
            dict_dec.decode('ascii')
        except UnicodeDecodeError:
            return None
    
        # Get the last byte which contains the padding size
        # Layout of dict_dec: Decrypted Dictionary | Padding Bytes | Padding Size (1 byte)
        padding_size = dict_dec[-1]

        # Check the padding size
        if padding_size < 1 or padding_size > 16:
            msg = 'Illegal dictionary padding value found: {}'.format(padding_size)
            raise ValueError(msg)

        # Remove all padding bytes (between 1 and 16)
        dict_dec = dict_dec[:-padding_size]

        # Get the dictionary hash which is stored at the end
        dict_hash = dict_enc[-(self.__HASH_SIZE):]

        # Calculate the hash value of the dictionary
        dict_hash2 = hmac.HMAC(dict_key, dict_dec, digestmod=hashlib.sha1).digest()

        # If dictionary hash values don't match, the password is invalid
        if dict_hash != dict_hash2:
            return None

        # Analyze and split dictionary
        match = re.match(DICT_RE, dict_dec.decode())
        if not match:
            msg = 'Dictionary has the wrong format: ' + dict_dec.decode()
            raise ValueError(msg)

        # Currently only one type for the dictionary is supported
        dict_type_s = match.group(1)
        if dict_type_s != 'key':
            msg = 'Unsupported dictionary type: ' + dict_type_s
            raise ValueError(msg)

        # Currently only one encryption algorithm for the configuration
        # is supported
        config_cipher_s = match.group(2)
        if config_cipher_s not in ('AES-256', 'XTS-AES-256'):
            msg = 'Unsupported configuration encryption algorithm: ' + config_cipher_s
            raise ValueError(msg)

        # Get quoted configuration AES key, unquote and decode it
        config_key_s = unquote(match.group(3))
        self.config_key = decode_base64(config_key_s)
        if self.config_key is None:
            msg = 'Configuration AES key is not a valid BASE64 string:\n' + config_key_s
            raise ValueError(msg)

        # Unquote, analyze and split the encryption.data line
        data_s = unquote(data_s)
        match = re.match(DATA_RE, data_s)
        if not match:
            if ignore_errors:
                match = re.match(DATA2_RE, data_s)
                if not match:
                    msg = 'Unsupported format of the encryption.data line'
                    raise ValueError(msg)
            else:
                msg = 'Unsupported format of the encryption.data line'
                raise ValueError(msg)

        # Get the encoded configuration and decode it
        config_s = match.group(1)
        config_enc = decode_base64(config_s)
        # Sucessfully decoded?
        if config_enc is None:
            if ignore_errors:
                # Shrink the string to find a valid BASE64 encoded string
                while len(config_s) > 0:
                    # Remove the last character
                    config_s = config_s[:-1]
                    config_enc = decode_base64(config_s)
                    # Sucessfully decoded?
                    if config_enc is not None:
                        break
            else:
                msg = 'Configuration is not a valid BASE64 string:\n' + config_s
                raise ValueError(msg)

        # The length of the encrypted configuration must be a multiple of the
        # AES Block Size (16 bytes) or something is wrong
        if ((len(config_enc) - self.__HASH_SIZE) % AES.block_size) != 0:
            if ignore_errors:
                # The new length will be a multiple of the AES Block Size plus hash
                newlen = len(config_enc) - self.__HASH_SIZE
                newlen = newlen - (newlen % AES.block_size) + self.__HASH_SIZE
                # Shrink the encoded data to the new length
                config_enc = config_enc[:newlen]
            else:
                msg = 'Configuration has incorrect length: {}'.format(len(config_enc))
                raise ValueError(msg)

        # Get the AES IV and decrypt the configuration (skip AES IV and hash)
        # Layout of config_enc: AES IV | Encrypted Data | HASH
        self.config_aes_iv = config_enc[:self.AES_IV_SIZE]
        cipher = AES.new(self.config_key[:self.AES_KEY_SIZE], self.__AES_MODE, self.config_aes_iv)
        config_dec = cipher.decrypt(config_enc[self.AES_IV_SIZE : -(self.__HASH_SIZE)])
        del cipher

        # Get the last byte which contains the padding size
        # Layout of config_dec: Decrypted Data | Padding Bytes | Padding Size (1 byte)
        padding_size = config_dec[-1]

        # Check the padding size
        if (padding_size < 1 or padding_size > 16) and not ignore_errors:
            msg = 'Illegal config padding size found: {}'.format(padding_size)
            raise ValueError(msg)

        if not ignore_errors:
            # Remove all padding bytes (between 1 and 16)
            config_dec = config_dec[:-padding_size]

            # Get the configuration hash which is stored at the end
            config_hash = config_enc[-(self.__HASH_SIZE):]

            # Calculate the hash value of the configuration
            config_hash2 = hmac.HMAC(self.config_key, config_dec, digestmod=hashlib.sha1).digest()

            # Abort if configuration hash values don't match
            if config_hash != config_hash2:
                msg = 'Config hash mismatch:\n{}\n{}' \
                      .format(hexlify(config_hash).decode(),
                              hexlify(config_hash2).decode())
                raise ValueError(msg)

        # Decryption was successful; return configuration
        return config_dec.decode(encoding=encoding_s)

    #--------------------------------------------------------------------------

    def encrypt(self, password_s, config_s, hash_rounds = None):
        """Encrypts the configuration and returns it as two strings

        If any of the public attributes is None, a random value is created.
        Otherwise the attribute is used for encryption.

        Args:
            password_s (str): the password to encrypt the configuration.
            config_s (str): the configuration to be encrypted.
            hash_rounds (int): the number of hash rounds for the encryption key

        Returns:
            str: the encrypted dictionary (keySafe) as parameter 1.
            str: the encrypted configuration (data) as parameter 2.

        Raises:
            TypeError: if one of the public attributes has the wrong type.
            ValueError: if one of the public attributes or the dictionary
                AES key has an incorrect length.
        """

        def encode_base64(bytes):
            """Encode bytes with BASE64

            Args:
                bytes (bytes): the data to be encoded.

            Returns:
                str: the encoded string.
            """
            return b64encode(bytes).decode()

        def quote_string(string_s):
            """Return a quoted string

            This function replaces 5 special characters with their quoted
            version.

            Args:
                string_s (str): string to be quoted.

            Returns:
                str: the quoted string.
            """
            repls = [('/', '%2f'), ('+', '%2b'), ('-', '%2d'),
                     (':', '%3a'), ('=', '%3d')]
            return reduce(lambda a, kv: a.replace(*kv), repls, string_s)

        # Use the argument if specified. Otherwise use the previous value
        # and if that one is undefined, too, use the default value.
        if hash_rounds is None:
            hash_rounds = self.hash_rounds
            if hash_rounds is None:
                hash_rounds = self.HASH_ROUNDS

        # Update the number of hash rounds
        self.hash_rounds = hash_rounds

        # Create the configuration AES key if not already set
        if self.config_key is None:
            self.config_key = Random.new().read(self.__aes_key_size)

        # Calculate the configuration hash
        config_hash = hmac.HMAC(self.config_key, config_s.encode(), digestmod=hashlib.sha1).digest()

        # Add padding bytes to the configuration (must be multiple of 16 bytes for AES)
        config_dec = pad(config_s.encode(), AES.block_size)

        # Create the AES Initialization Vector if not already set
        if self.config_aes_iv is None:
            self.config_aes_iv = Random.new().read(self.AES_IV_SIZE)

        # Encrypt the configuration and add AES IV and hash
        cipher = AES.new(self.config_key[:self.AES_KEY_SIZE], self.__AES_MODE, self.config_aes_iv)
        config_enc = self.config_aes_iv + cipher.encrypt(config_dec) + config_hash
        del cipher

        # Encode the configuration
        config_s = encode_base64(config_enc)

        # Encode and quote the configuration AES key
        config_key_s = encode_base64(self.config_key).replace('=','%3d')

        # Build the dictionary string
        dict_dec = 'type=key:cipher={}:key={}'.format(self.cipher, config_key_s)

        # Create the password salt if not already set
        if self.salt is None:
            self.salt = Random.new().read(self.SALT_SIZE)

        # Encode and quote the password salt
        salt_s = quote_string(encode_base64(self.salt)).replace('%3d','%253d')

        # Create the dictionary AES Key with PBKDF2-HMAC-SHA-1
        dict_key = hashlib.pbkdf2_hmac('sha1', password_s.encode(), self.salt,
                                       self.hash_rounds, self.__aes_key_size)

        # Check if the result is an AES-256 key
        if len(dict_key) != self.__aes_key_size:
            msg = 'Dictionary AES key has incorrect length: {}'.format(len(dict_key))
            raise ValueError(msg)

        # Calculate the dictionary hash
        dict_hash = hmac.HMAC(dict_key, dict_dec.encode(), digestmod=hashlib.sha1).digest()

        # Add padding bytes to the dictionary (must be multiple of 16 bytes for AES)
        dict_dec = pad(dict_dec.encode(), AES.block_size)

        # Create the AES Initialization Vector if not already set
        if self.dict_aes_iv is None:
            self.dict_aes_iv = Random.new().read(self.AES_IV_SIZE)

        # Encrypt the dictionary and add AES IV and hash
        cipher = AES.new(dict_key[:self.AES_KEY_SIZE], self.__AES_MODE, self.dict_aes_iv)
        dict_enc = self.dict_aes_iv + cipher.encrypt(dict_dec) + dict_hash
        del cipher

        # Encode the configuration
        dict_s = encode_base64(dict_enc)

        # Create the identifier if not already set
        if self.identifier is None:
            self.identifier = Random.new().read(self.IDENTIFIER_SIZE)

        # Encode and quote the identifier
        identifier_s = quote_string(encode_base64(self.identifier))

        # Build the dictionary string
        dict_s = 'pass2key={}:cipher={}:rounds={}:salt={},{},{}' \
                 .format('PBKDF2-HMAC-SHA-1', self.cipher, self.hash_rounds,
                         salt_s, 'HMAC-SHA-1', dict_s)

        # Quote the dictionary string
        dict_s = quote_string(dict_s)

        # Build the keysafe and data strings
        keysafe_s = 'encryption.keySafe = ' \
                    '"vmware:key/list/(pair/(phrase/{}/{}))"' \
                    .format(identifier_s, dict_s)
        data_s = 'encryption.data = "{}"'.format(config_s)

        # Return them
        return keysafe_s, data_s

# vim:set ts=4 sw=4 sts=4 expandtab: