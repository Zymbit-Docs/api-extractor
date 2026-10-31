# -*- coding: utf-8 -*-
# Copyright (c) 2016-2025 Zymbit, Inc.
# Copyright (c) 2026 Zymbit Technologies, Inc.

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# .. codeauthor:: Zymbit Technologies, Inc. <maintainers@zymbit.com>
# .. date:: 2026-09-30

"""Python interface module to Zymkey Application Utilities Library.

This file contains a Python class which interfaces to the the Zymkey
Application Utilities library. Systems intending to run such applications
require that the ``python3-zku`` package be installed.

This class facilitates writing userspace applications which use Zymkey to
perform cryptographic operations, such as:

1. Signing of payloads using ECDSA
2. Verification of payloads that were signed using Zymkey
3. Exporting the public key that matches Zymkey's private key
4. "Locking" and "unlocking" data objects
5. Generating random data

Additionally, there are methods for changing the i2c address (i2c units
only), setting tap sensitivity, and controlling the LED.
"""

import errno
import hashlib
import os
import sys
import typing as t
from ctypes import *

from .exceptions import (VerificationError, ZymkeyLibraryError,
                         ZymkeyTimeoutError)
from .settings import ZYMKEY_LIBRARY_PATH
from .utils import is_string
from .zka import zkalib

__all__ = [
    "Zymkey",
    "client",
    "RecoveryStrategy",
    "RecoveryStrategyBIP39",
    "RecoveryStrategySLIP39",
]

CLOUD_ENCRYPTION_KEY: str = "cloud"
"""The constant used to refer to the cloud encryption key."""

ZYMKEY_ENCRYPTION_KEY: str = "zymkey"
"""The constant used to refer to the zymkey encryption key."""

ENCRYPTION_KEYS: t.Tuple[str, ...] = (CLOUD_ENCRYPTION_KEY, ZYMKEY_ENCRYPTION_KEY)
"""A tuple containing the various encryption key constants."""

keyTypes: t.Mapping[str, int] = {
    "secp256r1": 0,
    "nistp256": 0,
    "secp256k1": 1,
    "ed25519": 2,
    "x25519": 3,
}
"""A dict containing the available key types."""

kdfFuncTypes: t.Mapping[str, int] = {
    "none": 0,
    "rfc5869-sha256": 1,
    "rfc5869-sha512": 2,
    "pbkdf2-sha256": 3,
    "pbkdf2-sha512": 4,
}
"""A dict containing the available KDF function types."""


class RecoveryStrategy:
    """The RecoveryStrategy class definition.

    This class specifies the recovery strategy used for wallet generation within Python.
    Base class strategy is to do no recovery.
    """

    def __init__(self, variant = ""):
        """Initialize an instance of RecoveryStrategy.

        Parameters
        ----------
        variant
            Variant of the key type. Currently only "cardano" for ed25519 is supported.
        """
        self.recovery_strategy = ""
        self.variant = variant
        self.passphrase = ""


class RecoveryStrategyBIP39(RecoveryStrategy):
    """The RecoveryStrategyBIP39 class definition.

    This class specifies the BIP39 recovery strategy used for wallet generation within Python.
    Derived from RecoveryStrategy class.
    """

    def __init__(self, variant = "", passphrase = ""):
        """Initialize an instance of RecoveryStrategyBIP39.

        Parameters
        ----------
        variant
            Variant of the key type. Currently only "cardano" for ed25519 is supported.
        passphrase
            Passphrase used for BIP39 generation. Can be empty string. Must be b64 encoded.
        """
        self.passphrase = passphrase
        self.recovery_strategy = "BIP39"
        self.variant = variant

class RecoveryStrategySLIP39(RecoveryStrategy):
    """The RecoveryStrategySLIP39 class definition.

    This class specifies the SLIP39 recovery strategy used for wallet generation within Python.
    Derived from RecoveryStrategy class.
    """

    def __init__(self, group_count, group_threshold, iteration_exponent, variant = "", passphrase = ""):
        """Initialize an instance of RecoveryStrategySLIP39.

        Parameters
        ----------
        group_count
            Total number of group shares to generate [Max: 14 Groups].
        group_threshold
            Number of groups needed to restore a master seed with [threshold <= group_count].
        iteration_exponent
            The higher the exponent the more PBKDF2 hashing is done. [Exponent: 0-5]
        variant
            Variant of the key type. Currently only "cardano" for ed25519 is supported.
        passphrase
            Passphrase used for BIP39 generation. Can be empty string. Must be b64 encoded.
        """
        self.passphrase = passphrase
        self.recovery_strategy = "SLIP39"
        self.variant = variant
        self.group_count = group_count
        self.group_threshold = group_threshold
        self.iteration_exponent = iteration_exponent

class DigestObject():

    def __init__(self, src, encoding = "utf-8", digest = None):
        self.src = src
        self.encoding = encoding
        self.hashlib = digest
        self.str = None

        if (isinstance(src, str)):
            self.str = src
        elif (isinstance(src, bytes)):
            self.str = src.decode(encoding)
        elif (isinstance(src, bytearray)):
            self.str = src.decode(encoding)

        if(self.hashlib is None):
            self.hashlib = hashlib.sha256()
        self.hashlib.update(self.str.encode(encoding))

    def digest(self, update_hash = False):
        if(update_hash):
            self.hashlib.update(self.str.encode(self.encoding))
        digest_str = self.hashlib.digest()
        return digest_str

class Zymkey(object):
    """The Zymkey class definition.

    This class provides access to the Zymkey within Python.
    """

    EPHEMERAL_KEY_SLOT = -1

    ## @name Zymkey Context
    ###@{

    def __init__(self):
        """Initialize an instance of a Zymkey context."""
        self._zk_ctx = c_void_p()
        ret = self._zkOpen(byref(self._zk_ctx))

        # To be able to import this module and class for parsing of inline
        # documentation by Sphinx autodoc, the import of the zkalib must be
        # mocked by Sphinx. Because the comparison will fail when the mocked
        # value of `ret` is compared with an integer, check for a TypeError and
        # pass on that exception.
        #
        # To be extra safe, it also checks the exception
        # text to ensure that the exception is a result of a mocked value
        # being compared.
        try:
            if ret < 0:
                raise AssertionError("bad return code {!r}".format(ret))
        except TypeError as e:
            if "instances of 'zkOpen' and 'int'" not in sys.exc_info()[1].args[0]:
                raise e
            pass

    ## @brief The class destructor closes a Zymkey context
    def __del__(self):
        if self._zk_ctx.value is not None:
            ret = self._zkClose(self._zk_ctx)

            # See the explanation for the `try` block above in `__init__()`. This
            # try block exists for the same reason.
            try:
                if ret < 0:
                    raise AssertionError("bad return code %d" % ret)
            except TypeError as e:
                if "instances of 'zkClose' and 'int'" not in sys.exc_info()[1].args[0]:
                    raise e
                pass

            self._zk_ctx.value = None

    ###@}

    ## @name LED Control
    ###@{

    def led_on(self) -> None:
        """Turn the LED on.

        Raises
        ------
        AssertionError
            If `ret` is a bad return code from the Zymkey library function.
        """
        ret = self._zkLEDOn(self._zk_ctx)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def led_off(self) -> None:
        """Turn the LED off.

        Raises
        ------
        AssertionError
            If `ret` is a bad return code from the Zymkey library function.
        """
        ret = self._zkLEDOff(self._zk_ctx)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def led_flash(self, on_ms: int, off_ms: int = 0, num_flashes: int = 0) -> None:
        """Flash the LED.

        Parameters
        ----------
        on_ms
            The amount of time in milliseconds that the LED will be on for.
        off_ms
            The amount of time in milliseconds that the LED will be off for. If
            this parameter is set to 0 (default), the off time is the same as
            the on time.
        num_flashes
            The number of on/off cycles to execute. If this parameter is set
            to 0 (default), the LED flashes indefinitely.

        Raises
        ------
        AssertionError
            If `ret` is a bad return code from the Zymkey library function.
        """
        if off_ms == 0:
            off_ms = on_ms
        ret = self._zkLEDFlash(self._zk_ctx, on_ms, off_ms, num_flashes)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    ###@}

    ## @name Random Number Generation
    ###@{

    def get_random(self, num_bytes: int) -> bytearray:
        """Get some random bytes.

        Parameters
        ----------
        num_bytes
            The number of random bytes to get.


        Returns
        -------
        bytearray
            An array of bytes returned by the random number generator.

        Raises
        ------
        AssertionError
            If `ret` is a bad return code from the Zymkey library function.
        """
        rdata = c_void_p()
        ret = self._zkGetRandBytes(self._zk_ctx, byref(rdata), num_bytes)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)
        rc = (c_ubyte * num_bytes).from_address(rdata.value)
        rd_array = bytearray(rc)
        return rd_array

    def create_random_file(self, file_path: str, num_bytes: int) -> None:
        """Deposit random data in a file.

        Parameters
        ----------
        file_path
            The absolute path name for the destination file.
        num_bytes
            The number of random bytes to get.

        Raises
        ------
        AssertionError
            If `ret` is a bad return code from the Zymkey library function.
        """
        ret = self._zkCreateRandDataFile(
            self._zk_ctx, file_path.encode("utf-8"), num_bytes
        )
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def lock(
        self,
        src: t.Union[str, bytes],
        dst: t.Optional[str] = None,
        encryption_key: str = ZYMKEY_ENCRYPTION_KEY,
    ) -> t.Union[None, bytearray]:
        """Lock up source (plaintext) data.

        This methods encrypts and signs a block of data.

        The Zymkey that can be used for locking/unlocking operations

        1. The one-way key is meant to lock up data only on the local host
           computer. Data encrypted using this key cannot be exported and
           deciphered anywhere else.

        Parameters
        ----------
        src
            The source (plaintext) data to lock.

            If a `str` is passed to this method, the value is assumed to be
            the absolute path to the location of the source file. If `bytes`
            or `bytesarray` is passed, it is assumed to contain binary data.
        dst
            The destination (ciphertext) of the locked data.

            If a `str` is passed to this method, the value is assumed to be
            the absolute path to the location of the file where the destination
            data is meant to be written. Otherwise, if `None` is passed to the
            method (the default), the locked data is returned from the method
            as a bytearray.
        encryption_key
            This specifies which key will be used to lock the data. A value of
            'zymbit' (default) specifies that the Zymkey will use the one-way
            key.

        Returns
        -------
        bytearray or None
            The locked data is returned as a bytearray if no destination is
            specified when this method is called. Otherwise, `None` is returned.

        Raises
        ------
        AssertionError
            If `ret` is a bad return code from the Zymkey library function.
        """
        assert encryption_key in ENCRYPTION_KEYS
        use_shared_key = encryption_key == CLOUD_ENCRYPTION_KEY

        dst_path: t.Optional[bytes] = None
        dst_data: t.Optional[t.Union[c_void_p, int]] = None
        if isinstance(dst, str):
            dst_path = dst.encode("utf-8")
        else:
            dst_data = c_void_p()
            dst_data_sz = c_int()

        # If the `src` is a file path
        if isinstance(src, str):
            src = src.encode("utf-8")

            # If the `src` is a file path and `dst` is a file path
            if dst_path:

                ret = self._zkLockDataF2F(self._zk_ctx, src, dst_path, use_shared_key)
                if ret < 0:
                    raise AssertionError("bad return code %d" % ret)

                return None

            # If the `src` is a file path and `dst` is not a file path
            else:
                dst_data = c_void_p()
                dst_data_sz = c_int()

                ret = self._zkLockDataF2B(
                    self._zk_ctx,
                    src,
                    byref(dst_data),
                    byref(dst_data_sz),
                    use_shared_key,
                )
                if ret < 0:
                    raise AssertionError("bad return code %d" % ret)
                dc = (c_ubyte * dst_data_sz.value).from_address(dst_data.value)  # type: ignore
                data_array = bytearray(dc)
                return data_array

        # If the `src` is not a file path
        else:
            src_sz = len(src)
            src_c_ubyte = (c_ubyte * src_sz)(*src)

            # If the `src` is not a file path and `dst` is a file path
            if dst_path:

                ret = self._zkLockDataB2F(
                    self._zk_ctx, byref(src_c_ubyte), len(src), dst_path, use_shared_key
                )
                if ret < 0:
                    raise AssertionError("bad return code %d" % ret)

                return None

            # If the `src` is not a file path and `dst` is not a file path
            else:
                dst_data = c_void_p()
                dst_data_sz = c_int()

                ret = self._zkLockDataB2B(
                    self._zk_ctx,
                    byref(src_c_ubyte),
                    len(src),
                    byref(dst_data),
                    byref(dst_data_sz),
                    use_shared_key,
                )
                if ret < 0:
                    raise AssertionError("bad return code %d" % ret)
                dc = (c_ubyte * dst_data_sz.value).from_address(dst_data.value)  # type: ignore
                data_array = bytearray(dc)
                return data_array

    ###@}

    ## @name Unlock Data
    ###@{

    def unlock(
        self,
        src: t.Union[str, bytes],
        dst: t.Optional[str] = None,
        encryption_key: str = ZYMKEY_ENCRYPTION_KEY,
        raise_exception: bool = True,
    ) -> t.Union[None, bytearray, t.NoReturn]:
        """Unlock source (ciphertext) data.

        This method verifies a locked object signature and decrypts the
        associated ciphertext data.

        The Zymkey has two keys that can be used for locking/unlocking operations

        1. The one-way key is meant to lock up data only on the local host
           computer. Data encrypted using this key cannot be exported and
           deciphered anywhere else.

        Parameters
        ----------
        src
            The source (ciphertext) data to verify and decrypt.

            If a `str` is passed to this method, the value is assumed to be
            the absolute path to the location of the source file. If `bytes`
            or `bytesarray` is passed, it is assumed to contain binary data.
        dst
            The destination of the decrypted data (plaintext).

            If a `str` is passed to this method, the value is assumed to be
            the absolute path to the location of the file where the destination
            data is meant to be written. Otherwise, if `None` is passed to the
            method (the default), the locked data is returned from the method
            as a bytearray.
        encryption_key
            This specifies which key will be used to lock the data. A value of
            'zymbit' (default) specifies that the Zymkey will use the one-way
            key.
        raise_exception
            Specifies if an exception should be raised if the signature verification
            of the locked object fails.

        Returns
        -------
        bytearray or None
            The locked data is returned as a bytearray if no destination is
            specified when this method is called. Otherwise, `None` is returned.

        Raises
        ------
        AssertionError
            If `ret` is a bad return code from the Zymkey library function.
        """
        # Determine if source and destination are strings. If so, they must be
        # filenames
        src_is_file = is_string(src)
        dst_is_file = is_string(dst)

        assert encryption_key in ENCRYPTION_KEYS
        use_shared_key = encryption_key == CLOUD_ENCRYPTION_KEY

        # Prepare src if it is not specifying a filename
        if not src_is_file:
            src_sz = len(src)
            src_c_ubyte = (c_ubyte * src_sz)(*src)
        else:
            src = src.encode("utf-8")
        # Prepare dst if it is not specifying a filename
        if not dst_is_file:
            dst_data = c_void_p()
            dst_data_sz = c_int()
        else:
            dst = dst.encode("utf-8")
        if src_is_file and dst_is_file:
            ret = self._zkUnlockDataF2F(self._zk_ctx, src, dst, use_shared_key)
            if ret < 0:
                raise AssertionError("bad return code %d" % ret)

        if not src_is_file and dst_is_file:
            ret = self._zkUnlockDataB2F(
                self._zk_ctx, byref(src_c_ubyte), len(src), dst, use_shared_key
            )
            if ret < 0:
                raise AssertionError("bad return code %d" % ret)

        if src_is_file and not dst_is_file:
            ret = self._zkUnlockDataF2B(
                self._zk_ctx, src, byref(dst_data), byref(dst_data_sz), use_shared_key
            )
            if ret < 0:
                raise AssertionError("bad return code %d" % ret)
            dc = (c_ubyte * dst_data_sz.value).from_address(dst_data.value)
            data_array = bytearray(dc)
            return data_array

        if not src_is_file and not dst_is_file:
            ret = self._zkUnlockDataB2B(
                self._zk_ctx,
                byref(src_c_ubyte),
                len(src),
                byref(dst_data),
                byref(dst_data_sz),
                use_shared_key,
            )
            if ret < 0:
                raise AssertionError("bad return code %d" % ret)
            if ret == 0:
                if raise_exception:
                    raise VerificationError()
                return None
            if ret == 1:
                dc = (c_ubyte * dst_data_sz.value).from_address(dst_data.value)
                data_array = bytearray(dc)
                return data_array

        return None

    ###@}

    ## @name ECDSA
    ###@{

    def sign(self, src: t.Union[str, bytes, bytearray], slot: int = 0, return_recid: bool = False,
    encoding: str = "utf-8", digest: t.Any = None) -> bytearray:
        """Generate a signature using the Zymkey's ECDSA private key.

        Parameters
        ----------
        src
            The SHA256 digest of the data that will be used to generate the signature.
        slot
            The key slot used for signing. [ZYMKEY5, HSM60, HSM64, HSM6] Slot can't contain a X25519 key pair
        return_recid : bool
            This parameter asks for the y parity to be returned.
        encoding : str
            This parameter asks for the encoding for the string source.
        digest : _hashlib.HASH
            This parameter asks for the type of hash. Can be None. Defaults to sha256.

        Returns
        -------
        bytearray
            A bytearray of the signature.
        int
            If return_recid = True, then return the y parity of the signature (either a 1 or 0).

        Todo
        ----
        Allow for overloading of source parameter in similar fashion to lock/unlock.
        """

        if (digest is None):
            digest = hashlib.sha256()

        digest_obj = DigestObject(src, encoding, digest)

        return self.sign_digest(digest_obj, slot=slot, return_recid=return_recid)

    def sign_digest(
        self, digest: t.Any, slot: int = 0, return_recid: bool = False
    ) -> bytearray:
        """Generate a signature using the Zymkey's ECDSA private key.

        Parameters
        ----------
        digest : _hashlib.HASH
            A encoded str instance representing the digest to be signed.
        slot : int
            This parameter specifies the key slot used for signing. [ZYMKEY5, HSM60, HSM64, HSM6] Slot can't contain a X25519 key pair
        return_recid : bool
            This parameter asks for the y parity to be returned.

        Returns
        -------
        bytearray
            The signature of the SHA-256 digest passed to this method.
        int
            If return_recid = True, then return the y parity of the signature (either a 1 or 0).

        Raises
        ------
        AssertionError
            If `ret` is a bad return code from the Zymkey library function.

        Todo
        ----
        Allow for overloading of source parameter in similar fashion to lock/unlockData.
        """
        digest_bytes = bytearray(digest.digest())

        src_sz = len(digest_bytes)
        src_c_ubyte = (c_ubyte * src_sz)(*digest_bytes)
        dst_data = c_void_p()
        dst_data_sz = c_int()
        recovery_id = c_uint()

        ret = self._zkGenECDSASigFromDigestWithRecID(
            self._zk_ctx,
            src_c_ubyte,
            slot,
            byref(dst_data),
            byref(dst_data_sz),
            byref(recovery_id),
        )
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)
        dc = (c_ubyte * dst_data_sz.value).from_address(dst_data.value)
        data_array = bytearray(dc)

        if return_recid:
            return data_array, recovery_id
        else:
            return data_array

    def verify(
        self,
        src: t.Union[str, bytes, bytearray],
        sig: bytearray,
        raise_exception: bool = True,
        pubkey_slot: int = 0,
        foreign: bool = False,
        encoding: str = "utf-8",
        digest: t.Any = None,
    ) -> bool:
        """Verify data against a signature.

        The public key is not specified in the parameter list to ensure
        that the public key that matches the Zymkey's ECDSA private key
        is used.

        Parameters
        ----------
        src : TYPE
            The buffer to verify.
        sig : TYPE
            The signature to verify against.
        raise_exception : bool
            By default, when verification fails a `VerificationError` will be
            raised, unless this is set to `False`.
        pubkey_slot : int
            The key slot to use to verify the signature against. Defaults to the
            first key slot.
        foreign : bool
            If false, the normal key store is referenced. Otherwise, the foreign
            public key store is referenced.
            **Note:** This parameter is only applicable for Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module.
        encoding : str
            This parameter asks for the encoding for the string source.
        digest : _hashlib.HASH
            This parameter asks for the type of hash. Can be None. Defaults to sha256.

        Returns
        -------
        bool
            Returns `True` for a good verification or `False` for a bad
            verification when the `raise_exception` parameters is `False`.
        """
        if (digest is None):
            digest = hashlib.sha256()

        digest_obj = DigestObject(src, encoding, digest)

        return self.verify_digest(
            digest_obj,
            sig,
            raise_exception=raise_exception,
            pubkey_slot=pubkey_slot,
            foreign=foreign,
        )

    def verify_digest(
        self,
        digest: t.Any,
        sig: bytearray,
        raise_exception: bool = True,
        pubkey_slot: int = 0,
        foreign: bool = False,
    ) -> bool:
        """Verify a signature using the Zymkey's ECDSA public key.

        The public key is not specified in the parameter list to ensure
        that the public key that matches the Zymkey's ECDSA private key
        is used.

        Parameters
        ----------
        digest : TYPE
            A hashlib instance that will be used to generate the signature.
        sig : TYPE
            The signature to verify.
        raise_exception : bool
            By default, when verification fails, a `VerificationError` will be
            raised, unless this is set to `False`.
        pubkey_slot : int
            The key slot to use to verify the signature against. Defaults to
            the first key slot.
        foreign : bool
            If false, the normal key store is referenced. Otherwise, the foreign
            public key store is referenced.
            **Note:** This parameter is only applicable for Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module.

        Returns
        -------
        bool
            Returns `True` for a good verification or `False` for a bad
            verification when `raise_exception` is `False`.
        """
        digest_bytes = bytearray(digest.digest())

        src_sz = len(digest_bytes)
        sig_sz = len(sig)
        src_c_ubyte = (c_ubyte * src_sz)(*digest_bytes)
        sig_c_ubyte = (c_ubyte * sig_sz)(*sig)

        if not foreign:
            ret = self._zkVerifyECDSASigFromDigest(
                self._zk_ctx, src_c_ubyte, pubkey_slot, sig_c_ubyte, sig_sz
            )
        else:
            ret = self._zkVerifyECDSASigFromDigestWithForeignKeySlot(
                self._zk_ctx, src_c_ubyte, pubkey_slot, sig_c_ubyte, sig_sz
            )

        if ret == 0:
            if raise_exception:
                raise VerificationError()
            return False
        if ret == 1:
            return True
        else:
            raise AssertionError("bad return code %d" % ret)

    ###@}

    ## @name ECDH and KDF
    ###@{

    def ecdh(
        self,
        local_slot: int,
        peer_pubkey: t.Union[t.List[bytes], int],
        kdf_func_type: str = "none",
        salt: t.Optional[t.List[bytes]] = [],
        info: t.Optional[t.List[bytes]] = [],
        num_iterations: int = 1,
        peer_pubkey_slot_is_foreign: bool = True,
        derived_key_size: bool = 32,
    ) -> bytearray:
        """Derive a key or a pre-master secret from an ECDH operation. (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        Parameters
        ----------
        local_slot : int
            The local key slot to use.
        peer_pubkey : t.Union[t.List[bytes], int]
            The public key of the peer used to generate the pre-master secret
            against the private key located in `local_slot`. This parameter can
            be a list of `bytes` if the key is provided explicitly or an `int`
            if it refers to a key slot.
        kdf_func_type : str
            Specifies the KDF (Key Derivation Function) to use
            for the returned derived key. Valid values are:

            * `"none"`: just return the pre-master secret. NOTE: The raw pre-master
              secret should not be used as a derived key should be put through a
              suitable KDF. Use 'none' when it is desired to use a different KDF
              than what is offered by this method.
            * `"rfc5869-sha256"`: RFC5869 with SHA256
            * `"rfc5869-sha512"`: RFC5869 with SHA512
            * `"pbkdf2-sha256"`: PBKDF2 with SHA256
            * `"pbkdf2-sha512"`: PBKDF2 with SHA512
        salt : t.Optional[t.List[bytes]]
            A unique identifier for KDF. Ignored for `kdf_func_type='none'`.
        info : t.Optional[t.List[bytes]]
            A unique field for rfc5869. Ignore for other KDF types.
        num_iterations : int
            The number of iterations that the KDF should complete.
        peer_pubkey_slot_is_foreign : bool
            TODO_DESCRIPTION
        derived_key_size : bool
            TODO_DESCRIPTION

        Returns
        -------
        bytearray
            The computed signature.

        Todo
        ----
        Allow for overloading of source parameter in similar fashion to lock/unlockData.
        """
        derived_key = c_void_p()
        salt_sz = len(salt)
        salt_c_ubyte = (c_ubyte * salt_sz)(*salt)
        info_sz = len(info)
        info_c_ubyte = (c_ubyte * info_sz)(*info)
        # Get the kdf_func_type
        kdf_func = kdfFuncTypes[kdf_func_type]
        # Get the type of the peer public key. If the type is 'int', peer_pubkey
        # refers to a slot internal to the zymkey. Otherwise, a list with the
        # contents of the public key is expected.
        if type(peer_pubkey) == "int" or type(peer_pubkey) is int:
            peer_pubkey = c_int(peer_pubkey)
            peer_pubkey_slot_is_foreign = c_bool(peer_pubkey_slot_is_foreign)
            if kdf_func_type == "none":
                self._zkDoRawECDHWithIntPeerPubkey(
                    self._zk_ctx,
                    local_slot,
                    peer_pubkey,
                    peer_pubkey_slot_is_foreign,
                    byref(derived_key),
                )
                dst_data_sz = c_int(32)
            else:
                self._zkDoECDHAndKDFWithIntPeerPubkey(
                    self._zk_ctx,
                    kdf_func - 1,
                    local_slot,
                    peer_pubkey,
                    peer_pubkey_slot_is_foreign,
                    salt_c_ubyte,
                    salt_sz,
                    info_c_ubyte,
                    info_sz,
                    num_iterations,
                    derived_key_size,
                    byref(derived_key),
                )
        else:
            peer_pubkey_sz = len(peer_pubkey)
            peer_pubkey_c_ubyte = (c_ubyte * peer_pubkey_sz)(*peer_pubkey)
            if kdf_func_type == "none":
                self._zkDoRawECDH(
                    self._zk_ctx,
                    local_slot,
                    peer_pubkey_c_ubyte,
                    peer_pubkey_sz,
                    byref(derived_key),
                )
                dst_data_sz = c_int(32)
            else:
                self._zkDoECDHAndKDF(
                    self._zk_ctx,
                    kdf_func - 1,
                    local_slot,
                    peer_pubkey_c_ubyte,
                    peer_pubkey_sz,
                    salt_c_ubyte,
                    salt_sz,
                    info_c_ubyte,
                    info_sz,
                    num_iterations,
                    derived_key_size,
                    byref(derived_key),
                )
        dc = (c_ubyte * derived_key_size).from_address(derived_key.value)
        data_array = bytearray(dc)
        return data_array

    ###@}

    ## @name Key Management
    ###@{

    def create_ecdsa_public_key_file(self, filename: str, slot: int = 0) -> None:
        """Create a file with the PEM-formatted ECDSA public key.

        **[DEPRECATED]:** Use `create_public_key_file` instead.

        This method is useful for generating a Certificate Signing Request.

        Parameters
        ----------
        filename : str
            The absolute file path where the public key will be stored in PEM format.
        slot : int
            The key slot for the public key.

        Raises
        ------
        AssertionError
            If `ret` is a bad return code from the Zymkey library function.
        """
        ret = self._zkSaveECDSAPubKey2File(self._zk_ctx, filename.encode("utf-8"), slot)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def create_public_key_file(
        self, filename: str, slot: int = 0, foreign: bool = False
    ) -> None:
        """Create a file with the PEM-formatted public key.

        This method is useful for generating a Certificate Signing Request.

        Parameters
        ----------
        filename : str
            The absolute file path where the public key will be stored in PEM format.
        slot : int
            The key slot for the public key.
        foreign : bool
            If `True`, designates the pubkey slot to come from the foreign keystore (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        Raises
        ------
        AssertionError
            If `ret` is a bad return code from the Zymkey library function.

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        """
        ret = self._zkExportPubKey2File(
            self._zk_ctx, filename.encode("utf-8"), slot, foreign
        )
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def get_ecdsa_public_key(self, slot: int = 0) -> bytearray:
        """Retrieves the ECDSA public key as a binary bytearray.

        **[DEPRECATED]:** Use `get_public_key` instead.

        This method is used to retrieve the public key in binary form.

        Parameters
        ----------
        slot : int
            The key slot for the public key.

        Returns
        -------
        bytearray
            The public key in binary form.

        Raises
        ------
        AssertionError
            If `ret` is a bad return code from the Zymkey library function.
        """
        dst_data = c_void_p()
        dst_data_sz = c_int()

        ret = self._zkGetECDSAPubKey(
            self._zk_ctx, byref(dst_data), byref(dst_data_sz), slot
        )
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)
        dc = (c_ubyte * dst_data_sz.value).from_address(dst_data.value)
        data_array = bytearray(dc)
        return data_array

    def get_public_key(self, slot: int = 0, foreign: bool = False):
        """Retrieves a public key as a binary bytearray.

        This method is used to retrieve the public key in binary form.

        Parameters
        ----------
        slot : int
            The key slot for the public key. Zymkey and HSM4 have slots 0, 1, and 2.
        foreign : bool
            If `True`, designates the pubkey slot to come from the foreign keystore (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        Returns
        -------
        bytearray
            The public key in binary form.

        Raises
        ------
        AssertionError
            If `ret` is a bad return code from the Zymkey library function.
        """
        dst_data = c_void_p()
        dst_data_sz = c_int()

        ret = self._zkExportPubKey(
            self._zk_ctx, byref(dst_data), byref(dst_data_sz), slot, foreign
        )
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)
        dc = (c_ubyte * dst_data_sz.value).from_address(dst_data.value)
        data_array = bytearray(dc)
        return data_array

    def get_slot_alloc_list(self, foreign: bool = False) -> t.Tuple[list, int]:
        """Get a list of the allocated slots in the key store (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        This method gets a list of the allocated slots in the key store.

        Parameters
        ----------
        foreign : bool
            If `True`, designates the pubkey slot to come from the foreign keystore (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        Returns
        -------
        t.Tuple[list, int]
            The allocation list and the maximum number of keys

        Raises
        ------
        AssertionError
            If `ret` is a bad return code from the Zymkey library function.
        """
        alloc_key_slot_list = c_void_p()
        alloc_key_slot_list_sz = c_int()
        max_num_keys = c_int()

        ret = self._zkGetAllocSlotsList(
            self._zk_ctx,
            foreign,
            byref(max_num_keys),
            byref(alloc_key_slot_list),
            byref(alloc_key_slot_list_sz),
        )
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)
        dc = (c_int * alloc_key_slot_list_sz.value).from_address(
            alloc_key_slot_list.value
        )
        alloc_keys = list(dc)
        return alloc_keys, max_num_keys.value

    def store_foreign_public_key(self, key_type: str, pubkey: bytearray) -> int:
        """Stores a foreign public key on the Zymkey foreign keyring (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        This method stores a foreign public key onto the Zymkey foreign public keyring.

        Parameters
        ----------
        key_type : TYPE
            The EC curve type that should be associated with the public key.
        pubkey : TYPE
            The public key binary data.

        Returns
        -------
        int
            The slot allocated to the key, or less than one for failure.

        Raises
        ------
        AssertionError
            If `ret` is a bad return code from the Zymkey library function.
        """
        pubkey_sz = len(pubkey)
        pubkey_c_ubyte = (c_ubyte * pubkey_sz)(*pubkey)

        kt = keyTypes[key_type]
        ret = self._zkStoreForeignPubKey(self._zk_ctx, kt, pubkey_c_ubyte, pubkey_sz)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)
        return ret

    def disable_public_key_export(self, slot=0, foreign=False):
        """Disable exporting of a public key at a given slot (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        This method permanently disables exporting a public key from a
        given slot.

        Parameters
        ----------
        slot
            This parameter specifies the key slot for the public key.
        foreign
            If true, the slot refers to the foreign public keyring.

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        """
        ret = self._zkDisablePubKeyExport(self._zk_ctx, slot, foreign)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def gen_key_pair(self, key_type):
        """Generate a new key pair (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        This method generates a new key pair of the specified type.

        Parameters
        ----------
        key_type
            This parameter indicates the EC curve type that should be
            associated with the new key pair.

        Returns
        -------
        TYPE
            the slot allocated to the key or less than one for failure.
        """
        kt = keyTypes[key_type]
        ret = self._zkGenKeyPair(self._zk_ctx, kt)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)
        return ret

    def gen_ephemeral_key_pair(self, key_type):
        """Generate a new ephemeral key pair (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        This method generates a new ephemeral key pair of the specified
        type, overwriting the previous ephemeral key pair.

        Parameters
        ----------
        key_type
            This parameter indicates the EC curve type that should be
            associated with the new key pair.

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        """
        kt = keyTypes[key_type]
        ret = self._zkGenEphemeralKeyPair(self._zk_ctx, kt)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def remove_key(self, slot, foreign=False):
        """Remove a key at the designated slot (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        This method removes a key at the designated slot in either the
        standard key store or the foreign public keyring.

        Parameters
        ----------
        slot
            This parameter specifies the key slot for the key.
        foreign
            If true, a public key in the foreign keyring will be deleted.

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        """
        ret = self._zkRemoveKey(self._zk_ctx, slot, foreign)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def invalidate_ephemeral_key(self) -> int:
        """Invalidate the ephemeral key (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        This method invalidates the ephemeral key, effectively removing
        it from service until a new key is generated.

        Raises
        ------
        AssertionError
            If `ret` is a bad return code from the Zymkey library function.

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        """
        ret = self._zkInvalidateEphemeralKey(self._zk_ctx)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)
        return ret

    ###@}

    ## @name Digital Wallet (BIP 32/39/44)
    ###@{

    def gen_wallet_master_seed(
        self,
        key_type,
        master_gen_key,
        wallet_name,
        recovery_strategy=RecoveryStrategy(),
    ):
        """Generates a new master seed for creating a new BIP32 wallet (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        This method generates a new master seed for creating a new BIP32
        wallet.

        Parameters
        ----------
        key_type
            This parameter indicates the EC curve type that should be
            associated with the new key pair.
        master_gen_key
            The master generator key (bytearray) used in the
            derivation of the child key.
        wallet_name
            The name of the wallet (string) that this master seed
            is attached to.
        recovery_strategy
            RecoveryStrategy() class that defines what strategy to be used
            {None, BIP39, SLIP39} are currently supported.
            RecoveryStrategy->passphrase must be b64 encoded.

        Returns
        -------
        TYPE
            the slot the master seed was generated in. 0 for starting SLIP39 sessions.
        """
        master_gen_key_sz = len(master_gen_key)
        master_gen_key_c_ubyte = (c_ubyte * master_gen_key_sz)(*master_gen_key)

        BIP39_mnemonic = c_void_p()

        if recovery_strategy is None:
            recovery_strategy = RecoveryStrategy()

        if recovery_strategy.recovery_strategy == "BIP39":
            mnemonic_ptr = byref(BIP39_mnemonic)
        else:
            mnemonic_ptr = POINTER(c_void_p)()

        kt = keyTypes[key_type]
        if recovery_strategy.recovery_strategy != "SLIP39":
            ret = self._zkGenWalletMasterSeed(
                self._zk_ctx,
                kt,
                recovery_strategy.variant.encode("utf-8"),
                wallet_name.encode("utf-8"),
                master_gen_key_c_ubyte,
                master_gen_key_sz,
                recovery_strategy.passphrase.encode("utf-8"),
                mnemonic_ptr,
            )
        else:
            ret = self._zkOpenGenSLIP39Session(
                self._zk_ctx,
                kt,
                recovery_strategy.variant.encode("utf-8"),
                wallet_name.encode("utf-8"),
                master_gen_key_c_ubyte,
                master_gen_key_sz,
                recovery_strategy.group_count,
                recovery_strategy.group_threshold,
                recovery_strategy.iteration_exponent,
                recovery_strategy.passphrase.encode("utf-8"),
            )

        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

        if recovery_strategy.recovery_strategy == "BIP39":
            mnemonic = cast(BIP39_mnemonic, c_char_p)
            return ret, mnemonic.value.decode("utf-8")
        elif recovery_strategy.recovery_strategy == "SLIP39":
            return ret
        else:
            return ret

    def set_gen_SLIP39_group_info(
        self,
        group_index,
        member_count,
        member_threshold,
    ):
        """Configures the number of members and threshold for the group shares (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        This method sets the number of members required for a group share once a SLIP39 session
        was opened via gen_wallet_master_seed().

        Parameters
        ----------
        group_index
            This parameter indicates the index of the group share
            to set the amount of member count/threshold for.
        member_count
            The total number of members (mnemonics) in this group share.
        member_threshold
            The number of members (mnemonics) needed to reconstruct the group share.

        Returns
        -------
        TYPE
            0 on successful configuration. non-zero for error.
        """
        ret = self._zkSetSLIP39GroupInfo(self._zk_ctx, group_index, member_count, member_threshold)
        if (ret < 0):
            raise AssertionError("bad return code %d" % ret)

    def add_gen_SLIP39_member_pwd(
        self,
        passphrase = "",
    ):
        """Generates a new mnemonic_str tied to a SLIP39 member (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        This method generates a new member of a group share. Members can also be
        passphrase protected. Passphrases are not required to be unique. This
        function is meant to be called after configuring a group via set_gen_SLIP39_group_info().

        Parameters
        ----------
        passphrase
            This parameter indicates the passphrase of the SLIP39 member
            and is associated with the mnemonic string generated. Can
            be empty string for no passphrase.

        Returns
        -------
        TYPE
            A 24-word recovery phrase known as a mnemonic sentence. non-zero for error.
        """

        mnemonic_sentence = c_void_p()
        mnemonic_ptr = byref(mnemonic_sentence)
        ret = self._zkAddSLIP39Member(self._zk_ctx, passphrase.encode("utf-8"), mnemonic_ptr)
        mnemonic = cast(mnemonic_sentence, c_char_p)
        if mnemonic is None:
            raise AssertionError("Mnemonic returned nothing")
        return ret, mnemonic.value.decode("utf-8")

    def cancel_SLIP39_session(self):
        """Cancels an active SLIP39 session (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        This method cancels an ongoing SLIP39 session for both master seed generation and recovery.

        Returns
        -------
        TYPE
            0 on success. non-zero for error.
        """

        ret = self._zkCancelSLIP39Session(self._zk_ctx)
        if (ret < 0):
            raise AssertionError("bad return code %d" % ret)

    def gen_oversight_wallet(
        self,
        key_type,
        pub_key,
        chain_code,
        node_addr,
        wallet_name,
        variant = ""
    ):
        """Generates a supervisory bip32 wallet. (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        This method generates a new supervisory Bip32 wallet. Meant for
        read-only transactions and supervising history.

        Parameters
        ----------
        key_type
            This parameter indicates the EC curve type that should be
            associated with the new key pair.
        pub_key
            The public key (bytearray) of the last
            hardened node of the node address.
        chain_code
            The chain code (bytearray) of the last
            hardened node of the node address.
        node_addr
            The bip32 node address used. (EX: "m/1852'/1815'/0'").
        wallet_name
            The name of the wallet (string) that this master seed
            is attached to.
        variant
            Key type variant to generate from. Currently only "cardano" is
            supported for "ed25519".

        Returns
        -------
        TYPE
            the slot the oversight wallet was generated in.
        """

        kt = keyTypes[key_type]
        pubkey_sz = len(pub_key)
        pubkey_c_ubyte = (c_ubyte * pubkey_sz)(*pub_key)
        chaincode_sz = len(chain_code)
        chaincode_c_ubyte = (c_ubyte * chaincode_sz)(*chain_code)
        ret = self._zkGenOversightWallet(
            self._zk_ctx,
            kt,
            variant.encode("utf-8"),
            pubkey_c_ubyte,
            chaincode_c_ubyte,
            node_addr.encode("utf-8"),
            wallet_name.encode("utf-8")
        )
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

        return ret

    def gen_wallet_child_key(self, parent_key_slot, index, hardened, return_chain_code = False):
        """Generates a child key based on a parent key that is in a wallet (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        This method generates a child key based on a parent key that is
        in a wallet.

        Parameters
        ----------
        parent_key_slot
            This parameter specifies the parent key slot. This
            key must already be part of a wallet.
        index
            This parameter represents the index for the child key
            derivation which becomes part of the node address.
        hardened
            If true, the key is a hardened key.
        return_chain_code
            If true, returns the chain code for the key as well.
            (Must be from a hardened key).

        Returns
        -------
        TYPE
            the allocated slot on success, or a tuple containing the chain code as well.
        """
        chain_code_data = c_void_p()
        if return_chain_code:
            chain_ptr = byref(chain_code_data)
        else:
            chain_ptr = POINTER(c_void_p)()

        ret = self._zkGenWalletChildKey(self._zk_ctx, parent_key_slot, index, hardened, return_chain_code, chain_ptr)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

        if return_chain_code:
            dc = (c_ubyte * 32).from_address(chain_code_data.value)
            chain_code = bytearray(dc)
            return ret, chain_code
        else:
            return ret

    def restore_wallet_master_seed(
        self, key_type, master_gen_key, wallet_name, recovery_strategy, mnemonics = None
    ):
        """Restore a wallet's master seed based on the recovery strategy object (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        This method restores a wallet's master seed based on a
        mnemonic string and a master generator key. This method can be
        used in the process of wallet duplication.

        Parameters
        ----------
        key_type
            This parameter indicates the EC curve type that should be
            associated with the new key pair.
        master_gen_key
            The master generator key used in the derivation of
            the child key.
        wallet_name
            Name of the new wallet to be generated.
        recovery_strategy
            RecoveryStategy class object that provides the type of recovery
            and key variant required for restoration.
        mnemonics
            Mnemonic sentences required for restoration, number of mnemonics dependant
            on recovery strategy used. This field is not used for SLIP39.

        Returns
        -------
        TYPE
            the allocated slot on success
        """
        master_gen_key_sz = len(master_gen_key)
        master_gen_key_c_ubyte = (c_ubyte * master_gen_key_sz)(*master_gen_key)

        kt = keyTypes[key_type]
        if recovery_strategy.recovery_strategy == "BIP39":
            if mnemonics is None:
                raise AssertionError("BIP39 requires a mnemonic sentence")
            ret = self._zkRestoreWalletMasterSeedFromBIP39Mnemonic(
                self._zk_ctx,
                kt,
                recovery_strategy.variant.encode("utf-8"),
                wallet_name.encode("utf-8"),
                master_gen_key_c_ubyte,
                master_gen_key_sz,
                recovery_strategy.passphrase.encode("utf-8"),
                mnemonics.encode("utf-8"),
            )
        elif recovery_strategy.recovery_strategy == "SLIP39":
            ret = self._zkOpenRestoreSLIP39Session(
                self._zk_ctx,
                kt,
                recovery_strategy.variant.encode("utf-8"),
                wallet_name.encode("utf-8"),
                master_gen_key_c_ubyte,
                master_gen_key_sz,
                recovery_strategy.passphrase.encode("utf-8"),
            )
        else:
            raise AssertionError("Not a supported recovery strategy")

        if ret < 0 and recovery_strategy.recovery_strategy != "SLIP39":
            raise AssertionError("bad return code %d" % ret)
        return ret

    def add_restore_SLIP39_mnemonic(
        self,
        mnemonic_sentence,
        passphrase = "",
    ):
        """Feed a mnemonic string and the passphrase associated with it (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        This method feeds in mnemonic sentences (shards) into the module.
        Meant to be called after starting a restore_wallet_master_seed() SLIP39 session.
        Will return -1 until the master seed is reconstructed properly.

        Parameters
        ----------
        mnemonic_sentence
            24-word recovery phrase associated with the SLIP39 member.
        passphrase
            This parameter indicates the passphrase of the SLIP39 member
            and is associated with the mnemonic string generated. Can
            be empty string for no passphrase.

        Returns
        -------
        TYPE
            A -1 for no change in status. Otherwise returns the slot of the master seed successfully
            reconstructed from the last shard passed in.
        """
        ret = self._zkAddRestoreSLIP39Mnemonic(self._zk_ctx, passphrase.encode("utf-8"), mnemonic_sentence.encode("utf-8"))
        return ret

    def get_wallet_node_addr(self, slot):
        """Get a wallet node address from a key slot (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module)

        This method gets a wallet entry's node address from its key slot
        assignment. The wallet name and master seed slot are also
        returned.

        Parameters
        ----------
        slot
            The key slot assignment.

        Returns
        -------
        TYPE
            the node address, wallet name and master seed key slot.
        """
        node_addr = c_void_p()
        wallet_name = c_void_p()
        master_seed_slot = c_int()
        ret = self._zkGetWalletNodeAddrFromKeySlot(
            self._zk_ctx,
            slot,
            byref(node_addr),
            byref(wallet_name),
            byref(master_seed_slot),
        )
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)
        na = cast(node_addr, c_char_p)
        wn = cast(wallet_name, c_char_p)
        return (
            na.value.decode("utf-8"),
            wn.value.decode("utf-8"),
            master_seed_slot.value,
        )

    def get_wallet_key_slot(self, node_addr, wallet_name=None, master_seed_slot=None):
        """Look up a wallet key slot number from a node address (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module)

        This method gets a wallet key slot number from its node address
        and wallet name or master seed key slot. Either the wallet name
        or the master seed slot must be present.

        Parameters
        ----------
        node_addr
            The desired node address to look up
        wallet_name
            The name of the wallet that the node address belongs
            to. Either this parameter or master_seed_slot must be
            specified or this function will fail.
        master_seed_slot
            The master seed slot that the node address belongs
            to. Either this parameter or wallet_name must be
            specified or this function will fail.

        Returns
        -------
        TYPE
            the key slot.
        """
        if wallet_name:
            wallet_name = wallet_name.encode("utf-8")
            master_seed_slot = 0
        key_slot = c_int()
        ret = self._zkGetWalletKeySlotFromNodeAddr(
            self._zk_ctx,
            node_addr.encode("utf-8"),
            wallet_name,
            master_seed_slot,
            byref(key_slot),
        )
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)
        return key_slot.value

    ###@}

    ## @name Adminstration
    ###@{

    def set_i2c_address(self, address: int) -> None:
        """Set the i2c address of the Zymkey.

        **Note:** This is only applicable to versions of the Zymkey with i2c.

        This method should be called if the i2c address of the
        Zymkey is shared with another i2c device on the same i2c bus.
        The default i2c address for Zymkey units is 0x30. Currently,
        the address may be set in the ranges of 0x30 - 0x37 and 0x60 - 0x67.

        After successful completion of this command, the Zymkey will
        reboot itself.

        Parameters
        ----------
        address
            The i2c address that the Zymkey will set itself to.

        Raises
        ------
        AssertionError
            If `ret` is a bad return code from the Zymkey library function.

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        """
        addr_c_int = c_int(address)
        ret = self._zkSetI2CAddr(self._zk_ctx, addr_c_int)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    ###@}

    ## @name Accelerometer
    ###@{

    def set_tap_sensitivity(self, axis="all", pct=50.0):
        """Set the sensitivity of tap operations.

        This method permits setting the sensitivity of the tap
        detection feature. Each axis may be individually
        configured or all at once.

        Parameters
        ----------
        axis
            The axis to configure. Valid values include:
              1. 'all': Configure all axes with the specified sensitivity value.
              2. 'x' or 'X': Configure only the x-axis
              3. 'y' or 'Y': Configure only the y-axis
              4. 'z' or 'Z': Configure only the z-axis
        pct
            The sensitivity expressed as percentage.
              1. 0% = Shut down: Tap detection should not occur along the axis.
              2. 100% = Maximum sensitivity.

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        """
        axis = axis.lower()
        axis_c_int = c_int()
        if axis == "x":
            axis_c_int = 0
        elif axis == "y":
            axis_c_int = 1
        elif axis == "z":
            axis_c_int = 2
        elif axis == "all":
            axis_c_int = 3
        else:
            raise AssertionError("invalid input value " + axis)
        ret = self._zkSetTapSensitivity(self._zk_ctx, axis_c_int, pct)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def wait_for_tap(self, timeout_ms=-1):
        """Wait for tap event

        This function is called in order to wait for a tap event to occur.
        This function blocks the calling thread unless called with a
        timeout of zero.

        Parameters
        ----------
        timeout_ms
            The maximum amount of time in milliseconds to wait for a tap
            event to arrive.
        """
        ret = self._zkWaitForTap(self._zk_ctx, timeout_ms)
        if ret == -errno.ETIMEDOUT:
            raise ZymkeyTimeoutError("wait timed out")
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    ## @brief Return class for Zymkey.get_accelerometer_data
    #  @details This class is the return type for Zymkey.get_accelerometer_data. It
    #           contains the instantaneous reading of an axis along with the
    #           direction of force that caused the latest tap event.
    class ZymkeyAccelAxisData(object):
        def __init__(self, g_force, tap_dir):
            self.g_force = g_force
            self.tap_dir = tap_dir

    def get_accelerometer_data(self):
        """Get current accelerometer data and tap info.

        This function gets the most recent accelerometer data in units of g
        forces plus the tap direction per axis.

        Returns
        -------
            An array of accelerometer readings in units of g-force.
            array index 0 = x axis
                        1 = y axis
                        2 = z axis
            A value of -1 indicates that the tap event was detected in a
            negative direction for the axis, +1 for a positive direction
            and 0 for stationary.
        """

        class _zkAccelAxisDataType(Structure):
            _fields_ = [("g", c_double), ("tapDirection", c_int)]

        x = _zkAccelAxisDataType()
        y = _zkAccelAxisDataType()
        z = _zkAccelAxisDataType()
        ret = self._zkGetAccelerometerData(self._zk_ctx, byref(x), byref(y), byref(z))
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)
        xret = self.ZymkeyAccelAxisData(x.g, x.tapDirection)
        yret = self.ZymkeyAccelAxisData(y.g, y.tapDirection)
        zret = self.ZymkeyAccelAxisData(z.g, z.tapDirection)
        return xret, yret, zret

    ###@}

    ## @name Time
    ###@{

    def get_time(self, precise=False):
        """Get current GMT time

        This function is called to get the time directly from a
        Zymkey's Real Time Clock (RTC)

        Parameters
        ----------
        precise
            If true, this API returns the time after the next second
            falls. This means that the caller could be blocked up to one second.
            If False, the API returns immediately with the current time reading.
        Returns
        -------
            Time in epoch seconds.
        """
        epoch_sec = c_int()
        ret = self._zkGetTime(self._zk_ctx, byref(epoch_sec), precise)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)
        return epoch_sec.value

    ###@}

    ## @name Binding Management
    ###@{

    def lock_binding(self):
        """Set soft binding lock.

        This function locks the binding for a specific HSM. This API is
        only valid for HSM series products.

        Raises
        ------
        AssertionError
            If `ret` is a bad return code from the Zymkey library function.
        """
        ret = self._zkLockBinding(self._zk_ctx)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def get_current_binding_info(self):
        """Get current binding info.

        This function gets the current binding lock state as well as the
        current binding state. This API is only valid for devices in the HSM
        family.

        Returns
        -------
        binding_is_locked
            Binary value which expresses the current binding lock state.
        is_bound
            Binary value which expresses the current bind state.
        """
        locked = c_bool()
        is_bound = c_bool()
        ret = self._zkGetCurrentBindingInfo(
            self._zk_ctx, byref(locked), byref(is_bound)
        )
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)
        return locked.value, is_bound.value

    ###@}

    ## @name Perimeter Breach
    ###@{

    def set_perimeter_event_actions(
        self, channel, action_notify=True, action_self_destruct=False
    ):
        """Set perimeter breach action

        This function specifies the action to take when a perimeter breach
        event occurs. The possible actions are any combination of:
          * Notify host
          * Zymkey self-destruct

        Parameters
        ----------
        channel
            The channel (0 or 1) that the action flags will be applied to
        action_notify
            Set a perimeter breach to notify. (default = True)
        action_self_destruct
            Set a perimeter breach to self destruct. (default = False)

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        """
        actions = 0
        if action_notify:
            actions |= 1
        if action_self_destruct:
            actions |= 2
        ret = self._zkSetPerimeterEventAction(self._zk_ctx, channel, actions)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def set_digital_perimeter_lp_period(self, lp_period):
        """Set the digital perimeter detect low power period (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        This function sets the digital perimeter detect low power period (microseconds).

        Parameters
        ----------
        lp_period
            The perimeter detect low power period in microseconds.

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        """
        ret = self._zkSetDigitalPerimeterDetectLPPeriod(self._zk_ctx, lp_period)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def set_digital_perimeter_lp_max_bits(self, max_num_bits):
        """Set the low power max number of bits (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        This function sets the digital perimeter detect low power max number of bits

        Parameters
        ----------
        max_num_bits
            The perimeter detect low power max number of bits

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        """
        ret = self._zkSetDigitalPerimeterDetectLPMaxBits(self._zk_ctx, max_num_bits)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def set_digital_perimeter_delays(self, min_delay_ns, max_delay_ns):
        """Set the digital perimeter detect delays (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        This function sets the digital perimeter detect delay values.

        Parameters
        ----------
        min_delay_ns
            The minimum delay in nanoseconds.
        max_delay_ns
            The maximum delay in nanoseconds.

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        """
        ret = self._zkSetDigitalPerimeterDetectDelays(
            self._zk_ctx, min_delay_ns, max_delay_ns
        )
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def wait_for_perimeter_event(self, timeout_ms=-1):
        """Wait for a perimeter breach event to be detected

        This function is called in order to wait for a perimeter breach
        event to occur. This function blocks the calling thread unless
        called with a timeout of zero.

        Parameters
        ----------
        timeout_ms
            (input) The maximum amount of time in milliseconds to wait for a perimeter breach
            event to arrive.

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        """
        ret = self._zkWaitForPerimeterEvent(self._zk_ctx, timeout_ms)
        if ret == -errno.ETIMEDOUT:
            raise ZymkeyTimeoutError("wait timed out")
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def get_perimeter_detect_info(self):
        """Get current perimeter detect info.

        This function gets the timestamp of the first perimeter detect
        event for the given channel. The index corresponds to the channel specified in set_perimeter_event_actions.

        Returns
        -------
        TYPE
            The array of timestamps for each channel for the first detected
            event in epoch seconds
        """
        pdata = c_void_p()
        pdata_sz = c_int()

        ret = self._zkGetPerimeterDetectInfo(
            self._zk_ctx, byref(pdata), byref(pdata_sz)
        )
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)
        dc = (c_uint32 * pdata_sz.value).from_address(pdata.value)

        timestamps_sec = []

        for i in range(pdata_sz.value):
            timestamps_sec.append(dc[i])
        return timestamps_sec

    def clear_perimeter_detect_info(self):
        """Clear perimeter detect info.

        This function clears all perimeter detect info and rearms all
        perimeter detect channels

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        """
        ret = self._zkClearPerimeterDetectEvents(self._zk_ctx)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    ###@}

    ## @name Module Info
    ###@{

    def get_cpu_temp(self):
        """Get current CPU temperature (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        This function gets the current HSM CPU temperature.

        Returns
        -------
        TYPE
            The CPU temperature in celsius as a float
        """
        temp = c_float()
        ret = self._zkGetCPUTemp(self._zk_ctx, byref(temp))
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)
        return temp.value

    def get_aux_temp(self, index = 0):
        """Get current aux temperature (Secure Compute Modules only).

        THIS FUNCTION IS FOR INTERNAL ZYMBIT USE ONLY.

        This function gets the current aux temperature. (defaults to 0)

        Parameters
        ----------
        index
            (input) The index id of the processor.

        Returns
        -------
        TYPE
            The temperature in celsius as a float
        """
        temp = c_float()
        ret = self._zkGetAUXTemp(self._zk_ctx, index, byref(temp))
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)
        return temp.value

    def get_rtc_drift(self):
        """Get RTC drift (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        This function gets the current RTC drift.

        Returns
        -------
        TYPE
            The RTC drift as a float
        """
        drift = c_float()
        ret = self._zkGetRTCDrift(self._zk_ctx, byref(drift))
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)
        return drift.value

    def get_batt_volt(self):
        """Get current battery voltage (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module).

        This function gets the current battery voltage.

        Returns
        -------
        TYPE
            The battery voltage as a float
        """
        volt = c_float()
        ret = self._zkGetBatteryVoltage(self._zk_ctx, byref(volt))
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)
        return volt.value

    ###@}

    ## @name Model Information
    ###@{

    def get_model_number(self):
        """Get Zymkey model number

        This function gets the Zymkey model number.

        Returns
        -------
        TYPE
            The model number as a string.
        """
        model = c_void_p()
        ret = self._zkGetModelNumberString(self._zk_ctx, byref(model))
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)
        model_str = cast(model, c_char_p)
        return model_str.value.decode("utf-8")

    def get_firmware_version(self):
        """Get Zymkey firmware version

        This function gets the Zymkey firmware version.

        Returns
        -------
        TYPE
            The firmware version as a string.
        """
        fw = c_void_p()
        ret = self._zkGetFirmwareVersionString(self._zk_ctx, byref(fw))
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)
        fw_str = cast(fw, c_char_p)
        return fw_str.value.decode("utf-8")

    def get_serial_number(self):
        """Get Zymkey serial number

        This function gets the Zymkey serial number.

        Returns
        -------
        TYPE
            The serial number as a string.
        """
        sn = c_void_p()
        ret = self._zkGetSerialNumberString(self._zk_ctx, byref(sn))
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)
        sn_str = cast(sn, c_char_p)
        return sn_str.value.decode("utf-8")

    ###@}

    ## @name Battery Voltage Monitor
    ###@{

    def set_battery_voltage_action(self, sleep=False, self_destruct=False):
        """Set battery voltage action. (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module)

        This function specifies the action to take when the
        battery voltage falls below the threshold set by
        set_battery_voltage_threshold. If this function is never
        called, do nothing is default. There are three actions:
          * Do nothing
          * Go to sleep until battery is replaced
          * Self-destruct
        With sleep and self_destruct set to False, it removes a
        previously set sleep or self_destruct action.

        Parameters
        ----------
        sleep
            Set the sleep action.
        self_destruct
            Set the self_destruct action.

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        """
        if not sleep and not self_destruct:
            action = 0
        elif not sleep and self_destruct:
            action = 1
        elif sleep and not self_destruct:
            action = 2
        elif sleep and self_destruct:
            raise AssertionError("Sleep and self-destruct cannot both be True")
        ret = self._zkSetBatteryVoltageAction(self._zk_ctx, action)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def set_battery_voltage_threshold(self, threshold):
        """Sets the battery voltage threshold. (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module)

        This function sets the threshold at which if the
        battery voltage falls bellow, the action set by
        set_battery_voltage_action will be carried out.
        The recommended threshold is 2.3V is assumed by default. Threshold
        must be below 2.5V.

        Parameters
        ----------
        threshold
            The threshold in Volts.

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        """
        ret = self._zkSetBatteryVoltageThreshold(self._zk_ctx, threshold)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    ###@}

    ## @name HSM CPU Temperature Monitor
    ###@{

    def set_cpu_temp_action(self, self_destruct=False):
        """Set HSM CPU temperature threshold action. (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module)

        This function specifies the action to take when the
        HSM CPU temperature falls below the threshold set by
        set_cpu_low_temp_threshold, or rises above the threshold
        set by set_cpu_high_temp_threshold. There are two
        actions to apply:
          * Do nothing
          * Self-destruct
        To remove a previously set self-destruct action, call
        this function with self_destruct=False.

        Parameters
        ----------
        self_destruct
            Set the self_destruct action.

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        """
        if self_destruct:
            action = 1
        else:
            action = 0
        ret = self._zkSetCPUTempAction(self._zk_ctx, action)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def set_cpu_low_temp_threshold(self, threshold):
        """Sets the HSM CPU low temperature threshold. (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module)

        This function sets the threshold at which if the
        on-board HSM CPU's tempreature falls below, the
        action set by set_cpu_temp_action will be carried out.
        WARNING: You can lock yourself out in dev mode if
        you set a threshold above the CPU's ambient temperature.
        The recommended setting is no more than 20C.
        If this function is never called, -10 degrees celsius is
        assumed.

        Parameters
        ----------
        threshold
            The threshold in celsius.

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        """
        ret = self._zkSetCPULowTempThreshold(self._zk_ctx, threshold)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def set_cpu_high_temp_threshold(self, threshold):
        """Sets the HSM CPU high temperature threshold. (Supported Devices: ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module)

        This function sets the threshold at which if the
        on-board HSM CPU's tempreature rises above, the
        action set by set_cpu_temp_action will be carried out.
        WARNING: You can lock yourself out in dev mode if
        you set a threshold below the CPU's ambient temperature.
        The recommended setting is no less than 40C.
        If this function is never called, 65 degrees celsius is
        assumed.

        Parameters
        ----------
        threshold
            The threshold in celsius.

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        """
        ret = self._zkSetCPUHighTempThreshold(self._zk_ctx, threshold)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def set_supervised_boot_policy(self, policy_id : int = 0):
        """Sets the Supervised boot policy. (Supported Devices: Secure Compute Module)

        This function sets the action policy to take when
        Supervised boot detects a file change during the boot process.

        Parameters
        ----------
        policy_id
            The actions to apply to the Supervised boot process:
            - 0 Do Nothing
            - 1 Self-Destruct
            - 2 Hold Chip in Reset

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        """
        ret = self._zkSetSupervisedBootPolicy(self._zk_ctx, policy_id)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def add_or_update_supervised_boot_file(self, filepath : str = "", slot : int = 15):
        """Update file manifest for Supervised boot to check. (Supported Devices: Secure Compute Module)

        This function adds or updates a file in the file manifest to
        be checked by Supervised during the boot process.

        Parameters
        ----------
        slot
            The slot to sign the file with.
        filepath
            The file to be signed and checked by Supervised boot.

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        """
        file_path = filepath.encode("utf-8")
        ret = self._zkAddOrUpdateSupervisedBootFile(self._zk_ctx, file_path, slot)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def remove_supervised_boot_file(self, filepath : str = ""):
        """Remove a file from file manifest for Supervised boot to check. (Supported Devices: Secure Compute Module)

        This function removes a file in the file manifest to
        be checked by Supervised boot during the boot process.

        Parameters
        ----------
        filepath
            The file to be removed from the manifest.

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        """
        file_path = filepath.encode("utf-8")
        ret = self._zkRemoveSupervisedBootFile(self._zk_ctx, file_path)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

    def get_supervised_boot_file_manifest(self):
        """Get the file manifest for Supervised boot to check. (Supported Devices: Secure Compute Module)

        This function gets a list of the files that are checked
        by Supervised boot during the boot process.

        Returns
        -------
        TYPE
            0 for success, less than 0 for failure.
        TYPE
            File manifest to be checked by Supervised boot.
        """
        manifest = c_void_p()

        manifest_ptr = byref(manifest)

        ret = self._zkGetSupervisedBootFileManifest(self._zk_ctx, manifest_ptr)
        if ret < 0:
            raise AssertionError("bad return code %d" % ret)

        manifest_str = cast(manifest, c_char_p)

        return manifest_str.value.decode("utf-8")

    ###@}

    # Interfaces to the C library
    _zkOpen = zkalib.zkOpen
    _zkOpen.restype = c_int
    _zkOpen.argtypes = [POINTER(c_void_p)]

    _zkClose = zkalib.zkClose
    _zkClose.restype = c_int
    _zkClose.argtypes = [c_void_p]

    _zkLEDOn = zkalib.zkLEDOn
    _zkLEDOn.restype = c_int
    _zkLEDOn.argtypes = [c_void_p]

    _zkLEDOff = zkalib.zkLEDOff
    _zkLEDOff.restype = c_int
    _zkLEDOff.argtypes = [c_void_p]

    _zkLEDFlash = zkalib.zkLEDFlash
    _zkLEDFlash.restype = c_int
    _zkLEDFlash.argtypes = [c_void_p, c_ulong, c_ulong, c_ulong]

    _zkGetRandBytes = zkalib.zkGetRandBytes
    _zkGetRandBytes.restype = c_int
    _zkGetRandBytes.argtypes = [c_void_p, POINTER(c_void_p), c_int]

    _zkCreateRandDataFile = zkalib.zkCreateRandDataFile
    _zkCreateRandDataFile.restype = c_int
    _zkCreateRandDataFile.argtypes = [c_void_p, c_char_p, c_int]

    _zkLockDataF2F = zkalib.zkLockDataF2F
    _zkLockDataF2F.restype = c_int
    _zkLockDataF2F.argtypes = [c_void_p, c_char_p, c_char_p, c_bool]

    _zkLockDataB2F = zkalib.zkLockDataB2F
    _zkLockDataB2F.restype = c_int
    _zkLockDataB2F.argtypes = [c_void_p, c_void_p, c_int, c_char_p, c_bool]

    _zkLockDataF2B = zkalib.zkLockDataF2B
    _zkLockDataF2B.restype = c_int
    _zkLockDataF2B.argtypes = [
        c_void_p,
        c_char_p,
        POINTER(c_void_p),
        POINTER(c_int),
        c_bool,
    ]

    _zkLockDataB2B = zkalib.zkLockDataB2B
    _zkLockDataB2B.restype = c_int
    _zkLockDataB2B.argtypes = [
        c_void_p,
        c_void_p,
        c_int,
        POINTER(c_void_p),
        POINTER(c_int),
        c_bool,
    ]

    _zkUnlockDataF2F = zkalib.zkUnlockDataF2F
    _zkUnlockDataF2F.restype = c_int
    _zkUnlockDataF2F.argtypes = [c_void_p, c_char_p, c_char_p, c_bool]

    _zkUnlockDataB2F = zkalib.zkUnlockDataB2F
    _zkUnlockDataB2F.restype = c_int
    _zkUnlockDataB2F.argtypes = [c_void_p, c_void_p, c_int, c_char_p, c_bool]

    _zkUnlockDataF2B = zkalib.zkUnlockDataF2B
    _zkUnlockDataF2B.restype = c_int
    _zkUnlockDataF2B.argtypes = [
        c_void_p,
        c_char_p,
        POINTER(c_void_p),
        POINTER(c_int),
        c_bool,
    ]

    _zkUnlockDataB2B = zkalib.zkUnlockDataB2B
    _zkUnlockDataB2B.restype = c_int
    _zkUnlockDataB2B.argtypes = [
        c_void_p,
        c_void_p,
        c_int,
        POINTER(c_void_p),
        POINTER(c_int),
        c_bool,
    ]

    _zkGenECDSASigFromDigest = zkalib.zkGenECDSASigFromDigest
    _zkGenECDSASigFromDigest.restype = c_int
    _zkGenECDSASigFromDigest.argtypes = [
        c_void_p,
        c_void_p,
        c_int,
        POINTER(c_void_p),
        POINTER(c_int),
    ]

    _zkGenECDSASigFromDigestWithRecID = zkalib.zkGenECDSASigFromDigestWithRecID
    _zkGenECDSASigFromDigestWithRecID.restype = c_int
    _zkGenECDSASigFromDigestWithRecID.argtypes = [
        c_void_p,
        c_void_p,
        c_int,
        POINTER(c_void_p),
        POINTER(c_int),
        POINTER(c_uint),
    ]

    _zkVerifyECDSASigFromDigest = zkalib.zkVerifyECDSASigFromDigest
    _zkVerifyECDSASigFromDigest.rettype = c_int
    _zkVerifyECDSASigFromDigest.argtypes = [c_void_p, c_void_p, c_int, c_void_p, c_int]

    try:
        _zkVerifyECDSASigFromDigestWithForeignKeySlot = (
            zkalib.zkVerifyECDSASigFromDigestWithForeignKeySlot
        )
        _zkVerifyECDSASigFromDigestWithForeignKeySlot.rettype = c_int
        _zkVerifyECDSASigFromDigestWithForeignKeySlot.argtypes = [
            c_void_p,
            c_void_p,
            c_int,
            c_void_p,
            c_int,
        ]

        _zkStoreForeignPubKey = zkalib.zkStoreForeignPubKey
        _zkStoreForeignPubKey.restype = c_int
        _zkStoreForeignPubKey.argtypes = [c_void_p, c_int, c_void_p, c_int]

        _zkDisablePubKeyExport = zkalib.zkDisablePubKeyExport
        _zkDisablePubKeyExport.restype = c_int
        _zkDisablePubKeyExport.argtypes = [c_void_p, c_int, c_bool]

        _zkGenKeyPair = zkalib.zkGenKeyPair
        _zkGenKeyPair.restype = c_int
        _zkGenKeyPair.argtypes = [c_void_p, c_int]

        _zkGenEphemeralKeyPair = zkalib.zkGenEphemeralKeyPair
        _zkGenEphemeralKeyPair.restype = c_int
        _zkGenEphemeralKeyPair.argtypes = [c_void_p, c_int]

        _zkRemoveKey = zkalib.zkRemoveKey
        _zkRemoveKey.restype = c_int
        _zkRemoveKey.argtypes = [c_void_p, c_int, c_bool]

        _zkInvalidateEphemeralKey = zkalib.zkInvalidateEphemeralKey
        _zkInvalidateEphemeralKey.restype = c_int
        _zkInvalidateEphemeralKey.argtypes = [c_void_p]

        _zkDoRawECDH = zkalib.zkDoRawECDH
        _zkDoRawECDH.restype = c_int
        _zkDoRawECDH.argtypes = [c_void_p, c_int, c_void_p, c_int, POINTER(c_void_p)]

        _zkDoRawECDHWithIntPeerPubkey = zkalib.zkDoRawECDHWithIntPeerPubkey
        _zkDoRawECDHWithIntPeerPubkey.restype = c_int
        _zkDoRawECDHWithIntPeerPubkey.argtypes = [
            c_void_p,
            c_int,
            c_int,
            c_bool,
            POINTER(c_void_p),
        ]

        _zkDoECDHAndKDF = zkalib.zkDoECDHAndKDF
        _zkDoECDHAndKDF.restype = c_int
        _zkDoECDHAndKDF.argtypes = [
            c_void_p,
            c_int,
            c_int,
            c_void_p,
            c_int,
            c_void_p,
            c_int,
            c_void_p,
            c_int,
            c_int,
            c_int,
            POINTER(c_void_p),
        ]

        _zkDoECDHAndKDFWithIntPeerPubkey = zkalib.zkDoECDHAndKDFWithIntPeerPubkey
        _zkDoECDHAndKDFWithIntPeerPubkey.restype = c_int
        _zkDoECDHAndKDFWithIntPeerPubkey.argtypes = [
            c_void_p,
            c_int,
            c_int,
            c_int,
            c_bool,
            c_void_p,
            c_int,
            c_void_p,
            c_int,
            c_int,
            c_int,
            POINTER(c_void_p),
        ]

        _zkGenWalletMasterSeed = zkalib.zkGenWalletMasterSeedWithBIP39
        _zkGenWalletMasterSeed.restype = c_int
        _zkGenWalletMasterSeed.argtypes = [
            c_void_p,
            c_int,
            c_char_p,
            c_char_p,
            c_void_p,
            c_int,
            c_char_p,
            POINTER(c_void_p),
        ]

        _zkOpenGenSLIP39Session = zkalib.zkGenWalletMasterSeedWithSLIP39
        _zkOpenGenSLIP39Session.restype = c_int
        _zkOpenGenSLIP39Session.argtypes = [
            c_void_p,
            c_int,
            c_char_p,
            c_char_p,
            c_void_p,
            c_int,
            c_int,
            c_int,
            c_int,
            c_char_p,
        ]

        _zkSetSLIP39GroupInfo = zkalib.zkSetSLIP39GroupInfo
        _zkSetSLIP39GroupInfo.restype = c_int
        _zkSetSLIP39GroupInfo.argtypes = [
            c_void_p,
            c_int,
            c_int,
            c_int,
        ]

        _zkAddSLIP39Member = zkalib.zkAddSLIP39MemberPassword
        _zkAddSLIP39Member.restype = c_int
        _zkAddSLIP39Member.argtypes = [
            c_void_p,
            c_char_p,
            POINTER(c_void_p),
        ]

        _zkCancelSLIP39Session = zkalib.zkCancelSLIP39Session
        _zkCancelSLIP39Session.restype = c_int
        _zkCancelSLIP39Session.argtypes = [
            c_void_p,
        ]

        _zkGenOversightWallet = zkalib.zkGenOversightWallet
        _zkGenOversightWallet.restype = c_int
        _zkGenOversightWallet.argtypes = [
            c_void_p,
            c_int,
            c_char_p,
            c_void_p,
            c_void_p,
            c_char_p,
            c_char_p,
        ]

        _zkRestoreWalletMasterSeedFromBIP39Mnemonic = (
            zkalib.zkRestoreWalletMasterSeedFromBIP39Mnemonic
        )
        _zkRestoreWalletMasterSeedFromBIP39Mnemonic.restype = c_int
        _zkRestoreWalletMasterSeedFromBIP39Mnemonic.argtypes = [
            c_void_p,
            c_int,
            c_char_p,
            c_char_p,
            c_void_p,
            c_int,
            c_char_p,
            c_char_p,
        ]

        _zkAddRestoreSLIP39Mnemonic = zkalib.zkAddRestoreSLIP39Mnemonic
        _zkAddRestoreSLIP39Mnemonic.restype = c_int
        _zkAddRestoreSLIP39Mnemonic.argtypes = [
            c_void_p,
            c_char_p,
            c_char_p,
        ]

        _zkOpenRestoreSLIP39Session = (
            zkalib.zkRestoreWalletMasterSeedFromSLIP39
        )
        _zkOpenRestoreSLIP39Session.restype = c_int
        _zkOpenRestoreSLIP39Session.argtypes = [
            c_void_p,
            c_int,
            c_char_p,
            c_char_p,
            c_void_p,
            c_int,
            c_char_p,
        ]

        _zkGenWalletChildKey = zkalib.zkGenWalletChildKey
        _zkGenWalletChildKey.restype = c_int
        _zkGenWalletChildKey.argtypes = [c_void_p, c_int, c_uint, c_bool, c_bool, POINTER(c_void_p)]

        _zkGetWalletNodeAddrFromKeySlot = zkalib.zkGetWalletNodeAddrFromKeySlot
        _zkGetWalletNodeAddrFromKeySlot.restype = c_int
        _zkGetWalletNodeAddrFromKeySlot.argtypes = [
            c_void_p,
            c_int,
            POINTER(c_void_p),
            POINTER(c_void_p),
            POINTER(c_int),
        ]

        _zkGetWalletKeySlotFromNodeAddr = zkalib.zkGetWalletKeySlotFromNodeAddr
        _zkGetWalletKeySlotFromNodeAddr.restype = c_int
        _zkGetWalletKeySlotFromNodeAddr.argtypes = [
            c_void_p,
            c_char_p,
            c_char_p,
            c_int,
            POINTER(c_int),
        ]

        _zkGetAllocSlotsList = zkalib.zkGetAllocSlotsList
        _zkGetAllocSlotsList.restype = c_int
        _zkGetAllocSlotsList.argtypes = [
            c_void_p,
            c_bool,
            POINTER(c_int),
            POINTER(c_void_p),
            POINTER(c_int),
        ]

        _zkExportPubKey2File = zkalib.zkExportPubKey2File
        _zkExportPubKey2File.restype = c_int
        _zkExportPubKey2File.argtypes = [c_void_p, c_char_p, c_int, c_bool]

        _zkExportPubKey = zkalib.zkExportPubKey
        _zkExportPubKey.restype = c_int
        _zkExportPubKey.argtypes = [
            c_void_p,
            POINTER(c_void_p),
            POINTER(c_int),
            c_int,
            c_bool,
        ]

        _zkLockBinding = zkalib.zkLockBinding
        _zkLockBinding.restype = c_int
        _zkLockBinding.argtypes = [c_void_p]

        _zkGetCurrentBindingInfo = zkalib.zkGetCurrentBindingInfo
        _zkGetCurrentBindingInfo.restype = c_int
        _zkGetCurrentBindingInfo.argtypes = [c_void_p, POINTER(c_bool), POINTER(c_bool)]

        _zkGetCPUTemp = zkalib.zkGetCPUTemp
        _zkGetCPUTemp.restype = c_int
        _zkGetCPUTemp.argtypes = [c_void_p, POINTER(c_float)]

        _zkGetAUXTemp = zkalib.zkGetAUXTemp
        _zkGetAUXTemp.restype = c_int
        _zkGetAUXTemp.argtypes = [c_void_p, c_int, POINTER(c_float)]

        _zkGetRTCDrift = zkalib.zkGetRTCDrift
        _zkGetRTCDrift.restype = c_int
        _zkGetRTCDrift.argtypes = [c_void_p, POINTER(c_float)]

        _zkGetBatteryVoltage = zkalib.zkGetBatteryVoltage
        _zkGetBatteryVoltage.restype = c_int
        _zkGetBatteryVoltage.argtypes = [c_void_p, POINTER(c_float)]

        _zkSetDigitalPerimeterDetectLPPeriod = (
            zkalib.zkSetDigitalPerimeterDetectLPPeriod
        )
        _zkSetDigitalPerimeterDetectLPPeriod.restype = c_int
        _zkSetDigitalPerimeterDetectLPPeriod.argtypes = [c_void_p, c_int]

        _zkSetDigitalPerimeterDetectLPMaxBits = (
            zkalib.zkSetDigitalPerimeterDetectLPMaxBits
        )
        _zkSetDigitalPerimeterDetectLPMaxBits.restype = c_int
        _zkSetDigitalPerimeterDetectLPMaxBits.argtypes = [c_void_p, c_int]

        _zkSetDigitalPerimeterDetectDelays = zkalib.zkSetDigitalPerimeterDetectDelays
        _zkSetDigitalPerimeterDetectDelays.restype = c_int
        _zkSetDigitalPerimeterDetectDelays.argtypes = [c_void_p, c_int, c_int]

        _zkSetBatteryVoltageAction = zkalib.zkSetBatteryVoltageAction
        _zkSetBatteryVoltageAction.restype = c_int
        _zkSetBatteryVoltageAction.argtypes = [c_void_p, c_int]

        _zkSetBatteryVoltageThreshold = zkalib.zkSetBatteryVoltageThreshold
        _zkSetBatteryVoltageThreshold.restype = c_int
        _zkSetBatteryVoltageThreshold.argtypes = [c_void_p, c_float]

        _zkSetCPUTempAction = zkalib.zkSetCPUTempAction
        _zkSetCPUTempAction.restype = c_int
        _zkSetCPUTempAction.argtypes = [c_void_p, c_int]

        _zkSetCPULowTempThreshold = zkalib.zkSetCPULowTempThreshold
        _zkSetCPULowTempThreshold.restype = c_int
        _zkSetCPULowTempThreshold.argtypes = [c_void_p, c_float]

        _zkSetCPUHighTempThreshold = zkalib.zkSetCPUHighTempThreshold
        _zkSetCPUHighTempThreshold.restype = c_int
        _zkSetCPUHighTempThreshold.argtypes = [c_void_p, c_float]

        _zkSetSupervisedBootPolicy = zkalib.zkSetSupervisedBootPolicy
        _zkSetSupervisedBootPolicy.restype = c_int
        _zkSetSupervisedBootPolicy.argtypes = [c_void_p, c_int]

        _zkAddOrUpdateSupervisedBootFile = zkalib.zkAddOrUpdateSupervisedBootFile
        _zkAddOrUpdateSupervisedBootFile.restype = c_int
        _zkAddOrUpdateSupervisedBootFile.argtypes = [c_void_p, c_char_p, c_int]

        _zkRemoveSupervisedBootFile = zkalib.zkRemoveSupervisedBootFile
        _zkRemoveSupervisedBootFile.restype = c_int
        _zkRemoveSupervisedBootFile.argtypes = [c_void_p, c_char_p]

        _zkGetSupervisedBootFileManifest = zkalib.zkGetSupervisedBootFileManifest
        _zkGetSupervisedBootFileManifest.restype = c_int
        _zkGetSupervisedBootFileManifest.argtypes = [c_void_p, POINTER(c_void_p)]
    except:
        pass

    _zkGetECDSAPubKey = zkalib.zkGetECDSAPubKey
    _zkGetECDSAPubKey.restype = c_int
    _zkGetECDSAPubKey.argtypes = [c_void_p, POINTER(c_void_p), POINTER(c_int), c_int]

    _zkSaveECDSAPubKey2File = zkalib.zkSaveECDSAPubKey2File
    _zkSaveECDSAPubKey2File.restype = c_int
    _zkSaveECDSAPubKey2File.argtypes = [c_void_p, c_char_p, c_int]

    _zkSetI2CAddr = zkalib.zkSetI2CAddr
    _zkSetI2CAddr.restype = c_int
    _zkSetI2CAddr.argtypes = [c_void_p, c_int]

    _zkSetTapSensitivity = zkalib.zkSetTapSensitivity
    _zkSetTapSensitivity.restype = c_int
    _zkSetTapSensitivity.argtypes = [c_void_p, c_int, c_float]

    _zkGetTime = zkalib.zkGetTime
    _zkGetTime.restype = c_int
    _zkGetTime.argtypes = [c_void_p, POINTER(c_int), c_bool]

    _zkWaitForTap = zkalib.zkWaitForTap
    _zkWaitForTap.restype = c_int
    _zkWaitForTap.argtypes = [c_void_p, c_int]

    _zkGetAccelerometerData = zkalib.zkGetAccelerometerData
    _zkGetAccelerometerData.restype = c_int
    _zkGetAccelerometerData.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]

    _zkWaitForPerimeterEvent = zkalib.zkWaitForPerimeterEvent
    _zkWaitForPerimeterEvent.restype = c_int
    _zkWaitForPerimeterEvent.argtypes = [c_void_p, c_int]

    _zkGetPerimeterDetectInfo = zkalib.zkGetPerimeterDetectInfo
    _zkGetPerimeterDetectInfo.restype = c_int
    _zkGetPerimeterDetectInfo.argtypes = [c_void_p, POINTER(c_void_p), POINTER(c_int)]

    _zkClearPerimeterDetectEvents = zkalib.zkClearPerimeterDetectEvents
    _zkClearPerimeterDetectEvents.restype = c_int
    _zkClearPerimeterDetectEvents.argtypes = [c_void_p]

    _zkSetPerimeterEventAction = zkalib.zkSetPerimeterEventAction
    _zkSetPerimeterEventAction.restype = c_int
    _zkSetPerimeterEventAction.argtypes = [c_void_p, c_int, c_int]

    _zkGetModelNumberString = zkalib.zkGetModelNumberString
    _zkGetModelNumberString.restype = c_int
    _zkGetModelNumberString.argtypes = [c_void_p, POINTER(c_void_p)]

    _zkGetFirmwareVersionString = zkalib.zkGetFirmwareVersionString
    _zkGetFirmwareVersionString.restype = c_int
    _zkGetFirmwareVersionString.argtypes = [c_void_p, POINTER(c_void_p)]

    _zkGetSerialNumberString = zkalib.zkGetSerialNumberString
    _zkGetSerialNumberString.restype = c_int
    _zkGetSerialNumberString.argtypes = [c_void_p, POINTER(c_void_p)]


client: t.Optional[Zymkey]
try:
    client = Zymkey()
except AssertionError:
    client = None
    pass


def create_new_client():
    try:
        new_client = Zymkey()
    except AssertionError:
        new_client = None
    return new_client
