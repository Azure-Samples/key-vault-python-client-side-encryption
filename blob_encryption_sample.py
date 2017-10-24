# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
# This script expects that the following environment vars are set, or they can be hardcoded in key_vault_sample_config, these values
# SHOULD NOT be hardcoded in any code derived from this sample:
#
# AZURE_TENANT_ID: with your Azure Active Directory tenant id or domain
# AZURE_CLIENT_ID: with your Azure Active Directory Service Principal AppId
# AZURE_CLIENT_OID: with your Azure Active Directory Service Principle Object ID
# AZURE_CLIENT_SECRET: with your Azure Active Directory Application Key
# AZURE_SUBSCRIPTION_ID: with your Azure Subscription Id
# AZURE_STORAGE_ACCOUNT_NAME: with your storage account name
# AZURE_STORAGE_ACCOUNT_KEY: with your storage account key
#
# These are read from the environment and exposed through the KeyVaultSampleConfig class. For more information please
# see the implementation in key_vault_sample_config.py


from key_vault_sample_base import KeyVaultSampleBase, keyvaultsample, run_all_samples
from azure.keyvault import SecretId, KeyId
from os import urandom
import uuid

from cryptography.hazmat.primitives.keywrap import(
    aes_key_wrap,
    aes_key_unwrap,
)
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode

# Sample implementations of the encryption-related interfaces.

class AESKeyWrapper:
    """
    AESKeyWrapper implements the key encryption key interface outlined in the create_blob_from_* documentation 
    """
    def __init__(self, kid, kek):
        self.kek = kek
        self.backend = default_backend()
        self.kid = kid

    def wrap_key(self, key, algorithm='A256KW'):
        if algorithm == 'A256KW':
            return aes_key_wrap(self.kek, key, self.backend)
        else:
            raise ValueError('Unknown key wrap algorithm')

    def unwrap_key(self, key, algorithm):
        if algorithm == 'A256KW':
            return aes_key_unwrap(self.kek, key, self.backend)
        else:
            raise ValueError('Unknown key wrap algorithm')

    def get_key_wrap_algorithm(self):
        return 'A256KW'

    def get_kid(self):
        return self.kid


class KeyVaultAESKeyResolver:
    """
    KeyVaultAESKeyResolver provides a sample implementation of the key_resolver_function used by blob clients
    """
    def __init__(self, key_vault_client):
        self.keys = {}
        self.client = key_vault_client

    def resolve_key(self, kid):
        if kid in self.keys:
            key = self.keys[kid]
        else:
            sid = SecretId(kid)
            secret_bundle = self.client.get_secret(sid.vault, sid.name, sid.version)
            key = AESKeyWrapper(secret_bundle.id, kek=b64decode(secret_bundle.value))
            self.keys[secret_bundle.id] = key
        return key


class BlobEncryptionSample(KeyVaultSampleBase):
    """
    A collection of samples that demonstrate client side encryption for blob storage using a Key Encryption Key stored in keyvault 
    """

    @keyvaultsample
    def put_get_encrypted_blob_aes_secret_kek(self):
        """
        stores a AES key encryption key in key vault and utilizes that key for client side storage encryption
        """

        container_name = self._create_container()
        block_blob_name = self._get_blob_reference(prefix='block_blob')

        # create a vault where the storage KEK will be stored generate a
        # kek suitable for AES key wrap and store it as a base64 string
        #  secret in the vault
        vault = self.create_vault()
        kek = urandom(32)
        secret = self.keyvault_data_client.set_secret(vault_base_url=vault.properties.vault_uri,
                                                      secret_name='storage-sample-KEK',
                                                      value=b64encode(kek).decode())

        # AESKeyWrapper implements the key encryption key interface outlined
        # in the create_blob_from_* documentation on each service. Setting
        # this property will tell the service to encrypt the blob. Blob encryption
        # is supported only for uploading whole blobs and only at the time of creation.
        key_resolver = KeyVaultAESKeyResolver(self.keyvault_data_client)
        key_wrapper = key_resolver.resolve_key(kid=secret.id)
        self.block_blob_service.key_encryption_key = key_wrapper

        # store encrypted data
        data = urandom(13 * self.block_blob_service.MAX_SINGLE_PUT_SIZE + 1)
        self.block_blob_service.create_blob_from_bytes(container_name, block_blob_name, data)

        # Setting the key_resolver_function will tell the service to automatically
        # try to decrypt retrieved blobs. The key_resolver is a function that
        # takes in a key_id and returns a corresponding key_encryption_key.
        self.block_blob_service.key_resolver_function = key_resolver.resolve_key

        # Downloading works as usual with support for decrypting both entire blobs
        # and decrypting range gets.
        blob_full = self.block_blob_service.get_blob_to_bytes(container_name, block_blob_name)
        blob_range = self.block_blob_service.get_blob_to_bytes(container_name, block_blob_name,
                                                start_range=len(data)//2 + 5,
                                                end_range=(3*len(data)//4) + 1)

        self.block_blob_service.delete_container(container_name)

    @keyvaultsample
    def put_get_encrypted_blob_wrapped_aes_secret_kek(self):
        """
        wraps and stores an AES key encryption key with an key in key vault and utilizes that key for client side storage encryption
        """

        container_name = self._create_container()
        block_blob_name = self._get_blob_reference(prefix='block_blob')

        # create a vault and a key which will be used to wrap blob KEKs.
        # Note: This example uses a software basede RSA key so that it can be run on a standard vault
        # however this approach would more likely be used to wrap the KEK with hardware based
        # HSM key additional protection of the KEK
        vault = self.create_vault()
        kwk_key = self.keyvault_data_client.create_key(vault_base_url=vault.properties.vault_uri,
                                                       key_name='storage-sample-KWK',
                                                       kty='RSA')
        kwk_key_id = KeyId(kwk_key.key.kid)

        # generate a kek for blobs and wrap it using the wrapping key and store as a base64 string
        # secret in the vault. Also note the full id (including version) of the wrapping
        # key is stored as a tag on the secret to enable unwrapping even if the hsm_key is rotated
        kek = urandom(32)
        wrapped_kek = self.keyvault_data_client.wrap_key(vault_base_url=kwk_key_id.vault,
                                                         key_name=kwk_key_id.name,
                                                         key_version=kwk_key_id.version,
                                                         algorithm='RSA-OAEP-256',
                                                         value=kek).result
        secret = self.keyvault_data_client.set_secret(vault_base_url=vault.properties.vault_uri,
                                                      secret_name='storage-sample-KEK',
                                                      value=b64encode(wrapped_kek).decode(),
                                                      tags={'kwk-id': kwk_key_id.id})

        # AESKeyWrapper implements the key encryption key interface outlined
        # in the create_blob_from_* documentation on each service. Setting
        # this property will tell the service to encrypt the blob. Blob encryption
        # is supported only for uploading whole blobs and only at the time of creation.
        blob_kek = AESKeyWrapper(kid=secret.id, kek=kek)
        self.block_blob_service.key_encryption_key = blob_kek

        # store encrypted data
        data = urandom(13 * self.block_blob_service.MAX_SINGLE_PUT_SIZE + 1)
        self.block_blob_service.create_blob_from_bytes(container_name, block_blob_name, data)

        # create a method which will resolve the wrapped AES kek's stored as secrets
        # in key vault for the blob service, unwrapping them and caching them locally
        key_cache = {}

        def resolve_wrapped_aes_key_secret(kid):
            if kid in key_cache:
                key = key_cache[kid]
            else:
                sid = SecretId(kid)
                secret_bundle = self.keyvault_data_client.get_secret(sid.vault, sid.name, sid.version)
                # get the tag storing the id to the key wrapping the AES kek and unwrap the kek
                if secret_bundle.tags and 'kwk-id' in secret_bundle.tags:
                    kek_id=KeyId(secret_bundle.tags['kwk-id'])
                    kek_value = self.keyvault_data_client.unwrap_key(vault_base_url=kek_id.vault,
                                                                     key_name=kek_id.name,
                                                                     key_version=kek_id.version,
                                                                     algorithm='RSA-OAEP-256',
                                                                     value=b64decode(secret_bundle.value)).result
                else:
                    kek_value=b64decode(secret_bundle.value)
                key = AESKeyWrapper(secret_bundle.id, kek=kek_value)
                key_cache[secret_bundle.id] = key
            return key

        # Setting the key_resolver_function will tell the service to automatically
        # try to decrypt retrieved blobs. The key_resolver is a function that
        # takes in a key_id and returns a corresponding key_encryption_key.
        self.block_blob_service.key_resolver_function = resolve_wrapped_aes_key_secret

        # Downloading works as usual with support for decrypting both entire blobs
        # and decrypting range gets.
        blob_full = self.block_blob_service.get_blob_to_bytes(container_name, block_blob_name)
        blob_range = self.block_blob_service.get_blob_to_bytes(container_name, block_blob_name,
                                                               start_range=len(data) // 2 + 5,
                                                               end_range=(3 * len(data) // 4) + 1)

        self.block_blob_service.delete_container(container_name)

    def _get_resource_reference(self, prefix):
        return '{}{}'.format(prefix, str(uuid.uuid4()).replace('-', ''))

    def _get_blob_reference(self, prefix='blob'):
        return self._get_resource_reference(prefix)

    def _create_container(self, prefix='container'):
        container_name = self._get_resource_reference(prefix)
        self.block_blob_service.create_container(container_name)
        return container_name

if __name__ == "__main__":
    run_all_samples([BlobEncryptionSample()])
