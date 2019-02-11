
# Project Name

Encryption of Blobs using Key Vault Python SDK

## Features

* This sample shows you how to use Client side encryption of Azure blobs protected by a AES key stored in keyvault

### Quickstart
(Add steps to get up and running quickly)

1. git clone https://github.com/Azure-Samples/key-vault-python-client-side-encryption.git
2. cd key-vault-python-client-side-encryption
3. Install requirements from requirements.txt - pip install requirements.txt
4. Open key_vault_sample_config.py and populate the required fields - PLEASE NOTE that this is a demo and we recommend you should use [Managed Identities](https://docs.microsoft.com/azure/active-directory/managed-identities-azure-resources/overview) for Authenticating to Key Vault
5. Run python blob_encryption_sample.py

## Resources

- [Azure Storage Encryption](https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption)
- [Azure Key Vault Python Libraries](https://docs.microsoft.com/en-us/python/api/overview/azure/key-vault?view=azure-python)
