# About
This project serves as an example for authenticating to the Key Vault Service using a certificate retrieved from a key vault.

## Setup

### To authenticate the client
In order to interact with the Azure Key Vault service, you'll need to create an instance of the [CertificateClient](#create-certificate-client) class. You need a **vault url** and **client secret credentials (client id, client secret, tenant id)** to instantiate a client object using the `ClientSecretCredential` example shown in this document.

The `ClientSecretCredential` way of authentication by providing client secret credentials is being used in this getting started section, but you can find more ways to authenticate with [azure-identity][azure_identity].

#### Create/Get credentials
To create/get client secret credentials you can use the [Azure Portal][azure_create_application_in_portal], [Azure CLI][azure_keyvault_cli_full] or [Azure Cloud Shell][azure_cloud_shell]

Here is an [Azure Cloud Shell][azure_cloud_shell] snippet below to

* Create a service principal and configure its access to Azure resources:

```bash
az ad sp create-for-rbac -n <your-application-name> --skip-assignment
```

Output:

```json
{
    "appId": "generated-app-ID",
    "displayName": "my-app",
    "name": "http://my-app",
    "password": "random-password",
    "tenant": "tenant-id"
}
```

* Take note of the values returned above, it will be used to set up your `ClientSecretCredential` later.

* Grant the aforementioned application authorization to perform certificate operations on the Key Vault:

```bash
az keyvault set-policy --name <your-key-vault-name> --spn $AZURE_CLIENT_ID --certificate-permissions backup delete get list create update
```

> --certificate-permissions:
> Accepted values: backup, create, delete, deleteissuers, get, getissuers, import, list, listissuers, managecontacts, manageissuers, purge, recover, restore, setissuers, update

If you have enabled role-based access control (RBAC) for Key Vault instead, you can find roles like "Key Vault Certificates Officer" in our [RBAC guide][rbac_guide].

* Use the aforementioned Key Vault name to retrieve details of your Key Vault, which also contain your Key Vault URL:

```bash
az keyvault show --name <your-key-vault-name>
```

#### Create certificate client
Once you've populated the **AZURE_CLIENT_ID**, **AZURE_CLIENT_SECRET**, and **AZURE_TENANT_ID** environment variables and replaced **your-key-vault-url** with the URI returned above, you can create the CertificateClient:

```java
TokenCredential clientSecretCredential = new ClientSecretCredentialBuilder()
    .clientId("<client-id>")
    .clientSecret("<client-secret>")
    .tenantId("<tenant-id>")
    .build();

CertificateClient certificateClient = new CertificateClientBuilder()
    .vaultUrl("<your-key-vault-url>")
    .credential(clientSecretCredential)
    .buildClient();
```

<!-- LINKS -->
[azure_identity]: https://github.com/Azure/azure-sdk-for-java/tree/main/sdk/identity/azure-identity
[azure_create_application_in_portal]: https://docs.microsoft.com/azure/active-directory/develop/howto-create-service-principal-portal
[azure_keyvault_cli_full]: https://docs.microsoft.com/cli/azure/keyvault?view=azure-cli-latest
[azure_cloud_shell]: https://shell.azure.com/bash