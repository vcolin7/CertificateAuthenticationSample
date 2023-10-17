package com.vcolin7;

import com.azure.core.http.policy.HttpLogDetailLevel;
import com.azure.core.http.policy.HttpLogOptions;
import com.azure.identity.ClientCertificateCredential;
import com.azure.identity.ClientCertificateCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;

/**
 * This class serves as an example for authenticating to an Azure Service using a service principal that
 * authenticates using a certificate.
 */
public final class CertificateAuthentication {
    private CertificateAuthentication() {
        // Private constructor to prevent instantiation of this class.
    }

    /**
     * This application attempts to retrieve a secret from a key vault on behalf of a client that has been set
     * up on RBAC with a certificate, as opposed to a using a client secret.
     * <p>
     * See: <a href="https://learn.microsoft.com/azure/developer/java/sdk/identity-service-principal-auth">Azure authentication with service principal</a>
     *
     * @param args Unused. Arguments to the program.
     */
    public static void main(String[] args) {
        // Replace this value with the endpoint for the Key Vault where the certificate is stored.
        String vaultUrl = "<key-vault-url>";

        // Adding log options to see what happens with each HTTP call.
        HttpLogOptions httpLogOptions = new HttpLogOptions()
            .setLogLevel(HttpLogDetailLevel.BODY_AND_HEADERS);

        // Let's authenticate our service principal with a ClientCertificateCredential that uses the certificate we
        // created for it originally.
        ClientCertificateCredential clientCertificateCredential = new ClientCertificateCredentialBuilder()
            .clientId("<client-id>")
            .tenantId("<tenant-id>")
            .pfxCertificate("<certificate-path>", null)
            .build();

        SecretClient secretClient = new SecretClientBuilder()
            .vaultUrl(vaultUrl)
            .credential(clientCertificateCredential)
            .httpLogOptions(httpLogOptions)
            .buildClient();

        // Retrieve a secret from our key vault.
        KeyVaultSecret myCertificate = secretClient.getSecret("mySecret");

        System.out.println("Success! Retrieved certificate with name: " + myCertificate.getName());
    }
}
