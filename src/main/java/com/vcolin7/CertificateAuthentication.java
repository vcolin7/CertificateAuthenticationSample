package com.vcolin7;

import com.azure.core.credential.TokenCredential;
import com.azure.core.http.policy.HttpLogDetailLevel;
import com.azure.core.http.policy.HttpLogOptions;
import com.azure.core.util.Base64Util;
import com.azure.identity.ClientCertificateCredential;
import com.azure.identity.ClientCertificateCredentialBuilder;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.CertificateClientBuilder;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificate;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificateWithPolicy;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

/**
 * This class serves as an example for authenticating to an Azure Service using a certificate retrieved from a key
 * vault.
 */
public final class CertificateAuthentication {
    private CertificateAuthentication() {
        // Private constructor to prevent instantiation of this class.
    }

    /**
     * This application retrieves a certificate that will be used to authenticate to Key Vault on behalf of a client
     * that has been set up on RBAC with a certificate, as opposed to a using a client secret.
     * <p>
     * See: <a href="https://learn.microsoft.com/azure/developer/java/sdk/identity-service-principal-auth">Azure authentication with service principal</a>
     *
     * @param args Unused. Arguments to the program.
     *
     * @throws IOException If an error occurs while writing the PEM file.
     * @throws CertificateException If an error occurs while loading the certificate.
     * @throws KeyStoreException If an error occurs while loading the keystore.
     * @throws NoSuchAlgorithmException If an error occurs while loading the keystore.
     * @throws UnrecoverableKeyException If an error occurs while loading the keystore.
     */
    public static void main(String[] args) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        // The name of the certificate we want to use for authentication.
        String certificateName = "myCertificate";
        // Replace this value with the endpoint for the Key Vault where the certificate is stored.
        String vaultUrl = "<key-vault-url>";
        // My setup requires setting up a service principal with a client secret and giving it access to the key vault
        // we want to retrieve the certificate from. See:
        TokenCredential clientSecretCredential = new ClientSecretCredentialBuilder()
            .clientId("<client-id>")
            .clientSecret("<client-secret>")
            .tenantId("<tenant-id>")
            .build();
        // Adding log options to see what happens with each HTTP call.
        HttpLogOptions httpLogOptions = new HttpLogOptions()
            .setLogLevel(HttpLogDetailLevel.BODY_AND_HEADERS);

        // Let's create a certificate client to get the public part of our certificate.
        CertificateClientBuilder certificateClientBuilder = new CertificateClientBuilder()
            .vaultUrl(vaultUrl)
            .credential(clientSecretCredential)
            .httpLogOptions(httpLogOptions);

        CertificateClient certificateClient = certificateClientBuilder.buildClient();

        KeyVaultCertificateWithPolicy certificate = certificateClient.getCertificate(certificateName);

        // We'll save ths value to a PEM file later.
        String certificateString = Base64Util.encodeToString(certificate.getCer());

        // Now let's create a secret client to get the private key used to sign our certificate.
        SecretClient secretClient = new SecretClientBuilder()
            .vaultUrl(vaultUrl)
            .credential(clientSecretCredential)
            .httpLogOptions(httpLogOptions)
            .buildClient();

        KeyVaultSecret privateKey = secretClient.getSecret(certificateName);

        // The location where we'll save our certificate and private key as a PEM file.
        String certificatePath = "src/main/resources/myCertificate.pem";

        // Remember to decode the private key to using base64 to ensure it's in the correct format.
        try (InputStream certIs = new ByteArrayInputStream(Base64Util.decodeString(privateKey.getValue()))) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(certIs, null);
            String alias = null;

            // The keystore will only have one entry for our private key, so we'll iterate to get to that element.
            if (keyStore.aliases().hasMoreElements()) {
                alias = keyStore.aliases().nextElement();
            }

            // The password for the private key should be an empty string since we did not set it when creating our
            // certificate. We cannot use 'null' as it will cause an exception to be thrown.
            Key key = keyStore.getKey(alias, "".toCharArray());
            // We'll save this value to the PEM file as well.
            String keyString = Base64Util.encodeToString(key.getEncoded());

            // Let's create the file.
            writePemCertificate(certificateString, keyString, certificatePath);
        }

        // Let's authenticate with the certificate we just created by creating a new ClientCertificateCredential.
        ClientCertificateCredential clientCertificateCredential = new ClientCertificateCredentialBuilder()
            .clientId("<client-id>")
            .tenantId("<tenant-id>")
            .pemCertificate(certificatePath)
            .build();

        // Now we'll create a new certificate client using our new credential and the client builder we created earlier.
        CertificateClient otherCertificateClient = certificateClientBuilder
            .credential(clientCertificateCredential)
            .buildClient();

        // Retrieve the same certificate we did earlier, this time authenticating with our client id and certificate
        // instead of client id and client secret.
        KeyVaultCertificate myCertificate = otherCertificateClient.getCertificate(certificateName);

        System.out.println("Success! Retrieved certificate with name: " + myCertificate.getName());
    }

    /**
     * Creates a PEM file with a certificate and private key.
     *
     * @param certificate  The certificate to write to the file.
     * @param privateKey  The private key to write to the file.
     * @param certificatePath The path to the file to write.
     *
     * @throws IOException If an error occurs while writing the file.
     */
    public static void writePemCertificate(String certificate, String privateKey, String certificatePath) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN CERTIFICATE-----\n");
        sb.append(certificate);
        sb.append("\n");
        sb.append("-----END CERTIFICATE-----\n");
        sb.append("-----BEGIN PRIVATE KEY-----\n");
        sb.append(privateKey);
        sb.append("\n");
        sb.append("-----END PRIVATE KEY-----\n");

        // From https://www.genuitec.com/dump-a-stringbuilder-to-file/. It's just a more efficient way to write a file.
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(certificatePath))) {
            final int aLength = sb.length();
            final int aChunk = 1024; // 1 kb buffer to read data from
            final char[] aChars = new char[aChunk];

            for (int aPosStart = 0; aPosStart < aLength; aPosStart += aChunk) {
                final int aPosEnd = Math.min(aPosStart + aChunk, aLength);
                sb.getChars(aPosStart, aPosEnd, aChars, 0); // Create no new buffer
                bw.write(aChars, 0, aPosEnd - aPosStart); // This is faster than just copying one byte at the time
            }

            bw.flush();
        }
    }
}
