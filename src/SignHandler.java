import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * Sign the file 'data' with (the private) key in 'keystore' under the name 'alias'.
 * Save/write a certificate (holding the public key) in the file 'certificate'.
 * Save/write the signature in the file 'signature'.
 * The sender can then send the tiles 'data', 'signature' and 'certificate' to the receiver for verification.
 * In short: the files certificate & signature will be created.
 */
// in terminal: java SignHandler keystore keystore_password alias key_password data certificate signature
public class SignHandler {

    public static void main(String[] args) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, SignatureException {

        String keyStoreName = args[0];        // "keystore";
        String alias = args[1];               // "alias"
        String storepass  = args[2];          // "keystore_password"
        String keypass = args[3];             // "key_password"
        String data = args[4];                // "data"
        String certificate  = args[5];        // "certificate"
        String signatureFileName  = args[6];  // "signature"

        KeyStoreHandler keyStoreHandler = new KeyStoreHandler();

        // Connect/read key store to application.
        KeyStore keyStore = keyStoreHandler.getKeyStore(keyStoreName, storepass);

        // Fetch private key from key store.
        PrivateKey privateKey = keyStoreHandler.getPrivateKey(keyStore, alias, keypass);

        // Generate signature with private key.
        Signature signature = keyStoreHandler.generateSignature(privateKey);

        // Sign file 'data' with signature. byte[] of signed data returned.
        byte[] signedData = keyStoreHandler.signData(data, signature);

        // Fetch (public key) certificate from key store. byte[] of encoded certificate returned.
        byte[] encodedCertificate = keyStoreHandler.getCertificate(keyStore, alias);

        // Write certificate containing public key to file 'certificate'.
        keyStoreHandler.writeCertificateToFile(certificate, encodedCertificate);

        // Write signature bytes to file 'signature'.
        keyStoreHandler.writeSignatureToFile(signatureFileName, signedData);
    }
}
