import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;

/**
 * Verify if the certificate (with the public key) in the file 'certificate'
 * and the signature in the file 'signature' verifies the file 'data'.
 * In short: Verify the content in 'data' with the certificate/public key and the signature.
 * A boolean verifies and prints weather verified or not.
 */
// in terminal: java VerifyHandler data certificate signature
public class VerifyHandler {

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, SignatureException, InvalidKeyException {

        String data = "data";
        String certificate = "certificate";
        String signature = "signature";

        KeyStoreHandler keyStoreHandler = new KeyStoreHandler();

        // Extract public key from certificate.
        PublicKey publicKey = keyStoreHandler.extractPublicKeyFromCertificate(certificate);

        // Read signature from 'signature' file. Signature bytes returned.
        byte[] signatureBytes = keyStoreHandler.readSignatureFromFile(signature);

        // Verify content of file 'data' with public key extracted from certificate and signature.
        keyStoreHandler.verifyContent(publicKey, data, signatureBytes);

    }

}
