package DigitalSigniture;

import java.nio.charset.StandardCharsets;
import java.security.*;

public class DSATools {

    private Signature signature;
    private KeyPairGenerator pairGenerator;
    private SecureRandom secureRandom;
    private KeyPair keyPair;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public DSATools() throws NoSuchAlgorithmException, InvalidKeyException {
        this.signature = Signature.getInstance("SHA256withRSA");
        this.secureRandom = new SecureRandom();
        this.pairGenerator = KeyPairGenerator.getInstance("RSA");
        this.pairGenerator.initialize(1024,this.secureRandom);
        this.keyPair = pairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
        this.signature.initSign(this.privateKey);
    }

    public final byte[] signMessage(String message) throws SignatureException {
        this.signature.update(message.getBytes(StandardCharsets.UTF_8));
        return this.signature.sign();
    }

    public final boolean verifySign(PublicKey publicKey,byte[] message,byte[] signature) throws InvalidKeyException, SignatureException {
        this.signature.initVerify(publicKey);
        this.signature.update(message);
        return this.signature.verify(signature);
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
