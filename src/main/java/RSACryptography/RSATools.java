package RSACryptography;

import java.security.*;

public class RSATools {

    private KeyPairGenerator pairGenerator;
    private KeyPair keyPair;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private SecureRandom secureRandom;

    public RSATools() throws NoSuchAlgorithmException {
        this.pairGenerator = KeyPairGenerator.getInstance("RSA");
        this.secureRandom = new SecureRandom();
        this.pairGenerator.initialize(1024,this.secureRandom);
        this.keyPair = pairGenerator.generateKeyPair();
        this.generateKeys();
    }

    public PublicKey getPublicKey(){
        return this.keyPair.getPublic();
    }

    public PrivateKey getPrivateKey(){
        return this.keyPair.getPrivate();
    }

    private void generateKeys(){
        this.publicKey = this.keyPair.getPublic();
        this.privateKey = this.keyPair.getPrivate();
    }

}
