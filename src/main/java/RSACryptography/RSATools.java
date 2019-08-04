package RSACryptography;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

public class RSATools {

    private KeyPairGenerator pairGenerator;
    private KeyPair keyPair;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private SecureRandom secureRandom;
    private Cipher cipher;

    public RSATools() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.pairGenerator = KeyPairGenerator.getInstance("RSA");
        this.secureRandom = new SecureRandom();
        this.pairGenerator.initialize(1024,this.secureRandom);
        this.keyPair = pairGenerator.generateKeyPair();
        this.generateKeys();
        this.cipher =  Cipher.getInstance("RSA");
    }

    public PublicKey getPublicKey(){
        return this.publicKey;
    }

    public PrivateKey getPrivateKey(){
        return this.privateKey;
    }

    private void generateKeys(){
        this.publicKey = this.keyPair.getPublic();
        this.privateKey = this.keyPair.getPrivate();
    }

    public byte[] cipherMessage(String message) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        this.cipher.init(Cipher.ENCRYPT_MODE,this.getPublicKey());
        return this.cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
    }

    public void cipherMessage(String locationFile,String outputName) throws IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String message = new String(Files.readAllBytes(Paths.get(locationFile)));
        this.cipher.init(Cipher.ENCRYPT_MODE,getPublicKey());
        byte [] secretBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        OutputStream outputStream = new FileOutputStream(outputName);
        outputStream.write(secretBytes);
        outputStream.close();
    }

    public byte[] decipherMessage(byte[] secretBytes) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        this.cipher.init(Cipher.DECRYPT_MODE,getPrivateKey());
        return cipher.doFinal(secretBytes);
    }

    public void decipherMessage(String locationFile,String outputName) throws IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte [] secretBytes = Files.readAllBytes(Paths.get(locationFile));
        this.cipher.init(Cipher.DECRYPT_MODE,getPrivateKey());
        byte [] decodedBytes = this.cipher.doFinal(secretBytes);
        FileWriter fileWriter = new FileWriter(outputName);
        fileWriter.write(new String(decodedBytes,StandardCharsets.UTF_8));
        fileWriter.close();
    }

    public String convertBytesToString(byte[] decodedCipherBytes) throws BadPaddingException, IllegalBlockSizeException {
        return new String(this.cipher.doFinal(decodedCipherBytes), StandardCharsets.UTF_8);
    }

}
