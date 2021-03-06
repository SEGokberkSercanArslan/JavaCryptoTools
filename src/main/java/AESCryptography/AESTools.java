package AESCryptography;

import javax.crypto.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class AESTools {

    private KeyGenerator keyGenerator;
    private SecureRandom secureRandom;
    private Cipher cipher;
    private Key key;

    public AESTools() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.keyGenerator = KeyGenerator.getInstance("AES");
        this.secureRandom = new SecureRandom();
        this.keyGenerator.init(256,this.secureRandom);
        this.cipher = Cipher.getInstance("AES");
        this.generateKey();
    }

    private final void generateKey(){
        this.key = keyGenerator.generateKey();
    }

    public final Key getAESKey(){
        return this.key;
    }

    public final byte[] cipherMessage(String message) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        this.cipher.init(Cipher.ENCRYPT_MODE,this.key);
        return this.cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
    }

    // Output name must be txt or relevant extension
    public final void cipherMessage(String fileLocation, String cipherOutputName) throws IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String message = new String(Files.readAllBytes(Paths.get(fileLocation)));
        this.cipher.init(Cipher.ENCRYPT_MODE,this.key);
        byte[] secretBytes = this.cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        OutputStream outputStream = new FileOutputStream(cipherOutputName);
        outputStream.write(secretBytes);
        outputStream.close();
    }

    public final byte[] decipherMessage(byte[] cipherBytes) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        this.cipher.init(Cipher.DECRYPT_MODE,this.key);
        return this.cipher.doFinal(cipherBytes);
    }

    public final void decipherMessage(String fileLocation,String outFileName) throws IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] bytes = Files.readAllBytes(Paths.get(fileLocation));
        this.cipher.init(Cipher.DECRYPT_MODE,this.key);
        String secretMessage = this.convertBytesToString(this.cipher.doFinal(bytes));
        FileWriter writer = new FileWriter(outFileName);
        writer.write(secretMessage);
        writer.close();
    }

    public final String convertBytesToString(byte[] decodedCipherBytes) throws BadPaddingException, IllegalBlockSizeException {
        return new String(decodedCipherBytes,StandardCharsets.UTF_8);
    }





}
