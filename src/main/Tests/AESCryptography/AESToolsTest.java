package AESCryptography;

import org.junit.Before;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;

import static org.junit.Assert.assertEquals;

public class AESToolsTest {

    private AESTools tools;

    @Before
    public void setUp() throws Exception {
        this.tools = new AESTools();
    }

    @Test
    public void cipherDecipherMessage() throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        String msg = "Hello World";
        byte[] cipher = this.tools.cipherMessage(msg);
        byte[] decipher = this.tools.decipherMessage(cipher);
        assertEquals(msg,new String(decipher,StandardCharsets.UTF_8));
    }

    @Test
    public void cipherDecipherFileMessage() throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        this.tools.cipherMessage("src/main/Tests/AESCryptography/msg.txt","src/main/Tests/AESCryptography/cipher.txt");
        this.tools.decipherMessage("src/main/Tests/AESCryptography/cipher.txt","src/main/Tests/AESCryptography/decipher.txt");
        String msg = new String(Files.readAllBytes(Paths.get("src/main/Tests/AESCryptography/msg.txt")),StandardCharsets.UTF_8);
        String decipher = new String(Files.readAllBytes(Paths.get("src/main/Tests/AESCryptography/decipher.txt")),StandardCharsets.UTF_8);
        assertEquals(msg,decipher);
    }

    @Test
    public void convertBytesToString() throws BadPaddingException, IllegalBlockSizeException {
        java.lang.String msg = "Hello World";
        byte[] bytes = msg.getBytes(StandardCharsets.UTF_8);
        assertEquals(msg,this.tools.convertBytesToString(bytes));
    }
}