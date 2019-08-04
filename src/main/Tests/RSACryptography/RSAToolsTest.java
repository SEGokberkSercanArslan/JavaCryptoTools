package RSACryptography;

import org.junit.Before;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;

import static org.junit.Assert.assertEquals;

public class RSAToolsTest {

    RSATools rsaTools;

    @Before
    public void setUp() throws Exception {
        this.rsaTools = new RSATools();
    }

    @Test
    public void cipherDecipherMessage() throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        java.lang.String msg = "Hello World";
        byte[] secretBytes = this.rsaTools.cipherMessage(msg);
        byte[] decipherBytes = this.rsaTools.decipherMessage(secretBytes);
        assertEquals(msg,this.rsaTools.convertBytesToString(decipherBytes));
    }

    @Test
    public void cipherDecipherFileMessage() throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        this.rsaTools.cipherMessage("src/main/Tests/RSACryptography/msg.txt","src/main/Tests/RSACryptography/cipher.txt");
        this.rsaTools.decipherMessage("src/main/Tests/RSACryptography/cipher.txt","src/main/Tests/RSACryptography/decipher.txt");
        String msg  = new String(Files.readAllBytes(Paths.get("src/main/Tests/RSACryptography/msg.txt")),StandardCharsets.UTF_8);
        String decipher = new String(Files.readAllBytes(Paths.get("src/main/Tests/RSACryptography/decipher.txt")),StandardCharsets.UTF_8);
        assertEquals(msg,decipher);
    }

    @Test
    public void convertBytesToString() throws BadPaddingException, IllegalBlockSizeException {
        java.lang.String msg = "Hello World";
        assertEquals(msg,this.rsaTools.convertBytesToString(msg.getBytes(StandardCharsets.UTF_8)));
    }

}