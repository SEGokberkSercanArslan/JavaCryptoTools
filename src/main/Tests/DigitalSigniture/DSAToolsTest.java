package DigitalSigniture;

import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.SignatureException;

import static org.junit.Assert.*;

public class DSAToolsTest {

    private DSATools tools;

    @Before
    public void setUp() throws Exception {
        this.tools = new DSATools();
    }

    @Test
    public void testSignatureOperation() throws SignatureException, InvalidKeyException {
        String msg = "Hello World";
        byte [] signedMessage = this.tools.signMessage(msg);
        assertTrue(this.tools.verifySign(this.tools.getPublicKey(),msg.getBytes(StandardCharsets.UTF_8),signedMessage));
    }

}