package com.mycompany.app;


import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Date;

/**
 *
 */
public class App {

    public static final String STORE_PASSWORD = "mystorepass";
    public static final String ALIAS = "jceksaes";
    public static final String KEY_PASS = "mykeypass";

    public static Key getKey() throws KeyStoreException, IOException,
            CertificateException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableKeyException, VaultException {
        // Read from file
//        InputStream keystoreStream = new FileInputStream("/data/workspace/keystore-test/my-app/aes-keystore.jck");

        // Read from vault
        InputStream keystoreStream = new ByteArrayInputStream(vault());
        KeyStore keystore = KeyStore.getInstance("JCEKS");
        keystore.load(keystoreStream, STORE_PASSWORD.toCharArray());
        if (!keystore.containsAlias(ALIAS)) {
            throw new RuntimeException("Alias for key not found");
        }
        return keystore.getKey(ALIAS, KEY_PASS.toCharArray());

    }


    public static String encrypt(final String secret, final String data) {
        byte[] decodedKey = Base64.decodeBase64(secret);
        try {
            Cipher cipher = Cipher.getInstance("AES");
            // rebuild key using SecretKeySpec
            SecretKey originalKey = new SecretKeySpec(Arrays.copyOf(decodedKey, 16), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, originalKey);
            byte[] cipherText = cipher.doFinal(data.getBytes("UTF-8"));
            return Base64.encodeBase64String(cipherText);
        } catch (Exception e) {
            throw new RuntimeException("Error occurred while encrypting data", e);
        }

    }

    public static String decrypt(final String secret,
                                 final String encryptedString) {
        byte[] decodedKey = Base64.decodeBase64(secret);
        try {
            Cipher cipher = Cipher.getInstance("AES");
            // rebuild key using SecretKeySpec
            SecretKey originalKey = new SecretKeySpec(Arrays.copyOf(decodedKey, 16), "AES");
            cipher.init(Cipher.DECRYPT_MODE, originalKey);
            byte[] cipherText = cipher.doFinal(Base64.decodeBase64(encryptedString));
            return new String(cipherText);
        } catch (Exception e) {
            throw new RuntimeException("Error occured while decrypting data", e);
        }
    }


    public static void main(String[] args) throws CertificateException, UnrecoverableKeyException,
            NoSuchAlgorithmException, KeyStoreException, NoSuchPaddingException, IOException, VaultException {
        String data = "SAMPLE encryption text. " + new Date();
        System.out.println("Original : " + data);
//        String key = "---------------------------------";
        Key key = getKey();
        byte[] bytes = Base64.decodeBase64(key.getEncoded());
        String keyString = new String(bytes);
        String encrypted = encrypt(keyString, data);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypt(keyString, encrypted));

    }


    public static byte[] vault() throws VaultException {
        final VaultConfig config = new VaultConfig()
                .address("http://127.0.0.1:8200")
                .token("s.lU4riBlVIPUq9hfVzm3NXe0Y") // Token changes on vault dev server restart
                .engineVersion(1)
                .build();
        final Vault vault = new Vault(config);
        return Base64.decodeBase64(vault.logical().read("myapp/key64").getData().get("keyfile"));
    }
}
