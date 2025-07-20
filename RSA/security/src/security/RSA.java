package security;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class RSA {

    public static void main(String[] args) {
        try {
            SecureRandom random = new SecureRandom();

            // Key size input and validation
            System.out.print("Enter Size: ");
            int keySize = 0;
            boolean validKeySize = false;
            while (!validKeySize) {
                try {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                    String keySizeInput = reader.readLine();
                    keySize = Integer.parseInt(keySizeInput);
                    if (keySize >= 256) {
                        validKeySize = true;
                    } else {
                        System.out.print("n must be greater than or equal to 256\nEnter Size: ");
                    }
                } catch (NumberFormatException e) {
                    System.out.print("Invalid input. Please enter a valid integer for the key size: ");
                }
            }

            // Generate prime numbers p and q
            BigInteger p = new BigInteger(keySize / 2, 100, random);
            BigInteger q = new BigInteger(keySize / 2, 100, random);

            // Calculate n and phi
            BigInteger n = p.multiply(q);
            BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

            // Public exponent e
            BigInteger e = new BigInteger("65537");
            while (phi.gcd(e).compareTo(BigInteger.ONE) > 0) {
                e = e.add(BigInteger.TWO);
            }

            // Private exponent d
            BigInteger d = e.modInverse(phi);

            // Display public and private keys
            System.out.println("The generated public key in plaintext: " + e + "," + n);
            System.out.println("The generated public key in big integer: " + e.toString() + "," + n.toString());
            System.out.println("The generated private key in plaintext: " + d + "," + n);
            System.out.println("The generated private key in big integer: " + d.toString() + "," + n.toString());

            // Read message from message.txt
            String message;
            try {
                message = new String(Files.readAllBytes(Paths.get("message.txt")), "UTF-8");
            } catch (IOException ex) {
                System.err.println("Error: Cannot read message.txt. Ensure the file exists and is readable.");
                return;
            }
            System.out.println("Message in plaintext: " + message);

            // Convert message to BigInteger
            BigInteger messageBigInt;
            try {
                messageBigInt = new BigInteger(1, message.getBytes("UTF-8"));
            } catch (UnsupportedEncodingException ex) {
                System.err.println("Error: UTF-8 encoding not supported.");
                return;
            }
            System.out.println("Message in big integer: " + messageBigInt);

            // Check if message is too large for encryption
            if (messageBigInt.compareTo(n) >= 0) {
                System.err.println("Error: Message is too large to encrypt with the given key size. Try a larger key size or smaller message.");
                return;
            }

            // Encrypt message
            BigInteger encrypted = messageBigInt.modPow(e, n);
            System.out.println("Encrypted Cipher in big integer: " + encrypted.toString());

            // Convert encrypted cipher to Base64
            byte[] encryptedBytes = encrypted.toByteArray();
            String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedBytes);
            System.out.println("Encrypted Cipher in Plaintext: " + encryptedBase64);

            // Decrypt message
            BigInteger decrypted = encrypted.modPow(d, n);
            String decryptedMessage;
            try {
                decryptedMessage = new String(decrypted.toByteArray(), "UTF-8");
            } catch (UnsupportedEncodingException ex) {
                System.err.println("Error: UTF-8 encoding not supported.");
                return;
            }
            System.out.println("Decrypted Message in plaintext: " + decryptedMessage);
            System.out.println("Decrypted Message in big integer: " + decrypted.toString());

            // Write encrypted data to encyptedRSA.txt
            try (BufferedWriter writer = new BufferedWriter(new FileWriter("encyptedRSA.txt"))) {
                writer.write("Encrypted RSA Data\n");
                writer.write("Public Key (e, n):\n" + e + "," + n + "\n");
                writer.write("Encrypted Cipher in Plaintext: " + encryptedBase64 + "\n");
                writer.write("Your Full Name: Jana Saeed\n");
            } catch (IOException ex) {
                System.err.println("Error: Cannot write to encyptedRSA.txt. Check write permissions.");
            }

            // Write decrypted data to decryptedRSA.txt
            try (BufferedWriter writer = new BufferedWriter(new FileWriter("decryptedRSA.txt"))) {
                writer.write("Decrypted RSA Data\n");
                writer.write("Decrypted Message in plaintext: " + decryptedMessage + "\n");
                writer.write("Decrypted Message in big integer: " + decrypted.toString() + "\n");
                writer.write("Your Full Name: Jana Saeed\n");
            } catch (IOException ex) {
                System.err.println("Error: Cannot write to decryptedRSA.txt. Check write permissions.");
            }

        } catch (Exception ex) {
            System.err.println("An unexpected error occurred: " + ex.getMessage());
        }
    }
}


