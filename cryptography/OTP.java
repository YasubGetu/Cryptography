/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package cryptography;

import java.io.*;
 
// Main class
public class OTP {
 
    // Method 1
    // Returning encrypted text
    public static String stringEncryption(String messageToEncrypt,
                                          String encryptionKey)
    {
 
        // Initializing cipherText
        String cipherText = "";
 
        // Initialize cipher array of key length
        // which stores the sum of corresponding no.'s
        // of plainText and key.
        int cipher[] = new int[encryptionKey.length()];
 
        for (int i = 0; i < encryptionKey.length(); i++) {
            cipher[i] = messageToEncrypt.charAt(i) - 'A'
                        + encryptionKey.charAt(i)
                        - 'A';
        }

        for (int i = 0; i < encryptionKey.length(); i++) {
            if (cipher[i] > 25) {
                cipher[i] = cipher[i] - 26;
            }
        }
 
        // Converting the no.'s into integers
 
        // Convert these integers to corresponding
        // characters and add them up to cipherText
        for (int i = 0; i < encryptionKey.length(); i++) {
            int x = cipher[i] + 'A';
            cipherText += (char)x;
        }
 
        // Returning the cipherText
        return cipherText;
    }
 
    // Method 2
    // Returning plain text
    public static String stringDecryption(String messageToDecrypt,
                                          String decryptionKey)
    {
        // Initializing plain text
        String plainText = "";
 
        // Initializing integer array of key length
        // which stores difference
        // of corresponding no.'s of
        // each character of cipherText and key
        int plain[] = new int[decryptionKey.length()];
 
        // Running for loop for each character
        // subtracting and storing in the array
        for (int i = 0; i < decryptionKey.length(); i++) {
            plain[i]
                = messageToDecrypt.charAt(i) - 'A'
                  - (decryptionKey.charAt(i) - 'A');
        }
 
        // If the difference is less than 0
        // add 26 and store it in the array.
        for (int i = 0; i < decryptionKey.length(); i++) {
            if (plain[i] < 0) {
                plain[i] = plain[i] + 26;
            }
        }
 
        // Converting int to corresponding char
        // add them up to plainText
        for (int i = 0; i < decryptionKey.length(); i++) {
            int x = plain[i] + 'A';
            plainText += (char)x;
        }
 
        // Returning plainText
        return plainText;
    }
 
    // Method 3
    // Main driver method
    public static void main(String[] args)
    {
        // Declaring plain text
        String plainText = "Hello";
 
        // Declaring key
        String key = "MONEY";
 
        // Converting plain text to toUpperCase
        // function call to stringEncryption
        // with plainText and key as parameters
        String encryptedText = stringEncryption(
            plainText.toUpperCase(), key.toUpperCase());
 
        // Printing cipher Text
        System.out.println("Cipher Text - "
                           + encryptedText);
 
        // Calling above method to stringDecryption
        // with encryptedText and key as parameters
        System.out.println(
            "Message - "
            + stringDecryption(encryptedText,
                               key.toUpperCase()));
    }
}