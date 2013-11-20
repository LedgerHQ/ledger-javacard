/*
*******************************************************************************    
*   BTChip Bitcoin Hardware Wallet Java Card implementation
*   (c) 2013 BTChip - 1BTChip7VfTnrPra5jqci7ejnMguuHogTn
*   
*   This program is free software: you can redistribute it and/or modify
*   it under the terms of the GNU Affero General Public License as
*   published by the Free Software Foundation, either version 3 of the
*   License, or (at your option) any later version.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU Affero General Public License for more details.
*
*   You should have received a copy of the GNU Affero General Public License
*   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*******************************************************************************   
*/    

package com.btchip.applet.poc;

import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * Bitcoin signature implementation
 * @author BTChip
 *
 */
public class Crypto {
    
    public static void init() {
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        // it's not even possible to request a transient pair, yay.
        generatingPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        try {
            // ok, let's save RAM
            transientPrivate = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_EC_FP_256, false);
            transientPrivateTransient = true;
        }
        catch(CryptoException e) {
            try {
                // ok, let's save a bit less RAM
                transientPrivate = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET, KeyBuilder.LENGTH_EC_FP_256, false);
                transientPrivateTransient = true;
            }
            catch(CryptoException e1) {
                // ok, let's test the flash wear leveling \o/
                transientPrivate = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
                initKeyCurve(transientPrivate);
            }
        }
        initKeyCurve((ECKey)generatingPair.getPublic());
        initKeyCurve((ECKey)generatingPair.getPrivate());
        digestFull = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        digestAuthorization = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        digestScratch = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        blobEncryptDecrypt = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
        signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        try {
            digestRipemd = MessageDigest.getInstance(MessageDigest.ALG_RIPEMD160, false);
        }
        catch(CryptoException e) {
            // A typical Java Card implementation will not support RIPEMD160 - we deal with it
            Ripemd160.init();
        }
    }
    
    public static KeyPair generatePair() {
        generatingPair.genKeyPair();
        return generatingPair;
    }
    
    private static void initKeyCurve(ECKey key) {
        key.setA(SECP256K1_A, (short)0, (short)SECP256K1_A.length);
        key.setB(SECP256K1_B, (short)0, (short)SECP256K1_B.length);
        key.setFieldFP(SECP256K1_FP, (short)0, (short)SECP256K1_FP.length);
        key.setG(SECP256K1_G, (short)0, (short)SECP256K1_G.length);
        key.setR(SECP256K1_R, (short)0, (short)SECP256K1_R.length);
        key.setK(SECP256K1_K);
    }
    
    public static void hashRipemd32(byte[] buffer, short offset, byte[] target, short targetOffset) {
        if (digestRipemd != null) {
            digestRipemd.doFinal(buffer, offset, (short)32, target, targetOffset);
        }
        else {
            Ripemd160.hash32(buffer, offset, target, targetOffset);
        }
    }
    
    public static void signTransientPrivate(byte[] keyBuffer, short keyOffset, byte[] dataBuffer, short dataOffset, byte[] targetBuffer, short targetOffset) {
        if (transientPrivateTransient) {
            initKeyCurve(transientPrivate);
        }
        transientPrivate.setS(keyBuffer, keyOffset, (short)32);
        Util.arrayFillNonAtomic(keyBuffer, keyOffset, (short)32, (byte)0x00);
        // recheck with the target platform, initializing once instead might be possible and save a few flash write
        // (this part is unspecified in the Java Card API)
        signature.init(transientPrivate, Signature.MODE_SIGN);
        signature.sign(dataBuffer, dataOffset, (short)32, targetBuffer, targetOffset);
        if (transientPrivateTransient) {
            transientPrivate.clearKey();
        }
    }

    private static KeyPair generatingPair;
    private static ECPrivateKey transientPrivate;
    private static boolean transientPrivateTransient;
    private static Signature signature;
    public static MessageDigest digestFull;
    public static MessageDigest digestAuthorization;
    public static MessageDigest digestScratch;
    private static MessageDigest digestRipemd;
    public static RandomData random;
    public static Cipher blobEncryptDecrypt;
    
    // Nice SECp256k1 constants, only available during NIST opening hours
    
    private static final byte SECP256K1_FP[] = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,(byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F 
    };    
    private static final byte SECP256K1_A[] = {
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00, 
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00  
    };
    private static final byte SECP256K1_B[] = {
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00, 
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x07  
    };
    private static final byte SECP256K1_G[] = {
        (byte)0x04, 
        (byte)0x79,(byte)0xBE,(byte)0x66,(byte)0x7E,(byte)0xF9,(byte)0xDC,(byte)0xBB,(byte)0xAC,
        (byte)0x55,(byte)0xA0,(byte)0x62,(byte)0x95,(byte)0xCE,(byte)0x87,(byte)0x0B,(byte)0x07,
        (byte)0x02,(byte)0x9B,(byte)0xFC,(byte)0xDB,(byte)0x2D,(byte)0xCE,(byte)0x28,(byte)0xD9,
        (byte)0x59,(byte)0xF2,(byte)0x81,(byte)0x5B,(byte)0x16,(byte)0xF8,(byte)0x17,(byte)0x98,
        (byte)0x48,(byte)0x3A,(byte)0xDA,(byte)0x77,(byte)0x26,(byte)0xA3,(byte)0xC4,(byte)0x65,
        (byte)0x5D,(byte)0xA4,(byte)0xFB,(byte)0xFC,(byte)0x0E,(byte)0x11,(byte)0x08,(byte)0xA8,
        (byte)0xFD,(byte)0x17,(byte)0xB4,(byte)0x48,(byte)0xA6,(byte)0x85,(byte)0x54,(byte)0x19,
        (byte)0x9C,(byte)0x47,(byte)0xD0,(byte)0x8F,(byte)0xFB,(byte)0x10,(byte)0xD4,(byte)0xB8  
    };
    private static final byte SECP256K1_R[] = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
        (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6,(byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
        (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C,(byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41
    };
    private static final byte SECP256K1_K = (byte)0x01;   
}
