/*
*******************************************************************************    
*   Java Card Bitcoin Hardware Wallet
*   (c) 2015 Ledger
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
package com.ledger.wallet;

import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.HMACKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * Hardware Wallet crypto tools
 * @author BTChip
 *
 */
public class Crypto {
	
	// Java Card constants might be off for some platforms - recheck with your implementation
	//private static final short HMAC_SHA512_SIZE = KeyBuilder.LENGTH_HMAC_SHA_512_BLOCK_128; 
	private static final short HMAC_SHA512_SIZE = (short)(32 * 8);
    
    public static void init() {
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
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
                Secp256k1.setCommonCurveParameters(transientPrivate);
            }
        }
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
        }
        try {
        	digestSha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false); 
        }
        catch(CryptoException e) {
        	sha512 = new SHA512();
        }
        try {
        	signatureHmac = Signature.getInstance(Signature.ALG_HMAC_SHA_512, false);
        	try {
                // ok, let's save RAM        		
        		keyHmac = (HMACKey)KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT, HMAC_SHA512_SIZE, false);
        	}
        	catch(CryptoException e) {
        		try {
                    // ok, let's save a bit less RAM        			
        			keyHmac = (HMACKey)KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_RESET, HMAC_SHA512_SIZE, false);
        		}
        		catch(CryptoException e1) {
                    // ok, let's test the flash wear leveling \o/        			
        			keyHmac = (HMACKey)KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, HMAC_SHA512_SIZE, false);
        		}
        	}        	
        }
        catch(CryptoException e) {
        	signatureHmac = null;
        }
        
    }
    
    public static void signTransientPrivate(byte[] keyBuffer, short keyOffset, byte[] dataBuffer, short dataOffset, byte[] targetBuffer, short targetOffset) {
        if (transientPrivateTransient) {
        	Secp256k1.setCommonCurveParameters(transientPrivate);
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
    
    public static void initCipher(DESKey key, boolean encrypt) {
        blobEncryptDecrypt.init(key, (encrypt ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT), IV_ZERO, (short)0, (short)IV_ZERO.length);
    }
    
    private static final byte[] IV_ZERO = { 0, 0, 0, 0, 0, 0, 0, 0 };

    protected static ECPrivateKey transientPrivate;
    private static boolean transientPrivateTransient;
    private static Signature signature;
    protected static Signature signatureHmac;
    protected static HMACKey keyHmac;
    protected static MessageDigest digestFull;
    protected static MessageDigest digestAuthorization;
    protected static MessageDigest digestScratch;
    protected static MessageDigest digestRipemd;
    protected static MessageDigest digestSha512;
    protected static SHA512 sha512;
    protected static RandomData random;
    protected static Cipher blobEncryptDecrypt;   
}
