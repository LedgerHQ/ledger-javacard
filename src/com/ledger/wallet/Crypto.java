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

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.AESKey;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.HMACKey;
import javacard.security.KeyAgreement;
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
        scratch = JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_DESELECT);
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
                keyHmac2 = (HMACKey)KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT, HMAC_SHA512_SIZE, false);
        	}
        	catch(CryptoException e) {
        		try {
                    // ok, let's save a bit less RAM        			
        			keyHmac = (HMACKey)KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_RESET, HMAC_SHA512_SIZE, false);
                    keyHmac2 = (HMACKey)KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_RESET, HMAC_SHA512_SIZE, false);
        		}
        		catch(CryptoException e1) {
                    // ok, let's test the flash wear leveling \o/        			
        			keyHmac = (HMACKey)KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, HMAC_SHA512_SIZE, false);
                    keyHmac2 = (HMACKey)KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, HMAC_SHA512_SIZE, false);
        		}
        	}        	
        }
        catch(CryptoException e) {
        	signatureHmac = null;
        }
        // Optional initializations if no proprietary API is available
        try {
        	keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        }
        catch(CryptoException e) {
        	// Not having the KeyAgreement API is manageable if there is a proprietary API to recover public keys
            // and if the airgapped personalization can be skipped
        	// Otherwise there should be a remote secure oracle performing public derivations and sending back results
        }
        try {
            publicKey = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
            Secp256k1.setCommonCurveParameters(publicKey);        	
        }
        catch(CryptoException e) {
        }                
        try {
                keyPair = new KeyPair(
                        (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
                        (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false));
                Secp256k1.setCommonCurveParameters((ECKey)keyPair.getPrivate());
                Secp256k1.setCommonCurveParameters((ECKey)keyPair.getPublic());
        }
        catch(CryptoException e) {            
        }
        try {
            blobEncryptDecryptAES = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        }
        catch(CryptoException e) {            
        }
    }
    
    public static void initTransientPrivate(byte[] keyBuffer, short keyOffset) {
        if (transientPrivateTransient) {
        	Secp256k1.setCommonCurveParameters(transientPrivate);
        }
        transientPrivate.setS(keyBuffer, keyOffset, (short)32);    	
    }
    
    public static void signTransientPrivate(byte[] keyBuffer, short keyOffset, byte[] dataBuffer, short dataOffset, byte[] targetBuffer, short targetOffset) {
    	initTransientPrivate(keyBuffer, keyOffset);
        Util.arrayFillNonAtomic(keyBuffer, keyOffset, (short)32, (byte)0x00);
        // recheck with the target platform, initializing once instead might be possible and save a few flash write
        // (this part is unspecified in the Java Card API)
        signature.init(transientPrivate, Signature.MODE_SIGN);
        signature.sign(dataBuffer, dataOffset, (short)32, targetBuffer, targetOffset);
        if (transientPrivateTransient) {
            transientPrivate.clearKey();
        }
    }
    
    // following method is only used if no proprietary API is available
    public static boolean verifyPublic(byte[] keyBuffer, short keyOffset, byte[] dataBuffer, short dataOffset, byte[] signatureBuffer, short signatureOffset) {
    	publicKey.setW(keyBuffer, keyOffset, (short)65);
    	signature.init(publicKey, Signature.MODE_VERIFY);
    	try {
    		return signature.verify(dataBuffer, dataOffset, (short)32, signatureBuffer, signatureOffset, (short)(signatureBuffer[(short)(signatureOffset + 1)] + 2));
    	}
    	catch(Exception e) {
    		return false;
    	}
    }
    
    public static void initCipher(DESKey key, boolean encrypt) {
        blobEncryptDecrypt.init(key, (encrypt ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT), IV_ZERO, (short)0, (short)IV_ZERO.length);
    }

    public static void initCipherAES(AESKey key, boolean encrypt) {
        blobEncryptDecryptAES.init(key, (encrypt ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT), IV_ZERO_AES, (short)0, (short)IV_ZERO_AES.length);
    }

    public static byte getRandomByteModulo(short modulo) {
        short rng_max = (short)(256 % modulo);
        short rng_limit = (short)(256 - rng_max);
        short candidate = (short)0;
        do {
            random.generateData(scratch, (short)0, (short)1);
            candidate = (short)(scratch[0] & 0xff);
        }
        while(candidate > rng_limit);
        return (byte)(candidate % modulo);
    }
    
    private static final byte[] IV_ZERO = { 0, 0, 0, 0, 0, 0, 0, 0 };
    private static final byte[] IV_ZERO_AES = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    private static byte[] scratch;
    protected static ECPrivateKey transientPrivate;    
    protected static boolean transientPrivateTransient;    
    protected static Signature signature;
    protected static Signature signatureHmac;
    protected static HMACKey keyHmac;
    protected static HMACKey keyHmac2; // duplicated because platforms don't like changing the key size on the fly
    protected static MessageDigest digestFull;
    protected static MessageDigest digestAuthorization;
    protected static MessageDigest digestScratch;
    protected static MessageDigest digestRipemd;
    protected static MessageDigest digestSha512;
    protected static SHA512 sha512;
    protected static RandomData random;
    protected static Cipher blobEncryptDecrypt;    
    protected static Cipher blobEncryptDecryptAES;

    protected static KeyAgreement keyAgreement;
    protected static KeyPair keyPair;
    
    // following variables are only used if no proprietary API is available
    protected static ECPublicKey publicKey; 
    
}
