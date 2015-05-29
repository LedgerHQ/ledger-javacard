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

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;

/**
 * Hardware Wallet applet
 * @author BTChip
 *
 */
public class LedgerWalletApplet extends Applet {
    
    public LedgerWalletApplet() {
        BCDUtils.init();
        TC.init();
        Crypto.init();
        Transaction.init();
        Bip32Cache.init();
        limits = new byte[LIMIT_LAST];
        scratch256 = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
        transactionPin = new OwnerPIN(TRANSACTION_PIN_ATTEMPTS, TRANSACTION_PIN_SIZE);
        walletPin = new OwnerPIN(WALLET_PIN_ATTEMPTS, WALLET_PIN_SIZE);        
        secondaryPin = new OwnerPIN(SECONDARY_PIN_ATTEMPTS, SECONDARY_PIN_SIZE);
        masterDerived = new byte[64];
        chipKey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
        trustedInputKey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
        developerKey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
        Crypto.random.generateData(scratch256, (short)0, (short)16);
        chipKey.setKey(scratch256, (short)0);
        TC.ctxP[TC.P_TX_Z_USED] = TC.FALSE;
        setup = TC.FALSE;
        limitsSet = TC.FALSE;
        //proprietaryAPI = new JCOPProprietaryAPI();
    }
    
    protected static void writeIdleText() {
        short offset = Util.arrayCopyNonAtomic(TEXT_IDLE, (short)0, LWNFCForumApplet.FILE_DATA, LWNFCForumApplet.OFFSET_TEXT, (short)TEXT_IDLE.length);
        LWNFCForumApplet.writeHeader((short)(offset - LWNFCForumApplet.OFFSET_TEXT));
    }
    
    protected static boolean isContactless() {
        return ((APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK) == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A);                
    }
    
    private static void checkAccess(boolean checkPinContactless) {
        if ((setup == TC.FALSE) || (setup != TC.TRUE)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (!isContactless() && !walletPin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);            
        }
        if (checkPinContactless && !walletPin.isValidated()) {
        	ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
    
    private static void checkInterfaceConsistency() {
        // Check interface consistency - signature cannot go across interfaces
        if ((isContactless() && (TC.ctxP[TC.P_TX_Z_USED] != TC.FALSE)) ||
            (!isContactless() && (TC.ctxP[TC.P_TX_Z_USED] != TC.TRUE))) {
              ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }        
    }
    
    private static boolean isFirstSigned() {
        if (TC.ctxP[TC.P_TX_Z_USED] == TC.TRUE) {
            if (TC.ctxP[TC.P_TX_Z_FIRST_SIGNED] == TC.TRUE) {
                return true;
            }
            else
            if (TC.ctxP[TC.P_TX_Z_FIRST_SIGNED] == TC.FALSE) {
                return false;
            }
            else {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        }
        else
        if (TC.ctxP[TC.P_TX_Z_USED] == TC.FALSE) {
            if (TC.ctx[TC.TX_Z_FIRST_SIGNED] == TC.TRUE) {
                return true;
            }
            else
            if (TC.ctx[TC.TX_Z_FIRST_SIGNED] == TC.FALSE) {
                return false;
            }
            else {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }                
        }    
        else {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        return true; // happy compiler
    }
    
    private static void restoreState() {
        if (TC.ctxP[TC.P_TX_Z_USED] == TC.TRUE) {
            TC.ctx[TC.TX_B_TRANSACTION_STATE] = TC.ctxP[TC.P_TX_B_TRANSACTION_STATE];
            Util.arrayCopyNonAtomic(TC.ctxP, TC.P_TX_A_AUTH_NONCE, TC.ctx, TC.TX_A_AUTH_NONCE, TC.TX_AUTH_CONTEXT_SIZE);
            Util.arrayCopyNonAtomic(TC.ctxP, TC.P_TX_A_AUTHORIZATION_HASH, TC.ctx, TC.TX_A_AUTHORIZATION_HASH, TC.SIZEOF_SHA256);
            TC.ctx[TC.TX_Z_HAS_CHANGE] = TC.ctxP[TC.P_TX_Z_HAS_CHANGE];
            TC.ctx[TC.TX_Z_IS_P2SH] = TC.ctxP[TC.P_TX_Z_IS_P2SH];            
        }
        else
        if (TC.ctxP[TC.P_TX_Z_USED] == TC.FALSE) {            
        }
        else {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);            
        }
    }
    
    private static void saveState() {
        if (TC.ctxP[TC.P_TX_Z_USED] == TC.TRUE) {
            TC.ctxP[TC.P_TX_B_TRANSACTION_STATE] = TC.ctx[TC.TX_B_TRANSACTION_STATE];
        }
        else
        if (TC.ctxP[TC.P_TX_Z_USED] == TC.FALSE) {            
        }
        else {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);            
        }        
    }

    private static void verifyKeyChecksum(byte[] buffer, short offset, short length, byte[] scratch, short scratchOffset) {
        Crypto.digestScratch.doFinal(buffer, offset, (short)(length - 4), scratch, scratchOffset);
        Crypto.digestScratch.doFinal(scratch, scratchOffset, TC.SIZEOF_SHA256, scratch, scratchOffset);
        if (Util.arrayCompare(scratch, scratchOffset, buffer, (short)(offset + length - 4), (short)4) != (byte)0x00) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);                
        }        
    }

    // Compressed public key in scratch256, 0
    private static short publicKeyToAddress(byte[] out, short outOffset) {
    	Crypto.digestScratch.doFinal(scratch256, (short)0, (short)33, scratch256, (short)33);    	
    	if (Crypto.digestRipemd != null) {
    		Crypto.digestRipemd.doFinal(scratch256, (short)33, (short)32, scratch256, (short)1);
    	}
    	else {
    		Ripemd160.hash32(scratch256, (short)33, scratch256, (short)1, scratch256, (short)100);
    	}
    	scratch256[0] = stdVersion;
    	Crypto.digestScratch.doFinal(scratch256, (short)0, (short)21, scratch256, (short)21);
    	Crypto.digestScratch.doFinal(scratch256, (short)21, (short)32, scratch256, (short)21);
    	return Base58.encode(scratch256, (short)0, (short)25, out, outOffset, scratch256, (short)100);
    }
    
    private static void handleGetWalletPublicKey(APDU apdu) throws ISOException {
    	byte[] buffer = apdu.getBuffer();
    	short offset = ISO7816.OFFSET_CDATA;
    	byte derivationSize = buffer[offset++];
    	byte i;
    	if (derivationSize > MAX_DERIVATION_PATH) {
    		ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    	}
    	// Unwrap the initial seed
        Crypto.initCipher(chipKey, false);
        Crypto.blobEncryptDecrypt.doFinal(masterDerived, (short)0, (short)DEFAULT_SEED_LENGTH, scratch256, (short)0);
        // Derive all components
        i = Bip32Cache.copyPrivateBest(buffer, (short)(ISO7816.OFFSET_CDATA + 1), derivationSize, scratch256, (short)0);
        for (; i<derivationSize; i++) {
        	Util.arrayCopyNonAtomic(buffer, (short)(offset + 4 * i), scratch256, Bip32.OFFSET_DERIVATION_INDEX, (short)4);
        	if ((proprietaryAPI == null) && ((scratch256[Bip32.OFFSET_DERIVATION_INDEX] & (byte)0x80) == 0)) {
        		if (!Bip32Cache.setPublicIndex(buffer, (short)(ISO7816.OFFSET_CDATA + 1), (byte)(i + 1))) {
        			ISOException.throwIt(SW_PUBLIC_POINT_NOT_AVAILABLE);
        		}
        	}
        	Bip32.derive(buffer);
        	Bip32Cache.storePrivate(buffer, (short)(ISO7816.OFFSET_CDATA + 1), (byte)(i + 1), scratch256);
        }
        if (proprietaryAPI == null) {
    		if (!Bip32Cache.setPublicIndex(buffer, offset, derivationSize)) {
    			ISOException.throwIt(SW_PUBLIC_POINT_NOT_AVAILABLE);
    		}        	
        }
        // Finally output
        offset = 0;
        buffer[offset++] = (short)65;
        if (proprietaryAPI == null) {
        	Bip32Cache.copyLastPublic(buffer, offset);
        }
        else {
        	proprietaryAPI.getUncompressedPublicPoint(scratch256, (short)0, buffer, offset);
        }
        // Save the chaincode
        Util.arrayCopyNonAtomic(scratch256, (short)32, buffer, (short)200, (short)32);
        // Get the encoded address
        Util.arrayCopyNonAtomic(buffer, offset, scratch256, (short)0, (short)65);
        AddressUtils.compressPublicKey(scratch256, (short)0);
        offset += (short)65;
        buffer[offset] = (byte)(publicKeyToAddress(buffer, (short)(offset + 1)) - (short)(offset + 1));
        offset += (short)(buffer[offset] + 1);
        // Add the chaincode
        Util.arrayCopyNonAtomic(buffer, (short)200, buffer, offset, (short)32);
        offset += 32;
        apdu.setOutgoingAndSend((short)0, offset);            	
    }
    
    private static void handleTrustedInput(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte dataOffset = (short)0;
        apdu.setIncomingAndReceive();
        if (p1 == P1_TRUSTED_INPUT_FIRST) {
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, TC.ctx, TC.TX_I_TRANSACTION_TARGET_INPUT, TC.SIZEOF_U32);
            TC.ctx[TC.TX_B_TRANSACTION_STATE] = Transaction.STATE_NONE;
            TC.ctx[TC.TX_B_TRUSTED_INPUT_PROCESSED] = (byte)0x00;
            TC.ctx[TC.TX_B_HASH_OPTION] = Transaction.HASH_FULL;
            dataOffset = (short)4;
        }
        else
        if (p1 != P1_TRUSTED_INPUT_NEXT) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        short remainingData = (short)((short)(buffer[ISO7816.OFFSET_LC] & 0xff) - dataOffset);
        byte result = Transaction.parseTransaction(Transaction.PARSE_TRUSTED_INPUT, buffer, (short)(ISO7816.OFFSET_CDATA + dataOffset), remainingData);
        if (result == Transaction.RESULT_ERROR) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        else
        if (result == Transaction.RESULT_MORE) {
            return;
        }
        else
        if (result == Transaction.RESULT_FINISHED) {
            short offset = 0;
            buffer[offset++] = BLOB_MAGIC_TRUSTED_INPUT;
            Crypto.random.generateData(buffer, offset, (short)3);
            offset += 3;            
            Crypto.digestFull.doFinal(scratch256, (short)0, (short)0, scratch256, (short)0);
            Crypto.digestFull.doFinal(scratch256, (short)0, (short)32, buffer, offset);
            offset += 32;
            GenericBEHelper.swap(TC.SIZEOF_U32, buffer, offset, TC.ctx, TC.TX_I_TRANSACTION_TARGET_INPUT);
            offset += 4;
            Util.arrayCopyNonAtomic(TC.ctx, TC.TX_A_TRANSACTION_AMOUNT, buffer, offset, TC.SIZEOF_AMOUNT);
            offset += TC.SIZEOF_AMOUNT;
            Crypto.initCipher(trustedInputKey, true);
            // "sign", using the same cipher
            Crypto.blobEncryptDecrypt.doFinal(buffer, (short)0, offset, scratch256, (short)0);
            Util.arrayCopyNonAtomic(scratch256, (short)(offset - 8), buffer, offset, (short)8);
            offset += 8;
            apdu.setOutgoingAndSend((short)0, offset);                       
        }
    }
    
    private static void handleHashTransaction(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];        
        short dataOffset = (short)0;
        apdu.setIncomingAndReceive();                
        if (p1 == P1_HASH_TRANSACTION_FIRST) {
            // Initialize
            TC.ctx[TC.TX_B_TRANSACTION_STATE] = Transaction.STATE_NONE;
            TC.ctx[TC.TX_B_HASH_OPTION] = Transaction.HASH_BOTH;            
        }
        else
        if (p1 != P1_HASH_TRANSACTION_NEXT) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (p2 == P2_HASH_TRANSACTION_NEW_INPUT) {
            if (p1 == P1_HASH_TRANSACTION_FIRST) {
                checkAccess(false);
                if (isContactless() && (limitsSet != TC.TRUE)) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
                TC.ctxP[TC.P_TX_Z_USED] = (isContactless() ? TC.FALSE : TC.TRUE);
                if (TC.ctxP[TC.P_TX_Z_USED] == TC.TRUE) {
                    TC.ctxP[TC.P_TX_Z_FIRST_SIGNED] = TC.TRUE;
                }
                else {
                    TC.ctx[TC.TX_Z_FIRST_SIGNED] = TC.TRUE;
                }
                if (TC.ctxP[TC.P_TX_Z_USED] == TC.TRUE) {
                    Crypto.random.generateData(TC.ctxP, TC.P_TX_A_AUTH_NONCE, TC.SIZEOF_NONCE);
                }
                else {
                    Crypto.random.generateData(TC.ctx, TC.TX_A_AUTH_NONCE, TC.SIZEOF_NONCE);
                }
            }
        }
        else
        if (p2 != P2_HASH_TRANSACTION_CONTINUE_INPUT) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        checkInterfaceConsistency();
        short remainingData = (short)((short)(buffer[ISO7816.OFFSET_LC] & 0xff) - dataOffset);
        byte result = Transaction.parseTransaction(Transaction.PARSE_SIGNATURE, buffer, (short)(ISO7816.OFFSET_CDATA + dataOffset), remainingData);
        if (result == Transaction.RESULT_ERROR) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        else
        if (result == Transaction.RESULT_MORE) {
            saveState();
            return;
        }
        else
        if (result == Transaction.RESULT_FINISHED) {
            saveState();
            return;
        }        
    }
    
    private static short addTransactionOutput(byte[] buffer, short offset, byte[] hash160Address, short hash160Offset, byte[] amount, short amountOffset, boolean isP2sh) {
        byte[] pre = (isP2sh ? TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE : TRANSACTION_OUTPUT_SCRIPT_PRE);
        byte[] post = (isP2sh ? TRANSACTION_OUTPUT_SCRIPT_P2SH_POST : TRANSACTION_OUTPUT_SCRIPT_POST);
        Uint64Helper.swap(buffer, offset, amount, amountOffset);
        offset += 8;
        offset = Util.arrayCopyNonAtomic(pre, (short)0, buffer, offset, (short)pre.length);
        offset = Util.arrayCopyNonAtomic(hash160Address, hash160Offset, buffer, offset, TC.SIZEOF_RIPEMD);
        offset = Util.arrayCopyNonAtomic(post, (short)0, buffer, offset, (short)post.length);
        return offset;
    }
    
    private static short writeAmount(short textOffset, short amountOffset, short addressOffset) {
        textOffset = BCDUtils.hexAmountToDisplayable(TC.ctx, amountOffset, LWNFCForumApplet.FILE_DATA, textOffset);
        LWNFCForumApplet.FILE_DATA[textOffset++] = TEXT_SPACE;
        textOffset = Util.arrayCopyNonAtomic(TEXT_BTC, (short)0, LWNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_BTC.length);
        LWNFCForumApplet.FILE_DATA[textOffset++] = TEXT_SPACE;                
        textOffset = Util.arrayCopyNonAtomic(TEXT_TO, (short)0, LWNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_TO.length);
        // Recompute the key checksum in place as an additional sanity check
        Util.arrayCopyNonAtomic(TC.ctx, addressOffset, scratch256, (short)0, (short)(TC.SIZEOF_RIPEMD + 1));
        Crypto.digestScratch.doFinal(scratch256, (short)0, (short)(TC.SIZEOF_RIPEMD + 1), scratch256, (short)(TC.SIZEOF_RIPEMD + 1));
        Crypto.digestScratch.doFinal(scratch256, (short)(TC.SIZEOF_RIPEMD + 1), TC.SIZEOF_SHA256, scratch256, (short)(TC.SIZEOF_RIPEMD + 1));
        textOffset = Base58.encode(scratch256, (short)0, (short)(TC.SIZEOF_RIPEMD + 1 + 4), LWNFCForumApplet.FILE_DATA, textOffset, scratch256, (short)100);
        return textOffset;
    }

    private static void handleHashOutput(APDU apdu) throws ISOException {
    	// Stack size just fits JCOP 2.4.2 when deriving - be careful when adding local variables
        byte[] buffer = apdu.getBuffer(); 
        apdu.setIncomingAndReceive();
        checkInterfaceConsistency();
        restoreState();
        if (TC.ctx[TC.TX_B_TRANSACTION_STATE] != Transaction.STATE_PRESIGN_READY) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (isFirstSigned()) {
        	byte i;
            if ((short)(buffer[ISO7816.OFFSET_LC] & 0xff) < (short)(1 + 1 + 1 + 8 + 8)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            switch(buffer[ISO7816.OFFSET_P1]) {
                case P1_HASH_OUTPUT_BASE58:
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            short offset = (short)(ISO7816.OFFSET_CDATA);            
            byte addressLength = buffer[offset++];
            short decodedLength = Base58.decode(buffer, offset, addressLength, scratch256, (short)0, scratch256, (short)100);
            if (decodedLength < 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            switch(scratch256[0]) {
                case KEY_VERSION:
                case KEY_VERSION_TESTNET:
                    break;
                case KEY_VERSION_P2SH:
                case KEY_VERSION_P2SH_TESTNET:
                    TC.ctx[TC.TX_Z_IS_P2SH] = TC.TRUE;
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);    
            }
            verifyKeyChecksum(scratch256, (short)0, decodedLength, scratch256, (short)100);
            Util.arrayCopyNonAtomic(scratch256, (short)0, TC.ctx, TC.TX_A_AUTH_OUTPUT_ADDRESS, (short)(TC.SIZEOF_RIPEMD + 1));
            offset += addressLength;
            Util.arrayCopyNonAtomic(buffer, offset, TC.ctx, TC.TX_A_AUTH_OUTPUT_AMOUNT, TC.SIZEOF_AMOUNT);
            offset += TC.SIZEOF_AMOUNT;
            Util.arrayCopyNonAtomic(buffer, offset, TC.ctx, TC.TX_A_AUTH_FEE_AMOUNT, TC.SIZEOF_AMOUNT);
            offset += TC.SIZEOF_AMOUNT;
            // Compute change == totalInputs - (amount + fees)
            Uint64Helper.add(scratch256, (short)240, TC.ctx, TC.TX_A_AUTH_OUTPUT_AMOUNT, TC.ctx, TC.TX_A_AUTH_FEE_AMOUNT);
            Uint64Helper.sub(TC.ctx, TC.TX_A_AUTH_CHANGE_AMOUNT, TC.ctx, TC.TX_A_TRANSACTION_AMOUNT, scratch256, (short)240);                        
            TC.ctx[TC.TX_Z_HAS_CHANGE] = (Uint64Helper.isZero(TC.ctx, TC.TX_A_AUTH_CHANGE_AMOUNT) ? TC.FALSE : TC.TRUE);            
        	addressLength = buffer[offset++];
        	if (addressLength > MAX_DERIVATION_PATH) {
        		ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        	}
        	if (TC.ctx[TC.TX_Z_HAS_CHANGE] == TC.TRUE) {
        		// Unwrap the initial seed
        		Crypto.initCipher(chipKey, false);
        		Crypto.blobEncryptDecrypt.doFinal(masterDerived, (short)0, (short)DEFAULT_SEED_LENGTH, scratch256, (short)0);            
        		// Derive all components            
        		i = Bip32Cache.copyPrivateBest(buffer, offset, addressLength, scratch256, (short)0);
        		for (; i<addressLength; i++) {
        			Util.arrayCopyNonAtomic(buffer, (short)(offset + 4 * i), scratch256, Bip32.OFFSET_DERIVATION_INDEX, (short)4);
        			if ((proprietaryAPI == null) && ((scratch256[Bip32.OFFSET_DERIVATION_INDEX] & (byte)0x80) == 0)) {
        				if (!Bip32Cache.setPublicIndex(buffer, (short)(offset + 4 * i), (byte)(i + 1))) {
        					ISOException.throwIt(SW_PUBLIC_POINT_NOT_AVAILABLE);
        				}	
        			}            	
        			Bip32.derive(buffer);
        			Bip32Cache.storePrivate(buffer, (short)(offset + 4 * i), (byte)(i + 1), scratch256);
        		}
        		if (proprietaryAPI == null) {
        			if (!Bip32Cache.setPublicIndex(buffer, offset, addressLength)) {
        				ISOException.throwIt(SW_PUBLIC_POINT_NOT_AVAILABLE);
        			}
        			Bip32Cache.copyLastPublic(scratch256, (short)0);
        		}
        		else {
        			proprietaryAPI.getUncompressedPublicPoint(scratch256, (short)0, scratch256, (short)0);
        		}
        	}
            offset += (short)(4 * addressLength);                                                        
            // TODO : handle OP_RETURN
            /*
            byte opReturnSize = buffer[offset++];
            if (opReturnSize != 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);                	
            }
            */
            if (buffer[offset++] != 0) {
            	ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            // Enforce limits
            if (TC.ctxP[TC.P_TX_Z_USED] == TC.FALSE) {
                // Amount
                Uint64Helper.sub(scratch256, (short)200, limits, LIMIT_GLOBAL_AMOUNT, TC.ctx, TC.TX_A_AUTH_OUTPUT_AMOUNT);
                Util.arrayCopy(scratch256, (short)200, limits, LIMIT_GLOBAL_AMOUNT, TC.SIZEOF_AMOUNT);
                // Fees
                Uint64Helper.sub(scratch256, (short)200, limits, LIMIT_MAX_FEES, TC.ctx, TC.TX_A_AUTH_FEE_AMOUNT);
                // Change
                if (TC.ctx[TC.TX_Z_HAS_CHANGE] == TC.TRUE) {
                    Uint64Helper.sub(scratch256, (short)200, limits, LIMIT_MAX_CHANGE, TC.ctx, TC.TX_A_AUTH_CHANGE_AMOUNT);    
                }
            }            
            if (TC.ctx[TC.TX_Z_HAS_CHANGE] == TC.TRUE) {
                // Compute the change address - significant performance hit if not using a native RIPEMD160
            	AddressUtils.compressPublicKey(scratch256, (short)0);
                Crypto.digestScratch.doFinal(scratch256, (short)0, (short)33, scratch256, (short)0);
                TC.ctx[TC.TX_A_AUTH_CHANGE_ADDRESS] = KEY_VERSION; // force main net
                if (Crypto.digestRipemd != null) {
                	Crypto.digestRipemd.doFinal(scratch256, (short)0, (short)32, TC.ctx, (short)(TC.TX_A_AUTH_CHANGE_ADDRESS + 1));
                }
                else {
                	Ripemd160.hash32(scratch256, (short)0, TC.ctx, (short)(TC.TX_A_AUTH_CHANGE_ADDRESS + 1), scratch256, (short)33);
                }
            }            
            if (TC.ctxP[TC.P_TX_Z_USED] == TC.TRUE) {
                Util.arrayCopy(TC.ctx, TC.TX_A_AUTH_NONCE, TC.ctxP, TC.P_TX_A_AUTH_NONCE, TC.TX_AUTH_CONTEXT_SIZE);
                TC.ctxP[TC.P_TX_Z_HAS_CHANGE] = TC.ctx[TC.TX_Z_HAS_CHANGE];
                TC.ctxP[TC.P_TX_Z_IS_P2SH] = TC.ctx[TC.TX_Z_IS_P2SH];
            }
        }
        short dataOffset = 0;
        short outOffset = 0;
        // TODO : randomize output position
        scratch256[dataOffset++] = ((TC.ctx[TC.TX_Z_HAS_CHANGE] == TC.TRUE) ? (byte)2 : (byte)1);
        dataOffset = addTransactionOutput(scratch256, dataOffset, TC.ctx, (short)(TC.TX_A_AUTH_OUTPUT_ADDRESS + 1), TC.ctx, TC.TX_A_AUTH_OUTPUT_AMOUNT, (TC.ctx[TC.TX_Z_IS_P2SH] == TC.TRUE));
        if (TC.ctx[TC.TX_Z_HAS_CHANGE] == TC.TRUE) {
            dataOffset = addTransactionOutput(scratch256, dataOffset, TC.ctx, (short)(TC.TX_A_AUTH_CHANGE_ADDRESS + 1), TC.ctx, TC.TX_A_AUTH_CHANGE_AMOUNT, false);
        }
        // Update the main hash
        Crypto.digestFull.update(scratch256, (short)0, dataOffset);
        // Always return the output
        buffer[outOffset++] = (byte)dataOffset;
        Util.arrayCopyNonAtomic(scratch256, (short)0, buffer, outOffset, dataOffset);
        outOffset += dataOffset;
        if (isFirstSigned()) {
        	buffer[outOffset++] = AUTHORIZATION_NFC;
        }
        else {
            buffer[outOffset++] = (byte)0;
        }
        // Update the authorization hash and check it if necessary
        Crypto.digestAuthorization.doFinal(TC.ctx, TC.TX_A_AUTH_NONCE, TC.TX_AUTH_CONTEXT_SIZE, scratch256, (short)0);
        if (isFirstSigned()) {
            Util.arrayCopyNonAtomic(scratch256, (short)0, TC.ctx, TC.TX_A_AUTHORIZATION_HASH, TC.SIZEOF_SHA256);
            TC.ctx[TC.TX_Z_FIRST_SIGNED] = TC.FALSE;            
            if (TC.ctxP[TC.P_TX_Z_USED] == TC.TRUE) {                
                Util.arrayCopyNonAtomic(scratch256, (short)0, TC.ctxP, TC.P_TX_A_AUTHORIZATION_HASH, TC.SIZEOF_SHA256);
                // First signature in contact mode - prepare the confirmation text and PIN
                TC.ctxP[TC.P_TX_Z_FIRST_SIGNED] = TC.FALSE;
                short textOffset = LWNFCForumApplet.OFFSET_TEXT;
                textOffset = Util.arrayCopyNonAtomic(TEXT_CONFIRM, (short)0, LWNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_CONFIRM.length);
                textOffset = writeAmount(textOffset, TC.TX_A_AUTH_OUTPUT_AMOUNT, TC.TX_A_AUTH_OUTPUT_ADDRESS);
                LWNFCForumApplet.FILE_DATA[textOffset++] = TEXT_SPACE;                
                textOffset = Util.arrayCopyNonAtomic(TEXT_FEES, (short)0, LWNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_FEES.length);
                textOffset = BCDUtils.hexAmountToDisplayable(TC.ctx, TC.TX_A_AUTH_FEE_AMOUNT, LWNFCForumApplet.FILE_DATA, textOffset);                
                LWNFCForumApplet.FILE_DATA[textOffset++] = TEXT_SPACE;
                textOffset = Util.arrayCopyNonAtomic(TEXT_BTC, (short)0, LWNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_BTC.length);
                LWNFCForumApplet.FILE_DATA[textOffset++] = TEXT_COMMA;
                if (TC.ctx[TC.TX_Z_HAS_CHANGE] == TC.FALSE) {
                    textOffset = Util.arrayCopyNonAtomic(TEXT_NO_CHANGE, (short)0, LWNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_NO_CHANGE.length);
                }
                else {
                    textOffset = Util.arrayCopyNonAtomic(TEXT_CHANGE, (short)0, LWNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_CHANGE.length);
                    LWNFCForumApplet.FILE_DATA[textOffset++] = TEXT_SPACE;
                    textOffset = writeAmount(textOffset, TC.TX_A_AUTH_CHANGE_AMOUNT, TC.TX_A_AUTH_CHANGE_ADDRESS);                    
                }
                LWNFCForumApplet.FILE_DATA[textOffset++] = TEXT_CLOSE_P;
                LWNFCForumApplet.FILE_DATA[textOffset++] = TEXT_SPACE;
                textOffset = Util.arrayCopyNonAtomic(TEXT_PIN, (short)0, LWNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_PIN.length);
                Crypto.random.generateData(scratch256, (short)0, TRANSACTION_PIN_SIZE);
                for (byte i=0; i<TRANSACTION_PIN_SIZE; i++) {
                    scratch256[i] = (byte)((short)((scratch256[i] & 0xff)) % 10);
                    scratch256[i] += (byte)'0';
                }
                transactionPin.resetAndUnblock();
                transactionPin.update(scratch256, (short)0, TRANSACTION_PIN_SIZE);
                textOffset = Util.arrayCopyNonAtomic(scratch256, (short)0, LWNFCForumApplet.FILE_DATA, textOffset, TRANSACTION_PIN_SIZE);
                LWNFCForumApplet.writeHeader((short)(textOffset - LWNFCForumApplet.OFFSET_TEXT));
            }
        }
        else {            
            if (Util.arrayCompare(scratch256, (short)0, TC.ctx, TC.TX_A_AUTHORIZATION_HASH, TC.SIZEOF_SHA256) != 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        }
        TC.ctx[TC.TX_B_TRANSACTION_STATE] = Transaction.STATE_SIGN_READY;
        saveState();
        apdu.setOutgoingAndSend((short)0, outOffset);                
    }
    
    private static void handleHashSign(APDU apdu) throws ISOException {    	
        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;
        byte i;
        apdu.setIncomingAndReceive();
        checkInterfaceConsistency();
        restoreState();
        if (TC.ctx[TC.TX_B_TRANSACTION_STATE] != Transaction.STATE_SIGN_READY) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    	byte derivationSize = buffer[offset++];
    	if (derivationSize > MAX_DERIVATION_PATH) {
    		ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    	}
    	// Unwrap the initial seed
        Crypto.initCipher(chipKey, false);
        Crypto.blobEncryptDecrypt.doFinal(masterDerived, (short)0, (short)DEFAULT_SEED_LENGTH, scratch256, (short)0);
        // Derive all components
        i = Bip32Cache.copyPrivateBest(buffer, (short)(ISO7816.OFFSET_CDATA + 1), derivationSize, scratch256, (short)0);
        offset += (short)(i * 4);
        for (; i<derivationSize; i++) {
        	Util.arrayCopyNonAtomic(buffer, offset, scratch256, Bip32.OFFSET_DERIVATION_INDEX, (short)4);
        	if ((proprietaryAPI == null) && ((scratch256[Bip32.OFFSET_DERIVATION_INDEX] & (byte)0x80) == 0)) {
        		if (!Bip32Cache.setPublicIndex(buffer, (short)(ISO7816.OFFSET_CDATA + 1), (byte)(i + 1))) {
        			ISOException.throwIt(SW_PUBLIC_POINT_NOT_AVAILABLE);
        		}
        	}        	
        	Bip32.derive(buffer);
        	Bip32Cache.storePrivate(buffer, (short)(ISO7816.OFFSET_CDATA + 1), (byte)(i + 1), scratch256);
        	offset += (short)4;
        }
        short authorizationLength = (short)(buffer[offset++] & 0xff);    
        // Check the PIN if the transaction was started in contact mode
        if (TC.ctxP[TC.P_TX_Z_USED] == TC.TRUE) {
            // Clear the text
            writeIdleText();
            if (!transactionPin.check(buffer, offset, (byte)authorizationLength)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        }
        offset += authorizationLength;        
        // Copy lockTime        
        Uint32Helper.swap(scratch256, (short)100, buffer, offset);
        offset += 4;
        // Copy sigHashType
        byte sigHashType = buffer[offset++];
        Uint32Helper.clear(scratch256, (short)104);
        scratch256[(short)104] = sigHashType;        
        // Compute the signature
        Crypto.digestFull.doFinal(scratch256, (short)100, (short)8, scratch256, (short)100);
        Crypto.signTransientPrivate(scratch256, (short)0, scratch256, (short)100, buffer, (short)0);
        short signatureSize = (short)((short)(buffer[1] & 0xff) + 2);
        buffer[signatureSize] = sigHashType;
        // TODO : reset transaction state
        saveState();
        apdu.setOutgoingAndSend((short)0, (short)(signatureSize + 1));
    }
    
    private static void handleSetup(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;
        byte keyLength;
        apdu.setIncomingAndReceive();
        if ((setup == TC.TRUE) || (setup != TC.FALSE)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (buffer[ISO7816.OFFSET_P1] != P1_REGULAR_SETUP) {
        	ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        supportedModes = buffer[offset++];
        for (byte i=0; i<(byte)AVAILABLE_MODES.length; i++) {
        	if ((supportedModes & AVAILABLE_MODES[i]) != 0) {
        		currentMode = AVAILABLE_MODES[i];
        		break;
        	}
        }
        features = buffer[offset++];
        if ((features & FEATURE_UNCOMPRESSED_KEYS) != 0) {
        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        stdVersion = buffer[offset++];
        p2shVersion = buffer[offset++];
        walletPinSize = buffer[offset++];
        if (walletPinSize < 4) {
        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        Util.arrayFillNonAtomic(scratch256, (short)0, WALLET_PIN_SIZE, (byte)0xff);
        Util.arrayCopyNonAtomic(buffer, offset, scratch256, (short)0, walletPinSize);
        walletPin.update(scratch256, (short)0, WALLET_PIN_SIZE);
        walletPin.resetAndUnblock();
        offset += walletPinSize;
        secondaryPinSize = buffer[offset++];
        if (secondaryPinSize != 0) {
            Util.arrayFillNonAtomic(scratch256, (short)0, SECONDARY_PIN_SIZE, (byte)0xff);
            Util.arrayCopyNonAtomic(buffer, offset, scratch256, (short)0, secondaryPinSize);
            secondaryPin.update(scratch256, (short)0, SECONDARY_PIN_SIZE);
            secondaryPin.resetAndUnblock();
            offset += secondaryPinSize;        	
        }
        keyLength = buffer[offset++];
        if (keyLength == 0) {
        	keyLength = DEFAULT_SEED_LENGTH;
        	Crypto.random.generateData(scratch256, (short)0, keyLength);
        	short textOffset = LWNFCForumApplet.OFFSET_TEXT;
        	textOffset = Util.arrayCopyNonAtomic(TEXT_SEED, (short)0, LWNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_SEED.length);
        	for (byte i=0; i<DEFAULT_SEED_LENGTH; i++) {
        		LWNFCForumApplet.FILE_DATA[textOffset++] = HEX[(scratch256[i] >> 4) & 0x0f];
        		LWNFCForumApplet.FILE_DATA[textOffset++] = HEX[scratch256[i] & 0x0f];
        	}
        	LWNFCForumApplet.writeHeader((short)(textOffset - LWNFCForumApplet.OFFSET_TEXT));
        	LWNFCForumApplet.erase = true;
        }
        else {
        	if ((keyLength < 0) || (keyLength > DEFAULT_SEED_LENGTH)) {
        		ISOException.throwIt(ISO7816.SW_DATA_INVALID);	
        	}
        	Util.arrayCopyNonAtomic(buffer, offset, scratch256, (short)0, keyLength);
        }
        Bip32.deriveSeed(keyLength);
        Crypto.initCipher(chipKey, true);
        Crypto.blobEncryptDecrypt.doFinal(masterDerived, (short)0, (short)DEFAULT_SEED_LENGTH, masterDerived, (short)0);
        offset += keyLength;
        if ((supportedModes & MODE_DEVELOPER) != 0) {
        	keyLength = buffer[offset++];
        	if (keyLength == 0) {
                Crypto.random.generateData(scratch256, (short)0, (short)16);
                developerKey.setKey(scratch256, (short)0);        		
        	}
        	else {
            	if (keyLength != 16) {
            		ISOException.throwIt(ISO7816.SW_DATA_INVALID);	
            	}
            	developerKey.setKey(buffer, offset);
        	}
        }
        Crypto.random.generateData(scratch256, (short)0, (short)16);
        trustedInputKey.setKey(scratch256, (short)0);        		
        offset = 0;
        buffer[offset++] = SEED_NOT_TYPED;
        if ((supportedModes & MODE_DEVELOPER) != 0) {
        	trustedInputKey.getKey(buffer, offset);
        	offset += (short)16;
        	developerKey.getKey(buffer, offset);
        	offset += (short)16;
        }
        apdu.setOutgoingAndSend((short)0, offset);
        setup = TC.TRUE;
    }
    
    private static void handleVerifyPin(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_P1] == P1_GET_REMAINING_ATTEMPTS) {
        	buffer[0] = walletPin.getTriesRemaining();
        	apdu.setOutgoingAndSend((short)0, (short)1);
        	return;
        }
        apdu.setIncomingAndReceive();
        if ((setup == TC.FALSE) || (setup != TC.TRUE)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (buffer[ISO7816.OFFSET_LC] != walletPinSize) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayFillNonAtomic(scratch256, (short)0, WALLET_PIN_SIZE, (byte)0xff);
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, scratch256, (short)0, walletPinSize);        
        if (!walletPin.check(scratch256, (short)0, WALLET_PIN_SIZE)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }        

    private static void handleGetContactlessLimit(APDU apdu) throws ISOException {
        if ((setup == TC.FALSE) || (setup != TC.TRUE)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        Util.arrayCopyNonAtomic(limits, (short)0, scratch256, (short)0, LIMIT_LAST);
        apdu.setOutgoingAndSend((short)0, LIMIT_LAST);
    }
    
    private static void handleSetContactlessLimit(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();        
        if (isContactless()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (buffer[ISO7816.OFFSET_LC] != LIMIT_LAST) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, limits, (short)0, LIMIT_LAST);
        if (limitsSet != TC.TRUE) {
            limitsSet = TC.TRUE;
        }
    }
    
    private static void handleGetFirmwareVersion(APDU apdu) throws ISOException {
    	byte[] buffer = apdu.getBuffer();
    	Util.arrayCopyNonAtomic(FIRMWARE_VERSION, (short)0, buffer, (short)0, (short)FIRMWARE_VERSION.length);
    	apdu.setOutgoingAndSend((short)0, (short)FIRMWARE_VERSION.length);
    }
    
    private static void handleGetOperationMode(APDU apdu) throws ISOException { 
    	byte[] buffer = apdu.getBuffer();
    	if (buffer[ISO7816.OFFSET_P1] == P1_GET_OPERATION_MODE) {
    		buffer[0] = currentMode;
    	}
    	else
    	if (buffer[ISO7816.OFFSET_P1] == P1_GET_OPERATION_MODE_2FA) {
    		buffer[0] = SFA_NFC;
    	}
    	apdu.setOutgoingAndSend((short)0, (short)1);    	
    }
       
    public static void clearScratch() {
        Util.arrayFillNonAtomic(scratch256, (short)0, (short)scratch256.length, (byte)0x00);
    }
    
    public void process(APDU apdu) throws ISOException {    	
        if (selectingApplet()) {
        	if (LWNFCForumApplet.erase) {
        		writeIdleText();
        		LWNFCForumApplet.erase = false;
        	}
            return;
        }
        byte[] buffer = apdu.getBuffer();
        
        if (buffer[ISO7816.OFFSET_CLA] == CLA_BTC) {
            clearScratch();
            try {
                switch(buffer[ISO7816.OFFSET_INS]) {
                    case INS_SETUP:
                        handleSetup(apdu);                        
                        break;           
                    case INS_VERIFY_PIN:
                    	handleVerifyPin(apdu);
                    	break;
                    case INS_GET_WALLET_PUBLIC_KEY:
                    	checkAccess(true);
                    	handleGetWalletPublicKey(apdu);
                    	break;
                    case INS_GET_CONTACTLESS_LIMIT:
                        handleGetContactlessLimit(apdu);
                        break;
                    case INS_SET_CONTACTLESS_LIMIT:
                        checkAccess(true);
                        handleSetContactlessLimit(apdu);
                        break;            
                    case INS_GET_TRUSTED_INPUT:
                        checkAccess(false);
                        handleTrustedInput(apdu);
                        break;
                    case INS_UNTRUSTED_HASH_START:
                        handleHashTransaction(apdu);
                        break;
                    case INS_UNTRUSTED_HASH_FINALIZE:
                        handleHashOutput(apdu);
                        break;
                    case INS_UNTRUSTED_HASH_SIGN:
                        handleHashSign(apdu);
                        break;                   
                    case INS_GET_FIRMWARE_VERSION:
                    	handleGetFirmwareVersion(apdu);
                        break;
                    case INS_GET_OPERATION_MODE:
                    	handleGetOperationMode(apdu);
                    	break;
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
            }
            catch(Exception e) {
                //e.printStackTrace();
                // Abort the current transaction if an exception is thrown
                TC.clear();
                if (e instanceof CardRuntimeException) {
                    throw ((CardRuntimeException)e);
                }
                else {
                    ISOException.throwIt(ISO7816.SW_UNKNOWN);
                }
            }
            finally {
                clearScratch();
            }
            return;
        }        
    }

    public static void install (byte bArray[], short bOffset, byte bLength) throws ISOException {
        new LedgerWalletApplet().register(bArray, (short)(bOffset + 1), bArray[bOffset]);
    }
    
    private static final byte FIRMWARE_VERSION[] = {
    	(byte)0x01, (byte)0x60, (byte)0x01, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00
    };
    
    protected static final short SW_PUBLIC_POINT_NOT_AVAILABLE = (short)0x6FF6;
 
    private static final byte TRANSACTION_PIN_ATTEMPTS = (byte)1;
    private static final byte TRANSACTION_PIN_SIZE = (byte)4;
    private static final byte WALLET_PIN_ATTEMPTS = (byte)3;
    private static final byte WALLET_PIN_SIZE = (byte)32;
    private static final byte SECONDARY_PIN_ATTEMPTS = (byte)3;
    private static final byte SECONDARY_PIN_SIZE = (byte)4;
    

    private static final byte TEXT_IDLE[] = { 'N', 'o', ' ', 'p', 'e', 'n', 'd', 'i', 'n', 'g', ' ', 't', 'r', 'a', 'n', 's', 'f', 'e', 'r' };
    private static final byte TEXT_CONFIRM[] = { 'C', 'o', 'n', 'f', 'i', 'r', 'm', ' ', 't', 'r', 'a', 'n', 's', 'f', 'e', 'r', ' ', 'o', 'f', ' ' };
    private static final byte TEXT_BTC[] = { 'B', 'T', 'C' };
    private static final byte TEXT_TO[] = { 't', 'o', ' ' };
    private static final byte TEXT_FEES[] = { '(', 'f', 'e', 'e', 's', ' ' };
    private static final byte TEXT_NO_CHANGE[] = { 'n', 'o', ' ', 'c', 'h', 'a', 'n', 'g', 'e' };
    private static final byte TEXT_CHANGE[] = { 'c', 'h', 'a', 'n', 'g', 'e' };
    private static final byte TEXT_PIN[] = { 'w', 'i', 't', 'h', ' ', 'P', 'I', 'N', ' ' };
    private static final byte TEXT_CLOSE_P = ')';
    private static final byte TEXT_SPACE = ' ';
    private static final byte TEXT_COMMA = ',';
    private static final byte TEXT_SEED[] = { 'W','a','l','l','e','t',' ', 'S','e','e','d', ':', ' ' };
    
    private static final byte HEX[] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
    
    private static final byte AUTHORIZATION_NFC = (byte)0x04;
        
    private static final byte TRANSACTION_OUTPUT_SCRIPT_PRE[] = { (byte)0x19, (byte)0x76, (byte)0xA9, (byte)0x14 }; // script length, OP_DUP, OP_HASH160, address length
    private static final byte TRANSACTION_OUTPUT_SCRIPT_POST[] = { (byte)0x88, (byte)0xAC }; // OP_EQUALVERIFY, OP_CHECKSIG
    private static final byte TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE[] = { (byte)0x17, (byte)0xA9, (byte)0x14 }; // script length, OP_HASH160, address length
    private static final byte TRANSACTION_OUTPUT_SCRIPT_P2SH_POST[] = { (byte)0x87 }; // OP_EQUAL
    private static final byte KEY_VERSION_P2SH = (byte)0x05;
    private static final byte KEY_VERSION_P2SH_TESTNET = (byte)0xC4;
    private static final byte KEY_VERSION_PRIVATE = (byte)0x80;
    private static final byte KEY_VERSION = (byte)0x00;
    private static final byte KEY_VERSION_TESTNET = (byte)0x6F;
    
    private static final byte PUBLIC_KEY_W_LENGTH = 65;
    private static final byte PRIVATE_KEY_S_LENGTH = 32;
    
    private static final byte CLA_BTC = (byte)0xE0;
    private static final byte INS_SETUP = (byte)0x20;
    private static final byte INS_SET_USER_KEYCARD = (byte)0x10;
    private static final byte INS_SETUP_SECURE_SCREEN = (byte)0x12;
    private static final byte INS_SET_ALTERNATE_COIN_VERSIONS = (byte)0x14;
    private static final byte INS_VERIFY_PIN = (byte)0x22;
    private static final byte INS_GET_OPERATION_MODE = (byte)0x24;
    private static final byte INS_SET_OPERATION_MODE = (byte)0x26;
    private static final byte INS_GET_WALLET_PUBLIC_KEY = (byte)0x40;
    private static final byte INS_GET_TRUSTED_INPUT = (byte)0x42;
    private static final byte INS_UNTRUSTED_HASH_START = (byte)0x44;
    private static final byte INS_UNTRUSTED_HASH_FINALIZE = (byte)0x46;
    private static final byte INS_UNTRUSTED_HASH_SIGN = (byte)0x48;
    private static final byte INS_UNTRUSTED_HASH_FINALIZE_FULL = (byte)0x4A;
    private static final byte INS_SIGN_MESSAGE = (byte)0x4E;
    private static final byte INS_IMPORT_PRIVATE_KEY = (byte)0xB0;
    private static final byte INS_GET_PUBLIC_KEY = (byte)0xB2;
    private static final byte INS_DERIVE_BIP32_KEY = (byte)0xB4;
    private static final byte INS_SIGN_VERIFY_IMMEDIATE = (byte)0xB6;
    private static final byte INS_GET_RANDOM = (byte)0xC0;
    private static final byte INS_GET_ATTESTATION = (byte)0xC2;
    private static final byte INS_GET_FIRMWARE_VERSION = (byte)0xC4;   
    		
    private static final byte INS_GENERATE = (byte)0x20;
    private static final byte INS_SET_CONTACTLESS_LIMIT = (byte)0xA4;
    private static final byte INS_GET_CONTACTLESS_LIMIT = (byte)0xA6;

    private static final byte P1_REGULAR_SETUP = (byte)0x00;
    
    private static final byte P1_TRUSTED_INPUT_FIRST = (byte)0x00;
    private static final byte P1_TRUSTED_INPUT_NEXT = (byte)0x80;
    
    private static final byte P1_HASH_TRANSACTION_FIRST = (byte)0x00;
    private static final byte P1_HASH_TRANSACTION_NEXT = (byte)0x80;
    private static final byte P2_HASH_TRANSACTION_NEW_INPUT = (byte)0x00;
    private static final byte P2_HASH_TRANSACTION_CONTINUE_INPUT = (byte)0x80;
    
    private static final byte P1_HASH_OUTPUT_HASH160 = (byte)0x01;
    private static final byte P1_HASH_OUTPUT_BASE58 = (byte)0x02;
    private static final byte P1_HASH_OUTPUT_AUTHORIZED_ADDRESS = (byte)0x03;
    private static final byte P1_HASH_OUTPUT_HASH160_P2SH = (byte)0x04;
    
    private static final byte P1_GET_REMAINING_ATTEMPTS = (byte)0x80;
    
    private static final byte P1_GET_OPERATION_MODE = (byte)0x00;
    private static final byte P1_GET_OPERATION_MODE_2FA = (byte)0x01;
            
    public static final byte BLOB_MAGIC_TRUSTED_INPUT = (byte)0x32;
    
    private static final byte LIMIT_GLOBAL_AMOUNT = (byte)0;
    private static final byte LIMIT_MAX_FEES = (byte)(LIMIT_GLOBAL_AMOUNT + TC.SIZEOF_AMOUNT);
    private static final byte LIMIT_MAX_CHANGE = (byte)(LIMIT_MAX_FEES + TC.SIZEOF_AMOUNT);
    private static final byte LIMIT_LAST = (byte)(LIMIT_MAX_CHANGE + TC.SIZEOF_AMOUNT);
    
    private static final byte MODE_WALLET = (byte)0x01;
    private static final byte MODE_RELAXED_WALLET = (byte)0x02;
    private static final byte MODE_SERVER = (byte)0x04;
    private static final byte MODE_DEVELOPER = (byte)0x08;
    
    private static final byte SFA_NONE = (byte)0x00;
    private static final byte SFA_ORIGINAL = (byte)0x11;
    private static final byte SFA_SECURITY_CARD = (byte)0x12;
    private static final byte SFA_SECURE_SCREEN = (byte)0x13;
    private static final byte SFA_NFC = (byte)0x20;
    
    private static final byte FEATURE_UNCOMPRESSED_KEYS = (byte)0x01;
    private static final byte FEATURE_RFC_6979 = (byte)0x02;
    private static final byte FEATURE_ALL_HASHTYPES = (byte)0x04;
    private static final byte FEATURE_NO_2FA_P2SH = (byte)0x08;
    
    private static final byte DEFAULT_SEED_LENGTH = (byte)64;
    
    private static final byte MAX_DERIVATION_PATH = (byte)10;
    
    private static final byte SEED_NOT_TYPED = (byte)0x00;
    
    private static final byte AVAILABLE_MODES[] = { MODE_WALLET, MODE_RELAXED_WALLET, MODE_SERVER, MODE_DEVELOPER };
        
    public static byte[] scratch256;
    private static OwnerPIN transactionPin;
    private static OwnerPIN walletPin;
    private static byte walletPinSize;
    private static OwnerPIN secondaryPin;
    private static byte secondaryPinSize;
    private static byte setup;
    private static byte limitsSet;
    private static DESKey chipKey;
    protected static DESKey trustedInputKey;
    protected static DESKey developerKey;
    private static byte supportedModes;
    protected static byte features;
    protected static byte currentMode;
    private static byte stdVersion;
    private static byte p2shVersion;
    protected static byte[] masterDerived;   
    private static byte[] limits;    
    protected static ProprietaryAPI proprietaryAPI;
}
