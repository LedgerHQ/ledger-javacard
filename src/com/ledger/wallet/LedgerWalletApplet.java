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

// TODO : Add storage of change address

package com.btchip.applet.poc;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;

/**
 * Hardware Wallet applet
 * @author BTChip
 *
 */
public class BTChipPocApplet extends Applet {
    
    public BTChipPocApplet() {
        BCDUtils.init();
        TC.init();
        Crypto.init();
        Transaction.init();
        limits = new byte[LIMIT_LAST];
        scratch255 = JCSystem.makeTransientByteArray((short)255, JCSystem.CLEAR_ON_DESELECT);
        transactionPin = new OwnerPIN(TRANSACTION_PIN_ATTEMPTS, TRANSACTION_PIN_SIZE);
        walletPin = new OwnerPIN(WALLET_PIN_ATTEMPTS, WALLET_PIN_SIZE);
        TC.ctxP[TC.P_TX_Z_USED] = TC.FALSE;
        setup = TC.FALSE;
        limitsSet = TC.FALSE;
    }
    
    protected static void writeIdleText() {
        short offset = Util.arrayCopyNonAtomic(TEXT_IDLE, (short)0, BTChipNFCForumApplet.FILE_DATA, BTChipNFCForumApplet.OFFSET_TEXT, (short)TEXT_IDLE.length);
        BTChipNFCForumApplet.writeHeader((short)(offset - BTChipNFCForumApplet.OFFSET_TEXT));
    }
    
    protected static boolean isContactless() {
        return ((APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK) == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A);                
    }
    
    private static void checkAccess() {
        if ((setup == TC.FALSE) || (setup != TC.TRUE)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (!isContactless() && !walletPin.isValidated()) {
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
        
    private static void handleGenerate(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];
        short offset = ISO7816.OFFSET_CDATA;
        short scratchOffset = (short)0;
        ECPublicKey publicKey = null;
        short publicKeyOffset = (short)0;
        boolean prepare = ((p1 & P1_GENERATE_PREPARE) != 0);
        apdu.setIncomingAndReceive();
        // PoC only supports generate + import, and does not generate integrity data or authorized addresses
        // Also, generation is always done for main net when used for change
        if (prepare) {
            if (((p1 & P1_GENERATE_PREPARE_DERIVE) != 0) ||
                ((p1 & P1_GENERATE_PREPARE_HASH) != 0) ||
                ((p1 & P1_GENERATE_PREPARE_UID) != 0) ||
                ((p1 & P1_GENERATE_PROVIDE_AUTHORIZED_KEY) != 0) ||
                ((p1 & P1_GENERATE_PREPARE_BASE58) != 0) ||
                ((p1 & P1_GENERATE_PREPARE_BIN) == 0)) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
        }
        WrappingKeyRepository.WrappingKey encryptionKey = WrappingKeyRepository.find(buffer[offset++], WrappingKeyRepository.ROLE_PRIVATE_KEY_ENCRYPTION);
        if (encryptionKey == null) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // Drop signature keyset
        offset++;
        // Drop flags
        offset++;
        // Drop curve ID
        offset += 2;
        // Prepare the private key blob
        scratch255[scratchOffset++] = BLOB_MAGIC_PRIVATE_KEY_WITH_PUB;
        scratch255[scratchOffset++] = (byte)0x00; // flags RFU
        // skip curve ID
        scratchOffset += 2;
        // skip CRC
        scratchOffset += 2;
        Crypto.random.generateData(scratch255, scratchOffset, (short)2); // nonce
        scratchOffset += 2;        
        // If importing, decode
        if (prepare) {            
            publicKeyOffset = (short)(offset + PRIVATE_KEY_S_LENGTH);
            Util.arrayCopyNonAtomic(buffer, offset, scratch255, scratchOffset, (short)(PRIVATE_KEY_S_LENGTH + PUBLIC_KEY_W_LENGTH));
            scratchOffset += (PRIVATE_KEY_S_LENGTH + PUBLIC_KEY_W_LENGTH);
        }
        else {
            // Otherwise, generate
            KeyPair keyPair = Crypto.generatePair();
            ECPrivateKey privateKey = (ECPrivateKey)keyPair.getPrivate();
            publicKey = (ECPublicKey)keyPair.getPublic();
            privateKey.getS(scratch255, scratchOffset);
            scratchOffset += 32;
            // The component itself stays here to avoid stressing the flash even more
            publicKey.getW(scratch255, scratchOffset);
            scratchOffset += PUBLIC_KEY_W_LENGTH;
        }
        Crypto.random.generateData(scratch255, scratchOffset, (short)7); // nonce2
        scratchOffset += 7;        
        // Encrypt the blob ASAP
        encryptionKey.initCipher(true);
        Crypto.blobEncryptDecrypt.doFinal(scratch255, (short)0, scratchOffset, scratch255, (short)0);        
        offset = 0;
        // Prepare the output
        // Public key
        buffer[offset++] = PUBLIC_KEY_W_LENGTH;
        if (publicKey == null) {
            Util.arrayCopyNonAtomic(buffer, publicKeyOffset, buffer, offset, PUBLIC_KEY_W_LENGTH);
        }
        else {
            publicKey.getW(buffer, offset);            
        }
        offset += PUBLIC_KEY_W_LENGTH;
        // Blob
        buffer[offset++] = (byte)scratchOffset;
        Util.arrayCopyNonAtomic(scratch255, (short)0, buffer, offset, scratchOffset);
        offset += scratchOffset;
        // Derivation data and fake signature
        Util.arrayFillNonAtomic(buffer, offset, (short)(32 + 8), (byte)0x00);
        offset += (short)(32 + 8);
        apdu.setOutgoingAndSend((short)0, offset);
    }
    
    private static void handleTrustedInput(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte dataOffset = (short)0;
        apdu.setIncomingAndReceive();
        if (p1 == P1_TRUSTED_INPUT_FIRST) {
            // Early check
            WrappingKeyRepository.WrappingKey encryptionKey = WrappingKeyRepository.find(buffer[ISO7816.OFFSET_CDATA], WrappingKeyRepository.ROLE_TRUSTED_INPUT_ENCRYPTION);    
            if (encryptionKey == null) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            TC.ctx[TC.TX_B_TRUSTED_INPUT_KEYSET] = buffer[ISO7816.OFFSET_CDATA];
            Util.arrayCopyNonAtomic(buffer, (short)(ISO7816.OFFSET_CDATA + 1), TC.ctx, TC.TX_I_TRANSACTION_TARGET_INPUT, TC.SIZEOF_U32);
            TC.ctx[TC.TX_B_TRANSACTION_STATE] = Transaction.STATE_NONE;
            TC.ctx[TC.TX_B_TRUSTED_INPUT_PROCESSED] = (byte)0x00;
            TC.ctx[TC.TX_B_HASH_OPTION] = Transaction.HASH_FULL;
            dataOffset = 5;
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
            WrappingKeyRepository.WrappingKey encryptionKey = WrappingKeyRepository.find(TC.ctx[TC.TX_B_TRUSTED_INPUT_KEYSET], WrappingKeyRepository.ROLE_TRUSTED_INPUT_ENCRYPTION);                
            short offset = 0;
            buffer[offset++] = BLOB_MAGIC_TRUSTED_INPUT;
            Crypto.random.generateData(buffer, offset, (short)3);
            offset += 3;            
            Crypto.digestFull.doFinal(scratch255, (short)0, (short)0, scratch255, (short)0);
            Crypto.digestFull.doFinal(scratch255, (short)0, (short)32, buffer, offset);
            offset += 32;
            GenericBEHelper.swap(TC.SIZEOF_U32, buffer, offset, TC.ctx, TC.TX_I_TRANSACTION_TARGET_INPUT);
            offset += 4;
            Util.arrayCopyNonAtomic(TC.ctx, TC.TX_A_TRANSACTION_AMOUNT, buffer, offset, TC.SIZEOF_AMOUNT);
            offset += TC.SIZEOF_AMOUNT;
            encryptionKey.initCipher(true);
            // "sign", using the same cipher
            Crypto.blobEncryptDecrypt.doFinal(buffer, (short)0, offset, scratch255, (short)0);
            Util.arrayCopyNonAtomic(scratch255, (short)(offset - 8), buffer, offset, (short)8);
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
                checkAccess();
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
                dataOffset = (short)2;
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
        textOffset = BCDUtils.hexAmountToDisplayable(TC.ctx, amountOffset, BTChipNFCForumApplet.FILE_DATA, textOffset);
        BTChipNFCForumApplet.FILE_DATA[textOffset++] = TEXT_SPACE;
        textOffset = Util.arrayCopyNonAtomic(TEXT_BTC, (short)0, BTChipNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_BTC.length);
        BTChipNFCForumApplet.FILE_DATA[textOffset++] = TEXT_SPACE;                
        textOffset = Util.arrayCopyNonAtomic(TEXT_TO, (short)0, BTChipNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_TO.length);
        // Recompute the key checksum in place as an additional sanity check
        Util.arrayCopyNonAtomic(TC.ctx, addressOffset, scratch255, (short)0, (short)(TC.SIZEOF_RIPEMD + 1));
        Crypto.digestScratch.doFinal(scratch255, (short)0, (short)(TC.SIZEOF_RIPEMD + 1), scratch255, (short)(TC.SIZEOF_RIPEMD + 1));
        Crypto.digestScratch.doFinal(scratch255, (short)(TC.SIZEOF_RIPEMD + 1), TC.SIZEOF_SHA256, scratch255, (short)(TC.SIZEOF_RIPEMD + 1));
        textOffset = Base58.encode(scratch255, (short)0, (short)(TC.SIZEOF_RIPEMD + 1 + 4), BTChipNFCForumApplet.FILE_DATA, textOffset, scratch255, (short)100);
        return textOffset;
    }

    private static void handleHashOutput(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];
        apdu.setIncomingAndReceive();
        checkInterfaceConsistency();
        restoreState();
        if (TC.ctx[TC.TX_B_TRANSACTION_STATE] != Transaction.STATE_PRESIGN_READY) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (isFirstSigned()) {
            short length = (short)(buffer[ISO7816.OFFSET_LC] & 0xff);
            if (length < (short)(1 + 1 + 1 + 8 + 8)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            switch(p1) {
                case P1_HASH_OUTPUT_BASE58:
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            short offset = (short)(ISO7816.OFFSET_CDATA);            
            WrappingKeyRepository.WrappingKey encryptionKey = WrappingKeyRepository.find(buffer[offset++], WrappingKeyRepository.ROLE_PRIVATE_KEY_ENCRYPTION);
            if (encryptionKey == null) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }            
            byte addressLength = buffer[offset++];
            short changeKeyLength;
            short decodedLength = Base58.decode(buffer, offset, addressLength, scratch255, (short)0, scratch255, (short)100);
            if (decodedLength < 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            switch(scratch255[0]) {
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
            verifyKeyChecksum(scratch255, (short)0, decodedLength, scratch255, (short)100);
            Util.arrayCopyNonAtomic(scratch255, (short)0, TC.ctx, TC.TX_A_AUTH_OUTPUT_ADDRESS, (short)(TC.SIZEOF_RIPEMD + 1));
            offset += addressLength;
            changeKeyLength = (short)(buffer[offset++] & 0xff);
            if (changeKeyLength != 0) {
                encryptionKey.initCipher(false);
                Crypto.blobEncryptDecrypt.doFinal(buffer, offset, changeKeyLength, scratch255, (short)0);
                if (scratch255[0] != BLOB_MAGIC_PRIVATE_KEY_WITH_PUB) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                // TODO : save the blob first (until the next validated transaction) to avoid an attack holding the change
                // We do not care about the private key, erase it immediately
                Util.arrayFillNonAtomic(scratch255, (short)0, OFFSET_PUBLIC_KEY_IN_PRIVATE_BLOB, (byte)0);
            }
            offset += changeKeyLength;
            Util.arrayCopyNonAtomic(buffer, offset, TC.ctx, TC.TX_A_AUTH_OUTPUT_AMOUNT, TC.SIZEOF_AMOUNT);
            offset += TC.SIZEOF_AMOUNT;
            Util.arrayCopyNonAtomic(buffer, offset, TC.ctx, TC.TX_A_AUTH_FEE_AMOUNT, TC.SIZEOF_AMOUNT);
            offset += TC.SIZEOF_AMOUNT;
            // Compute change == totalInputs - (amount + fees)
            Uint64Helper.add(scratch255, (short)240, TC.ctx, TC.TX_A_AUTH_OUTPUT_AMOUNT, TC.ctx, TC.TX_A_AUTH_FEE_AMOUNT);
            Uint64Helper.sub(TC.ctx, TC.TX_A_AUTH_CHANGE_AMOUNT, TC.ctx, TC.TX_A_TRANSACTION_AMOUNT, scratch255, (short)240);                        
            TC.ctx[TC.TX_Z_HAS_CHANGE] = (Uint64Helper.isZero(TC.ctx, TC.TX_A_AUTH_CHANGE_AMOUNT) ? TC.FALSE : TC.TRUE);
            // Enforce limits
            if (TC.ctxP[TC.P_TX_Z_USED] == TC.FALSE) {
                // Amount
                Uint64Helper.sub(scratch255, (short)200, limits, LIMIT_GLOBAL_AMOUNT, TC.ctx, TC.TX_A_AUTH_OUTPUT_AMOUNT);
                Util.arrayCopy(scratch255, (short)200, limits, LIMIT_GLOBAL_AMOUNT, TC.SIZEOF_AMOUNT);
                // Fees
                Uint64Helper.sub(scratch255, (short)200, limits, LIMIT_MAX_FEES, TC.ctx, TC.TX_A_AUTH_FEE_AMOUNT);
                // Change
                if (TC.ctx[TC.TX_Z_HAS_CHANGE] == TC.TRUE) {
                    Uint64Helper.sub(scratch255, (short)200, limits, LIMIT_MAX_CHANGE, TC.ctx, TC.TX_A_AUTH_CHANGE_AMOUNT);    
                }
            }            
            if (TC.ctx[TC.TX_Z_HAS_CHANGE] == TC.TRUE) {
                if (changeKeyLength == (short)0) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                // Compute the change address - significant performance hit if not using a native RIPEMD160
                Crypto.digestScratch.doFinal(scratch255, OFFSET_PUBLIC_KEY_IN_PRIVATE_BLOB, PUBLIC_KEY_W_LENGTH, scratch255, (short)0);
                TC.ctx[TC.TX_A_AUTH_CHANGE_ADDRESS] = KEY_VERSION; // force main net
                Crypto.hashRipemd32(scratch255, (short)0, TC.ctx, (short)(TC.TX_A_AUTH_CHANGE_ADDRESS + 1));
            }            
            if (TC.ctxP[TC.P_TX_Z_USED] == TC.TRUE) {
                Util.arrayCopy(TC.ctx, TC.TX_A_AUTH_NONCE, TC.ctxP, TC.P_TX_A_AUTH_NONCE, TC.TX_AUTH_CONTEXT_SIZE);
                TC.ctxP[TC.P_TX_Z_HAS_CHANGE] = TC.ctx[TC.TX_Z_HAS_CHANGE];
                TC.ctxP[TC.P_TX_Z_IS_P2SH] = TC.ctx[TC.TX_Z_IS_P2SH];
            }
        }
        short dataOffset = 0;
        short outOffset = 0;
        scratch255[dataOffset++] = ((TC.ctx[TC.TX_Z_HAS_CHANGE] == TC.TRUE) ? (byte)2 : (byte)1);
        dataOffset = addTransactionOutput(scratch255, dataOffset, TC.ctx, (short)(TC.TX_A_AUTH_OUTPUT_ADDRESS + 1), TC.ctx, TC.TX_A_AUTH_OUTPUT_AMOUNT, (TC.ctx[TC.TX_Z_IS_P2SH] == TC.TRUE));
        if (TC.ctx[TC.TX_Z_HAS_CHANGE] == TC.TRUE) {
            dataOffset = addTransactionOutput(scratch255, dataOffset, TC.ctx, (short)(TC.TX_A_AUTH_CHANGE_ADDRESS + 1), TC.ctx, TC.TX_A_AUTH_CHANGE_AMOUNT, false);
        }
        // Update the main hash
        Crypto.digestFull.update(scratch255, (short)0, dataOffset);
        // Always return the output
        buffer[outOffset++] = (byte)dataOffset;
        Util.arrayCopyNonAtomic(scratch255, (short)0, buffer, outOffset, dataOffset);
        outOffset += dataOffset;
        if (isFirstSigned()) {
            buffer[outOffset++] = (byte)DUMMY_AUTHORIZATION_NFC.length; // dummy authorization given, for compatibility
            outOffset = Util.arrayCopyNonAtomic(DUMMY_AUTHORIZATION_NFC, (short)0, buffer, outOffset, (short)DUMMY_AUTHORIZATION_NFC.length);
        }
        else {
            buffer[outOffset++] = (byte)0;
        }
        // Update the authorization hash and check it if necessary
        Crypto.digestAuthorization.doFinal(TC.ctx, TC.TX_A_AUTH_NONCE, TC.TX_AUTH_CONTEXT_SIZE, scratch255, (short)0);
        if (isFirstSigned()) {
            Util.arrayCopyNonAtomic(scratch255, (short)0, TC.ctx, TC.TX_A_AUTHORIZATION_HASH, TC.SIZEOF_SHA256);
            TC.ctx[TC.TX_Z_FIRST_SIGNED] = TC.FALSE;            
            if (TC.ctxP[TC.P_TX_Z_USED] == TC.TRUE) {                
                Util.arrayCopyNonAtomic(scratch255, (short)0, TC.ctxP, TC.P_TX_A_AUTHORIZATION_HASH, TC.SIZEOF_SHA256);
                // First signature in contact mode - prepare the confirmation text and PIN
                TC.ctxP[TC.P_TX_Z_FIRST_SIGNED] = TC.FALSE;
                short textOffset = BTChipNFCForumApplet.OFFSET_TEXT;
                textOffset = Util.arrayCopyNonAtomic(TEXT_CONFIRM, (short)0, BTChipNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_CONFIRM.length);
                textOffset = writeAmount(textOffset, TC.TX_A_AUTH_OUTPUT_AMOUNT, TC.TX_A_AUTH_OUTPUT_ADDRESS);
                BTChipNFCForumApplet.FILE_DATA[textOffset++] = TEXT_SPACE;                
                textOffset = Util.arrayCopyNonAtomic(TEXT_FEES, (short)0, BTChipNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_FEES.length);
                textOffset = BCDUtils.hexAmountToDisplayable(TC.ctx, TC.TX_A_AUTH_FEE_AMOUNT, BTChipNFCForumApplet.FILE_DATA, textOffset);                
                BTChipNFCForumApplet.FILE_DATA[textOffset++] = TEXT_SPACE;
                textOffset = Util.arrayCopyNonAtomic(TEXT_BTC, (short)0, BTChipNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_BTC.length);
                BTChipNFCForumApplet.FILE_DATA[textOffset++] = TEXT_COMMA;
                if (TC.ctx[TC.TX_Z_HAS_CHANGE] == TC.FALSE) {
                    textOffset = Util.arrayCopyNonAtomic(TEXT_NO_CHANGE, (short)0, BTChipNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_NO_CHANGE.length);
                }
                else {
                    textOffset = Util.arrayCopyNonAtomic(TEXT_CHANGE, (short)0, BTChipNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_CHANGE.length);
                    BTChipNFCForumApplet.FILE_DATA[textOffset++] = TEXT_SPACE;
                    textOffset = writeAmount(textOffset, TC.TX_A_AUTH_CHANGE_AMOUNT, TC.TX_A_AUTH_CHANGE_ADDRESS);                    
                }
                BTChipNFCForumApplet.FILE_DATA[textOffset++] = TEXT_CLOSE_P;
                BTChipNFCForumApplet.FILE_DATA[textOffset++] = TEXT_SPACE;
                textOffset = Util.arrayCopyNonAtomic(TEXT_PIN, (short)0, BTChipNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_PIN.length);
                Crypto.random.generateData(scratch255, (short)0, TRANSACTION_PIN_SIZE);
                for (byte i=0; i<TRANSACTION_PIN_SIZE; i++) {
                    scratch255[i] = (byte)((short)((scratch255[i] & 0xff)) % 10);
                    scratch255[i] += (byte)'0';
                }
                transactionPin.resetAndUnblock();
                transactionPin.update(scratch255, (short)0, TRANSACTION_PIN_SIZE);
                textOffset = Util.arrayCopyNonAtomic(scratch255, (short)0, BTChipNFCForumApplet.FILE_DATA, textOffset, TRANSACTION_PIN_SIZE);
                BTChipNFCForumApplet.writeHeader((short)(textOffset - BTChipNFCForumApplet.OFFSET_TEXT));
            }
        }
        else {            
            if (Util.arrayCompare(scratch255, (short)0, TC.ctx, TC.TX_A_AUTHORIZATION_HASH, TC.SIZEOF_SHA256) != 0) {
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
        apdu.setIncomingAndReceive();
        checkInterfaceConsistency();
        restoreState();
        if (TC.ctx[TC.TX_B_TRANSACTION_STATE] != Transaction.STATE_SIGN_READY) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        
        WrappingKeyRepository.WrappingKey encryptionKey = WrappingKeyRepository.find(buffer[offset++], WrappingKeyRepository.ROLE_PRIVATE_KEY_ENCRYPTION);        
        if (encryptionKey == null) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }            
        short keyLength = (short)(buffer[offset++] & 0xff);
        encryptionKey.initCipher(false);
        Crypto.blobEncryptDecrypt.doFinal(buffer, offset, keyLength, scratch255, (short)0);
        if ((scratch255[0] != BLOB_MAGIC_PRIVATE_KEY_WITH_PUB) && (scratch255[0] != BLOB_MAGIC_PRIVATE_KEY)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        offset += keyLength;
        offset++; // skip key authorization
        short authorizationLength = (short)(buffer[offset++] & 0xff);    
        // Check the PIN if the transaction was started in contact mode
        if (TC.ctxP[TC.P_TX_Z_USED] == TC.TRUE) {
            // Clear the text
            BTChipPocApplet.writeIdleText();
            if (!transactionPin.check(buffer, offset, (byte)authorizationLength)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        }
        offset += authorizationLength;        
        // Copy lockTime        
        Uint32Helper.swap(scratch255, (short)100, buffer, offset);
        offset += 4;
        // Copy sigHashType
        byte sigHashType = buffer[offset++];
        Uint32Helper.clear(scratch255, (short)104);
        scratch255[(short)104] = sigHashType;        
        // Compute the signature
        Crypto.digestFull.doFinal(scratch255, (short)100, (short)8, scratch255, (short)100);
        Crypto.signTransientPrivate(scratch255, OFFSET_PRIVATE_KEY_IN_PRIVATE_BLOB, scratch255, (short)100, buffer, (short)0);
        short signatureSize = (short)((short)(buffer[1] & 0xff) + 2);
        buffer[signatureSize] = sigHashType;
        // TODO : reset transaction state
        saveState();
        apdu.setOutgoingAndSend((short)0, (short)(signatureSize + 1));
    }
    
    private static void handleSetup(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        if ((setup == TC.TRUE) || (setup != TC.FALSE)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (buffer[ISO7816.OFFSET_LC] != WALLET_PIN_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        walletPin.update(buffer, ISO7816.OFFSET_CDATA, WALLET_PIN_SIZE);
        Crypto.random.generateData(scratch255, (short)0, (short)16);
        WrappingKeyRepository.add((byte)0x40, WrappingKeyRepository.ROLE_TRUSTED_INPUT_ENCRYPTION, scratch255, (short)0);
        Crypto.random.generateData(buffer, (short)0, (short)16);
        WrappingKeyRepository.add((byte)0x02, WrappingKeyRepository.ROLE_PRIVATE_KEY_ENCRYPTION, buffer, (short)0);                       
        apdu.setOutgoingAndSend((short)0, (short)16);
        setup = TC.TRUE;
    }
    
    private static void handleUnlock(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        if ((setup == TC.FALSE) || (setup != TC.TRUE)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (buffer[ISO7816.OFFSET_LC] != WALLET_PIN_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (!walletPin.check(buffer, ISO7816.OFFSET_CDATA, WALLET_PIN_SIZE)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private static void handleGetContactlessLimit(APDU apdu) throws ISOException {
        if ((setup == TC.FALSE) || (setup != TC.TRUE)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        Util.arrayCopyNonAtomic(limits, (short)0, scratch255, (short)0, LIMIT_LAST);
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
       
    public static void clearScratch() {
        Util.arrayFillNonAtomic(scratch255, (short)0, (short)scratch255.length, (byte)0x00);
    }
    
    public void process(APDU apdu) throws ISOException {
        if (selectingApplet()) {
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
                    case INS_UNLOCK:
                        handleUnlock(apdu);
                        break;
                    case INS_GET_CONTACTLESS_LIMIT:
                        handleGetContactlessLimit(apdu);
                        break;
                    case INS_SET_CONTACTLESS_LIMIT:
                        checkAccess();
                        handleSetContactlessLimit(apdu);
                        break;                        
                    case INS_GENERATE:
                        checkAccess();
                        handleGenerate(apdu);
                        break;
                    case INS_GET_TRUSTED_INPUT:
                        checkAccess();
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
        new BTChipPocApplet().register(bArray, (short)(bOffset + 1), bArray[bOffset]);
    }
    
    private static final byte TRANSACTION_PIN_ATTEMPTS = (byte)1;
    private static final byte TRANSACTION_PIN_SIZE = (byte)4;
    private static final byte WALLET_PIN_ATTEMPTS = (byte)3;
    private static final byte WALLET_PIN_SIZE = (byte)8;
    

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

    private static final byte DUMMY_AUTHORIZATION_NFC[] = { (byte)'N', (byte)'F', (byte)'C' };
    
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
    private static final byte OFFSET_PRIVATE_KEY_IN_PRIVATE_BLOB = (short)(1 + 1 + 2 + 2 + 2);
    private static final byte OFFSET_PUBLIC_KEY_IN_PRIVATE_BLOB = (short)(1 + 1 + 2 + 2 + 2 + PRIVATE_KEY_S_LENGTH);    
    
    private static final byte CLA_BTC = (byte)0xE0;
    private static final byte INS_GENERATE = (byte)0x20;
    private static final byte INS_GET_TRUSTED_INPUT = (byte)0x42;
    private static final byte INS_UNTRUSTED_HASH_START = (byte)0x44;
    private static final byte INS_UNTRUSTED_HASH_FINALIZE = (byte)0x46;
    private static final byte INS_UNTRUSTED_HASH_SIGN = (byte)0x48;
    private static final byte INS_SETUP = (byte)0xA0;
    private static final byte INS_UNLOCK = (byte)0xA2;
    private static final byte INS_SET_CONTACTLESS_LIMIT = (byte)0xA4;
    private static final byte INS_GET_CONTACTLESS_LIMIT = (byte)0xA6;
    
    
    private static final byte P1_GENERATE_PREPARE = (byte)0x80;
    private static final byte P1_GENERATE_PROVIDE_AUTHORIZED_KEY = (byte)0x01;
    private static final byte P1_GENERATE_PREPARE_BASE58 = (byte)0x02;
    private static final byte P1_GENERATE_PREPARE_HASH = (byte)0x04;
    private static final byte P1_GENERATE_PREPARE_DERIVE = (byte)0x08;
    private static final byte P1_GENERATE_PREPARE_UID = (byte)0x10;
    private static final byte P1_GENERATE_PREPARE_BIN = (byte)0x20;
    
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
            
    public static final byte BLOB_MAGIC_PRIVATE_KEY = (byte)0x01;
    public static final byte BLOB_MAGIC_PRIVATE_KEY_WITH_PUB = (byte)0x11;
    public static final byte BLOB_MAGIC_ENCODED_ADDRESS = (byte)0x21;
    public static final byte BLOB_MAGIC_TRUSTED_INPUT = (byte)0x31;
    
    private static final byte LIMIT_GLOBAL_AMOUNT = (byte)0;
    private static final byte LIMIT_MAX_FEES = (byte)(LIMIT_GLOBAL_AMOUNT + TC.SIZEOF_AMOUNT);
    private static final byte LIMIT_MAX_CHANGE = (byte)(LIMIT_MAX_FEES + TC.SIZEOF_AMOUNT);
    private static final byte LIMIT_LAST = (byte)(LIMIT_MAX_CHANGE + TC.SIZEOF_AMOUNT);
        
    public static byte[] scratch255;
    private static OwnerPIN transactionPin;
    private static OwnerPIN walletPin;
    private static byte setup;
    private static byte limitsSet;
    
    private static byte[] limits;    
}
