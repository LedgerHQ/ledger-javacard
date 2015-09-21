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

/* This file is automatically processed from the .javap version and only included for convenience. Please refer to the .javap file
   for more readable code */

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
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.Signature;
public class LedgerWalletApplet extends Applet {
    public LedgerWalletApplet(byte[] parameters, short parametersOffset, byte parametersLength) {
        BCDUtils.init();
        TC.init();
        Crypto.init();
        Transaction.init();
        Bip32Cache.init();
        Keycard.init();
        limits = new byte[LIMIT_LAST];
        scratch256 = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
        transactionPin = new OwnerPIN(TRANSACTION_PIN_ATTEMPTS, TRANSACTION_PIN_SIZE);
        walletPin = new OwnerPIN(WALLET_PIN_ATTEMPTS, WALLET_PIN_SIZE);
        secondaryPin = new OwnerPIN(SECONDARY_PIN_ATTEMPTS, SECONDARY_PIN_SIZE);
        masterDerived = new byte[64];
        chipKey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
        trustedInputKey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
        developerKey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
        try {
            pairingKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        }
        catch(Exception e) {
        }
        reset();
        if (parametersLength != 0) {
            attestationPrivate = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
            attestationPublic = new byte[65];
            Secp256k1.setCommonCurveParameters(attestationPrivate);
            attestationPrivate.setS(parameters, parametersOffset, (short)32);
            parametersOffset += (short)32;
            attestationSignature = new byte[parameters[(short)(parametersOffset + 1)] + 2];
            Util.arrayCopy(parameters, parametersOffset, attestationSignature, (short)0, (short)attestationSignature.length);
        }
    }
    private static void reset() {
        Crypto.random.generateData(scratch256, (short)0, (short)16);
        chipKey.setKey(scratch256, (short)0);
        Util.arrayFillNonAtomic(scratch256, (short)0, (short)16, (byte)0x00);
        setup = TC.FALSE;
        limitsSet = TC.FALSE;
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
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (checkPinContactless && !walletPin.isValidated()) {
         ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }
    private static void checkInterfaceConsistency() {
        if ((isContactless() && (TC.ctxP[TC.P_TX_Z_WIRED] != TC.FALSE)) ||
            (!isContactless() && (TC.ctxP[TC.P_TX_Z_WIRED] != TC.TRUE))) {
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
    private static void signTransientPrivate(byte[] keyBuffer, short keyOffset, byte[] dataBuffer, short dataOffset, byte[] targetBuffer, short targetOffset) {
        if ((proprietaryAPI == null) || (!proprietaryAPI.hasDeterministicECDSASHA256())) {
            Crypto.signTransientPrivate(keyBuffer, keyOffset, dataBuffer, dataOffset, targetBuffer, targetOffset);
        }
        else {
            Crypto.initTransientPrivate(keyBuffer, keyOffset);
            proprietaryAPI.signDeterministicECDSASHA256(Crypto.transientPrivate, dataBuffer, dataOffset, (short)32, targetBuffer, targetOffset);
            if (Crypto.transientPrivateTransient) {
                Crypto.transientPrivate.clearKey();
            }
        }
    }
    private static void checkAirgapPersonalizationAvailable() throws ISOException {
        if ((attestationPublic == null) || (Crypto.keyAgreement == null) || (Crypto.keyPair == null) || (Crypto.blobEncryptDecryptAES == null) || (pairingKey == null)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
    private static void handleGetAttestation(APDU apdu) throws ISOException {
        short offset = (short)0;
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(attestationPublic, (short)0, buffer, offset, (short)65);
        offset += (short)65;
        Util.arrayCopyNonAtomic(attestationSignature, (short)0, buffer, offset, (short)attestationSignature.length);
        offset += (short)(attestationSignature.length);
        apdu.setOutgoingAndSend((short)0, offset);
    }
    private static void handleAirgapKeyAgreement(APDU apdu) throws ISOException {
        short offset = (short)0;
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        checkAirgapPersonalizationAvailable();
        if (buffer[ISO7816.OFFSET_P1] == P1_INITIATE_PAIRING) {
            if (buffer[ISO7816.OFFSET_LC] != (byte)65) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            pairingDone = false;
            Crypto.keyPair.genKeyPair();
            Crypto.keyAgreement.init((ECPrivateKey)Crypto.keyPair.getPrivate());
            Crypto.keyAgreement.generateSecret(buffer, ISO7816.OFFSET_CDATA, (short)65, scratch256, (short)0);
            pairingKey.setKey(scratch256, (short)0);
            ((ECPublicKey)Crypto.keyPair.getPublic()).getW(buffer, offset);
            offset += (short)65;
            Crypto.signature.init(attestationPrivate, Signature.MODE_SIGN);
            Crypto.signature.sign(buffer, (short)0, (short)65, buffer, offset);
            offset += (short)(buffer[(short)(offset + 1)] + 2);
            apdu.setOutgoingAndSend((short)0, offset);
        }
        else
        if (buffer[ISO7816.OFFSET_P1] == P1_CONFIRM_PAIRING) {
            if (buffer[ISO7816.OFFSET_LC] != (byte)32) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Crypto.initCipherAES(pairingKey, false);
            Crypto.blobEncryptDecryptAES.doFinal(buffer, ISO7816.OFFSET_CDATA, (short)32, scratch256, (short)0);
            pairingKey.setKey(scratch256, (short)0);
            pairingDone = true;
        }
        else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }
    private static void handleSetAttestationPublic(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        checkAirgapPersonalizationAvailable();
        if (buffer[ISO7816.OFFSET_LC] != (byte)attestationPublic.length) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, attestationPublic, (short)0, (short)attestationPublic.length);
    }
    private static void handleHasCachedPublicKey(APDU apdu) throws ISOException {
     byte[] buffer = apdu.getBuffer();
     apdu.setIncomingAndReceive();
     short offset = ISO7816.OFFSET_CDATA;
     byte derivationSize = buffer[offset++];
     if (derivationSize > MAX_DERIVATION_PATH) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
     }
     boolean result = Bip32Cache.hasPublic(buffer, offset, derivationSize);
     buffer[0] = (result ? (byte)0x01 : (byte)0x00);
     apdu.setOutgoingAndSend((short)0, (short)1);
    }
    private static void handleStorePublicKey(APDU apdu) throws ISOException {
     byte[] buffer = apdu.getBuffer();
     apdu.setIncomingAndReceive();
     short offset = ISO7816.OFFSET_CDATA;
     byte derivationSize = buffer[offset++];
     byte i;
     if (Crypto.keyAgreement == null) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
     }
     if (derivationSize > MAX_DERIVATION_PATH) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
     }
        Crypto.initCipher(chipKey, false);
        Crypto.blobEncryptDecrypt.doFinal(masterDerived, (short)0, (short)DEFAULT_SEED_LENGTH, scratch256, (short)0);
        i = Bip32Cache.copyPrivateBest(buffer, (short)(ISO7816.OFFSET_CDATA + 1), derivationSize, scratch256, (short)0);
        for (; i<derivationSize; i++) {
         Util.arrayCopyNonAtomic(buffer, (short)(offset + 4 * i), scratch256, Bip32.OFFSET_DERIVATION_INDEX, (short)4);
         if ((proprietaryAPI == null) && ((scratch256[Bip32.OFFSET_DERIVATION_INDEX] & (byte)0x80) == 0)) {
          if (!Bip32Cache.setPublicIndex(buffer, (short)(ISO7816.OFFSET_CDATA + 1), i)) {
           ISOException.throwIt(SW_PUBLIC_POINT_NOT_AVAILABLE);
          }
         }
         if (!Bip32.derive(buffer)) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
         }
         Bip32Cache.storePrivate(buffer, (short)(ISO7816.OFFSET_CDATA + 1), (byte)(i + 1), scratch256);
        }
        offset += (short)(derivationSize * 4);
        Crypto.random.generateData(scratch256, (short)32, (short)32);
        signTransientPrivate(scratch256, (short)0, scratch256, (short)32, scratch256, (short)64);
        if (Crypto.verifyPublic(buffer, offset, scratch256, (short)32, scratch256, (short)64)) {
         Bip32Cache.storePublic(buffer, (short)(ISO7816.OFFSET_CDATA + 1), derivationSize, buffer, offset);
        }
        else {
         ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }
    private static void handleGetHalfPublicKey(APDU apdu) throws ISOException {
     byte[] buffer = apdu.getBuffer();
     apdu.setIncomingAndReceive();
     short offset = ISO7816.OFFSET_CDATA;
     byte derivationSize = buffer[offset++];
     byte i;
     if (Crypto.keyAgreement == null) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
     }
     if (derivationSize > MAX_DERIVATION_PATH) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
     }
        Crypto.initCipher(chipKey, false);
        Crypto.blobEncryptDecrypt.doFinal(masterDerived, (short)0, (short)DEFAULT_SEED_LENGTH, scratch256, (short)0);
        i = Bip32Cache.copyPrivateBest(buffer, (short)(ISO7816.OFFSET_CDATA + 1), derivationSize, scratch256, (short)0);
        for (; i<derivationSize; i++) {
         Util.arrayCopyNonAtomic(buffer, (short)(offset + 4 * i), scratch256, Bip32.OFFSET_DERIVATION_INDEX, (short)4);
         if ((proprietaryAPI == null) && ((scratch256[Bip32.OFFSET_DERIVATION_INDEX] & (byte)0x80) == 0)) {
          if (!Bip32Cache.setPublicIndex(buffer, (short)(ISO7816.OFFSET_CDATA + 1), i)) {
           ISOException.throwIt(SW_PUBLIC_POINT_NOT_AVAILABLE);
          }
         }
         if (!Bip32.derive(buffer)) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
         }
         Bip32Cache.storePrivate(buffer, (short)(ISO7816.OFFSET_CDATA + 1), (byte)(i + 1), scratch256);
        }
        Crypto.initTransientPrivate(scratch256, (short)0);
        Crypto.keyAgreement.init(Crypto.transientPrivate);
        Crypto.keyAgreement.generateSecret(Secp256k1.SECP256K1_G, (short)0, (short)Secp256k1.SECP256K1_G.length, scratch256, (short)32);
        offset = 0;
        Crypto.random.generateData(buffer, (short)offset, (short)32);
        offset += 32;
        Util.arrayCopyNonAtomic(scratch256, (short)32, buffer, offset, (short)32);
        offset += 32;
        signTransientPrivate(scratch256, (short)0, buffer, (short)0, buffer, offset);
        offset += buffer[(short)(offset + 1)] + 2;
        Crypto.digestScratch.doFinal(buffer, (short)0, (short)32, buffer, (short)0);
        apdu.setOutgoingAndSend((short)0, offset);
    }
    private static void handleGetFeatures(APDU apdu) throws ISOException {
     byte[] buffer = apdu.getBuffer();
     buffer[0] = (byte)0;
     if (proprietaryAPI != null) {
      buffer[0] |= JC_FEATURE_HAS_PROPRIETARY_API;
     }
     apdu.setOutgoingAndSend((short)0, (short)1);
    }
    private static void handleGetWalletPublicKey(APDU apdu) throws ISOException {
     byte[] buffer = apdu.getBuffer();
     short offset = ISO7816.OFFSET_CDATA;
     byte derivationSize = buffer[offset++];
     byte i;
     if (derivationSize > MAX_DERIVATION_PATH) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
     }
        Crypto.initCipher(chipKey, false);
        Crypto.blobEncryptDecrypt.doFinal(masterDerived, (short)0, (short)DEFAULT_SEED_LENGTH, scratch256, (short)0);
        i = Bip32Cache.copyPrivateBest(buffer, (short)(ISO7816.OFFSET_CDATA + 1), derivationSize, scratch256, (short)0);
        for (; i<derivationSize; i++) {
         Util.arrayCopyNonAtomic(buffer, (short)(offset + 4 * i), scratch256, Bip32.OFFSET_DERIVATION_INDEX, (short)4);
         if ((proprietaryAPI == null) && ((scratch256[Bip32.OFFSET_DERIVATION_INDEX] & (byte)0x80) == 0)) {
          if (!Bip32Cache.setPublicIndex(buffer, (short)(ISO7816.OFFSET_CDATA + 1), i)) {
           ISOException.throwIt(SW_PUBLIC_POINT_NOT_AVAILABLE);
          }
         }
         if (!Bip32.derive(buffer)) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
         }
         Bip32Cache.storePrivate(buffer, (short)(ISO7816.OFFSET_CDATA + 1), (byte)(i + 1), scratch256);
        }
        if (proprietaryAPI == null) {
      if (!Bip32Cache.setPublicIndex(buffer, offset, derivationSize)) {
       ISOException.throwIt(SW_PUBLIC_POINT_NOT_AVAILABLE);
      }
        }
        offset = 0;
        buffer[offset++] = (short)65;
        if (proprietaryAPI == null) {
         Bip32Cache.copyLastPublic(buffer, offset);
        }
        else {
         proprietaryAPI.getUncompressedPublicPoint(scratch256, (short)0, buffer, offset);
        }
        Util.arrayCopyNonAtomic(scratch256, (short)32, buffer, (short)200, (short)32);
        Util.arrayCopyNonAtomic(buffer, offset, scratch256, (short)0, (short)65);
        AddressUtils.compressPublicKey(scratch256, (short)0);
        offset += (short)65;
        buffer[offset] = (byte)(publicKeyToAddress(buffer, (short)(offset + 1)) - (short)(offset + 1));
        offset += (short)(buffer[offset] + 1);
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
            TC.clear();
            TC.ctx[TC.TX_B_TRANSACTION_STATE] = Transaction.STATE_NONE;
            TC.ctx[TC.TX_B_HASH_OPTION] = Transaction.HASH_BOTH;
            TC.ctx[TC.TX_Z_CHANGE_ACCEPTED] = (byte)0x01;
        }
        else
        if (p1 != P1_HASH_TRANSACTION_NEXT) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (p2 == P2_HASH_TRANSACTION_NEW_INPUT) {
            if (p1 == P1_HASH_TRANSACTION_FIRST) {
                checkAccess(true);
                TC.ctxP[TC.P_TX_Z_WIRED] = (isContactless() ? TC.FALSE : TC.TRUE);
                TC.ctxP[TC.P_TX_Z_FIRST_SIGNED] = TC.TRUE;
                TC.ctxP[TC.P_TX_Z_RELAXED] = TC.FALSE;
                TC.ctxP[TC.P_TX_Z_CONSUME_P2SH] = TC.FALSE;
                TC.ctxP[TC.P_TX_Z_USE_KEYCARD] = TC.FALSE;
                Crypto.random.generateData(TC.ctxP, TC.P_TX_A_NONCE, TC.SIZEOF_NONCE);
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
            return;
        }
        else
        if (result == Transaction.RESULT_FINISHED) {
            return;
        }
    }
    private static short writeAmount(short textOffset, short amountOffset, byte[] addressBuffer, short addressOffset) {
        textOffset = BCDUtils.hexAmountToDisplayable(TC.ctx, amountOffset, LWNFCForumApplet.FILE_DATA, textOffset);
        LWNFCForumApplet.FILE_DATA[textOffset++] = TEXT_SPACE;
        textOffset = Util.arrayCopyNonAtomic(TEXT_BTC, (short)0, LWNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_BTC.length);
        LWNFCForumApplet.FILE_DATA[textOffset++] = TEXT_SPACE;
        textOffset = Util.arrayCopyNonAtomic(TEXT_TO, (short)0, LWNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_TO.length);
        Util.arrayCopyNonAtomic(addressBuffer, addressOffset, scratch256, (short)0, (short)(TC.SIZEOF_RIPEMD + 1));
        Crypto.digestScratch.doFinal(scratch256, (short)0, (short)(TC.SIZEOF_RIPEMD + 1), scratch256, (short)(TC.SIZEOF_RIPEMD + 1));
        Crypto.digestScratch.doFinal(scratch256, (short)(TC.SIZEOF_RIPEMD + 1), TC.SIZEOF_SHA256, scratch256, (short)(TC.SIZEOF_RIPEMD + 1));
        textOffset = Base58.encode(scratch256, (short)0, (short)(TC.SIZEOF_RIPEMD + 1 + 4), LWNFCForumApplet.FILE_DATA, textOffset, scratch256, (short)100);
        return textOffset;
    }
    private static void handleHashOutputFullChange(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short offset = (short)(ISO7816.OFFSET_CDATA);
        apdu.setIncomingAndReceive();
        checkInterfaceConsistency();
        if (TC.ctx[TC.TX_B_TRANSACTION_STATE] != Transaction.STATE_PRESIGN_READY) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte i;
        byte addressLength = buffer[offset];
        if (TC.ctx[TC.TX_Z_CHANGE_ACCEPTED] != (byte)0x01) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (addressLength > MAX_DERIVATION_PATH) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        offset++;
        Crypto.initCipher(chipKey, false);
        Crypto.blobEncryptDecrypt.doFinal(masterDerived, (short)0, (short)DEFAULT_SEED_LENGTH, scratch256, (short)0);
        i = Bip32Cache.copyPrivateBest(buffer, offset, addressLength, scratch256, (short)0);
        for (; i<addressLength; i++) {
            Util.arrayCopyNonAtomic(buffer, (short)(offset + 4 * i), scratch256, Bip32.OFFSET_DERIVATION_INDEX, (short)4);
            if ((proprietaryAPI == null) && ((scratch256[Bip32.OFFSET_DERIVATION_INDEX] & (byte)0x80) == 0)) {
                if (!Bip32Cache.setPublicIndex(buffer, offset, i)) {
                    ISOException.throwIt(SW_PUBLIC_POINT_NOT_AVAILABLE);
                }
            }
            if (!Bip32.derive(buffer)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            Bip32Cache.storePrivate(buffer, offset, (byte)(i + 1), scratch256);
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
        AddressUtils.compressPublicKey(scratch256, (short)0);
        Crypto.digestScratch.doFinal(scratch256, (short)0, (short)33, scratch256, (short)0);
        if (Crypto.digestRipemd != null) {
            Crypto.digestRipemd.doFinal(scratch256, (short)0, (short)32, TC.ctx, (short)(TC.TX_A_CHANGE_ADDRESS + 1));
        }
        else {
            Ripemd160.hash32(scratch256, (short)0, TC.ctx, (short)(TC.TX_A_CHANGE_ADDRESS + 1), scratch256, (short)33);
        }
        TC.ctx[TC.TX_Z_CHANGE_ACCEPTED] = (byte)0x00;
        TC.ctx[TC.TX_Z_CHANGE_INITIALIZED] = (byte)0x01;
    }
    private static void handleHashOutputFull(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short offset = (short)(ISO7816.OFFSET_CDATA);
        apdu.setIncomingAndReceive();
        checkInterfaceConsistency();
        if (TC.ctx[TC.TX_B_TRANSACTION_STATE] != Transaction.STATE_PRESIGN_READY) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        Crypto.digestFull.update(buffer, offset, (short)(buffer[ISO7816.OFFSET_LC] & 0xff));
        Crypto.digestAuthorization.update(buffer, offset, (short)(buffer[ISO7816.OFFSET_LC] & 0xff));
        if (buffer[ISO7816.OFFSET_P1] == P1_FINALIZE_MORE) {
            if ((currentMode == MODE_WALLET) && (TC.ctxP[TC.P_TX_Z_CONSUME_P2SH] == TC.FALSE)) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            TC.ctx[TC.TX_Z_MULTIPLE_OUTPUT] = (byte)0x01;
            buffer[0] = (byte)0x00;
            apdu.setOutgoingAndSend((short)0, (short)1);
            return;
        }
        else
        if (buffer[ISO7816.OFFSET_P1] != P1_FINALIZE_LAST) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (TC.ctxP[TC.P_TX_Z_FIRST_SIGNED] == TC.TRUE) {
            TC.ctxP[TC.P_TX_Z_FIRST_SIGNED] = TC.FALSE;
            if ((currentMode == MODE_WALLET) && (TC.ctxP[TC.P_TX_Z_CONSUME_P2SH] == TC.FALSE)) {
                byte numOutputs;
                byte i;
                short addressOffset = (short)0;
                byte tmpVersion = (byte)0;
                boolean changeFilled = false;
                boolean regularFilled = false;
                numOutputs = buffer[offset++];
                if (numOutputs > 3) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                for (i=0; i<numOutputs; i++) {
                    offset += (short)8;
                    if ((Util.arrayCompare(buffer, offset, TRANSACTION_OUTPUT_SCRIPT_PRE, (short)0, (short)TRANSACTION_OUTPUT_SCRIPT_PRE.length) == (byte)0) &&
                        (Util.arrayCompare(buffer, (short)(offset + TC.SIZEOF_RIPEMD + (short)TRANSACTION_OUTPUT_SCRIPT_PRE.length), TRANSACTION_OUTPUT_SCRIPT_POST, (short)0, (short)TRANSACTION_OUTPUT_SCRIPT_POST.length) == (byte)0)) {
                        tmpVersion = stdVersion;
                        addressOffset = (short)(offset + (short)TRANSACTION_OUTPUT_SCRIPT_PRE.length);
                    }
                    else
                    if ((Util.arrayCompare(buffer, offset, TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE, (short)0, (short)TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE.length) == (byte)0) &&
                        (Util.arrayCompare(buffer, (short)(offset + TC.SIZEOF_RIPEMD + (short)TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE.length), TRANSACTION_OUTPUT_SCRIPT_P2SH_POST, (short)0, (short)TRANSACTION_OUTPUT_SCRIPT_P2SH_POST.length) == (byte)0)) {
                        tmpVersion = p2shVersion;
                        addressOffset = (short)(offset + (short)TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE.length);
                    }
                    else
                    if (buffer[(short)(offset + 1)] == OP_RETURN) {
                        if (!Uint64Helper.isEqualByte(buffer, (short)(offset - 8), (byte)0)) {
                            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        }
                        offset += (short)((short)(buffer[offset] & 0xff) + (short)1);
                        continue;
                    }
                    else {
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    }
                    if ((TC.ctx[TC.TX_Z_CHANGE_INITIALIZED] == (byte)0x01) &&
                        (Util.arrayCompare(buffer, addressOffset, TC.ctx, (short)(TC.TX_A_CHANGE_ADDRESS + 1), TC.SIZEOF_RIPEMD) == (byte)0)) {
                        if (changeFilled) {
                            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        }
                        TC.ctx[TC.TX_A_CHANGE_ADDRESS] = tmpVersion;
                        Util.arrayCopyNonAtomic(buffer, addressOffset, TC.ctx, (short)(TC.TX_A_CHANGE_ADDRESS + 1), TC.SIZEOF_RIPEMD);
                        Uint64Helper.swap(TC.ctx, TC.TX_A_CHANGE_AMOUNT, buffer, (short)(offset - 8));
                        changeFilled = true;
                        TC.ctx[TC.TX_Z_CHANGE_CHECKED] = (byte)0x01;
                    }
                    else {
                        if (regularFilled && changeFilled) {
                            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        }
                        if (!regularFilled) {
                            TC.ctxP[TC.P_TX_A_OUTPUT_ADDRESS] = tmpVersion;
                            Util.arrayCopyNonAtomic(buffer, addressOffset, TC.ctxP, (short)(TC.P_TX_A_OUTPUT_ADDRESS + 1), TC.SIZEOF_RIPEMD);
                            Uint64Helper.swap(TC.ctx, TC.TX_A_OUTPUT_AMOUNT, buffer, (short)(offset - 8));
                            regularFilled = true;
                        }
                        else {
                            TC.ctx[TC.TX_A_CHANGE_ADDRESS] = tmpVersion;
                            Util.arrayCopyNonAtomic(buffer, addressOffset, TC.ctx, (short)(TC.TX_A_CHANGE_ADDRESS + 1), TC.SIZEOF_RIPEMD);
                            Uint64Helper.swap(TC.ctx, TC.TX_A_CHANGE_AMOUNT, buffer, (short)(offset - 8));
                            changeFilled = true;
                        }
                    }
                    offset += (short)((short)(buffer[offset] & 0xff) + (short)1);
                }
                if (changeFilled && (TC.ctx[TC.TX_Z_CHANGE_CHECKED] == (byte)0x00)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                Uint64Helper.add(scratch256, (short)240, TC.ctx, TC.TX_A_OUTPUT_AMOUNT, TC.ctx, TC.TX_A_CHANGE_AMOUNT);
                Uint64Helper.sub(TC.ctx, TC.TX_A_FEE_AMOUNT, TC.ctx, TC.TX_A_TRANSACTION_AMOUNT, scratch256, (short)240);
                if (Keycard.isInitialized()) {
                    Util.arrayCopyNonAtomic(TC.ctxP, TC.P_TX_A_OUTPUT_ADDRESS, scratch256, (short)0, (short)(TC.SIZEOF_RIPEMD + 1));
                    Crypto.digestScratch.doFinal(scratch256, (short)0, (short)(TC.SIZEOF_RIPEMD + 1), scratch256, (short)(TC.SIZEOF_RIPEMD + 1));
                    Crypto.digestScratch.doFinal(scratch256, (short)(TC.SIZEOF_RIPEMD + 1), TC.SIZEOF_SHA256, scratch256, (short)(TC.SIZEOF_RIPEMD + 1));
                    addressOffset = Base58.encode(scratch256, (short)0, (short)(TC.SIZEOF_RIPEMD + 1 + 4), scratch256, (short)30, scratch256, (short)100);
                    Keycard.generateIndexes(TC.ctxP, TC.P_TX_A_KEYCARD_INDEXES, (byte)(addressOffset - (short)30));
                    TC.ctxP[TC.P_TX_Z_USE_KEYCARD] = TC.TRUE;
                }
                else {
                    if (TC.ctxP[TC.P_TX_Z_WIRED] == TC.FALSE) {
                        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    }
                }
                if (TC.ctxP[TC.P_TX_Z_WIRED] == TC.TRUE) {
                    short textOffset = LWNFCForumApplet.OFFSET_TEXT;
                    textOffset = Util.arrayCopyNonAtomic(TEXT_CONFIRM, (short)0, LWNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_CONFIRM.length);
                    textOffset = writeAmount(textOffset, TC.TX_A_OUTPUT_AMOUNT, TC.ctxP, TC.P_TX_A_OUTPUT_ADDRESS);
                    LWNFCForumApplet.FILE_DATA[textOffset++] = TEXT_SPACE;
                    textOffset = Util.arrayCopyNonAtomic(TEXT_FEES, (short)0, LWNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_FEES.length);
                    textOffset = BCDUtils.hexAmountToDisplayable(TC.ctx, TC.TX_A_FEE_AMOUNT, LWNFCForumApplet.FILE_DATA, textOffset);
                    LWNFCForumApplet.FILE_DATA[textOffset++] = TEXT_SPACE;
                    textOffset = Util.arrayCopyNonAtomic(TEXT_BTC, (short)0, LWNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_BTC.length);
                    LWNFCForumApplet.FILE_DATA[textOffset++] = TEXT_COMMA;
                    if (changeFilled) {
                        textOffset = Util.arrayCopyNonAtomic(TEXT_NO_CHANGE, (short)0, LWNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_NO_CHANGE.length);
                    }
                    else {
                        textOffset = Util.arrayCopyNonAtomic(TEXT_CHANGE, (short)0, LWNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_CHANGE.length);
                        LWNFCForumApplet.FILE_DATA[textOffset++] = TEXT_SPACE;
                        textOffset = writeAmount(textOffset, TC.TX_A_CHANGE_AMOUNT, TC.ctx, TC.TX_A_CHANGE_ADDRESS);
                    }
                    LWNFCForumApplet.FILE_DATA[textOffset++] = TEXT_CLOSE_P;
                    LWNFCForumApplet.FILE_DATA[textOffset++] = TEXT_SPACE;
                    textOffset = Util.arrayCopyNonAtomic(TEXT_PIN, (short)0, LWNFCForumApplet.FILE_DATA, textOffset, (short)TEXT_PIN.length);
                    for (i=0; i<TRANSACTION_PIN_SIZE; i++) {
                        scratch256[i] = (byte)(Crypto.getRandomByteModulo((byte)10));
                        scratch256[i] += (byte)'0';
                    }
                    transactionPin.resetAndUnblock();
                    transactionPin.update(scratch256, (short)0, TRANSACTION_PIN_SIZE);
                    textOffset = Util.arrayCopyNonAtomic(scratch256, (short)0, LWNFCForumApplet.FILE_DATA, textOffset, TRANSACTION_PIN_SIZE);
                    LWNFCForumApplet.writeHeader((short)(textOffset - LWNFCForumApplet.OFFSET_TEXT));
                }
            }
            Crypto.digestAuthorization.doFinal(TC.ctxP, TC.P_TX_A_NONCE, TC.SIZEOF_NONCE, TC.ctxP, TC.P_TX_A_AUTHORIZATION_HASH);
        }
        else {
            Crypto.digestAuthorization.doFinal(TC.ctxP, TC.P_TX_A_NONCE, TC.SIZEOF_NONCE, scratch256, (short)0);
            if (Util.arrayCompare(scratch256, (short)0, TC.ctxP, TC.P_TX_A_AUTHORIZATION_HASH, TC.SIZEOF_SHA256) != 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        }
        short outOffset = (short)0;
        buffer[outOffset++] = (byte)0x00;
        if (TC.ctxP[TC.P_TX_Z_CONSUME_P2SH] == TC.TRUE) {
            buffer[outOffset++] = AUTHORIZATION_NONE;
        }
        else
        if (TC.ctxP[TC.P_TX_Z_WIRED] == TC.TRUE) {
            buffer[outOffset++] = AUTHORIZATION_NFC_KEYCARD;
        }
        else {
            buffer[outOffset++] = AUTHORIZATION_KEYCARD;
        }
        if (TC.ctxP[TC.P_TX_Z_CONSUME_P2SH] == TC.FALSE) {
            if (Keycard.isInitialized()) {
                buffer[outOffset++] = Keycard.issuerKeycardSize;
                Util.arrayCopyNonAtomic(TC.ctxP, TC.P_TX_A_KEYCARD_INDEXES, buffer, outOffset, Keycard.issuerKeycardSize);
                outOffset += Keycard.issuerKeycardSize;
            }
            else {
                buffer[outOffset++] = (byte)0x00;
            }
        }
        TC.ctx[TC.TX_B_TRANSACTION_STATE] = Transaction.STATE_SIGN_READY;
        apdu.setOutgoingAndSend((short)0, outOffset);
    }
    private static void handleHashSignDerive(APDU apdu, boolean checkStage) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;
        byte i;
        apdu.setIncomingAndReceive();
        if (checkStage) {
            checkInterfaceConsistency();
            if (TC.ctx[TC.TX_B_TRANSACTION_STATE] != Transaction.STATE_SIGN_READY) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        }
        byte derivationSize = buffer[offset++];
        if (derivationSize > MAX_DERIVATION_PATH) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        Crypto.initCipher(chipKey, false);
        Crypto.blobEncryptDecrypt.doFinal(masterDerived, (short)0, (short)DEFAULT_SEED_LENGTH, scratch256, (short)0);
        i = Bip32Cache.copyPrivateBest(buffer, (short)(ISO7816.OFFSET_CDATA + 1), derivationSize, scratch256, (short)0);
        offset += (short)(i * 4);
        for (; i<derivationSize; i++) {
            Util.arrayCopyNonAtomic(buffer, offset, scratch256, Bip32.OFFSET_DERIVATION_INDEX, (short)4);
            if ((proprietaryAPI == null) && ((scratch256[Bip32.OFFSET_DERIVATION_INDEX] & (byte)0x80) == 0)) {
                if (!Bip32Cache.setPublicIndex(buffer, (short)(ISO7816.OFFSET_CDATA + 1), i)) {
                    ISOException.throwIt(SW_PUBLIC_POINT_NOT_AVAILABLE);
                }
            }
            if (!Bip32.derive(buffer)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            Bip32Cache.storePrivate(buffer, (short)(ISO7816.OFFSET_CDATA + 1), (byte)(i + 1), scratch256);
            offset += (short)4;
        }
    }
    private static void handleHashSign(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;
        byte i;
     byte derivationSize = buffer[offset++];
        offset += (short)(derivationSize * 4);
        short authorizationLength = (short)(buffer[offset++] & 0xff);
        if (TC.ctxP[TC.P_TX_Z_CONSUME_P2SH] == TC.FALSE) {
            boolean verified = false;
            writeIdleText();
            if (TC.ctxP[TC.P_TX_Z_USE_KEYCARD] == TC.TRUE) {
                Util.arrayCopyNonAtomic(TC.ctxP, TC.P_TX_A_OUTPUT_ADDRESS, scratch256, (short)32, (short)(TC.SIZEOF_RIPEMD + 1));
                Crypto.digestScratch.doFinal(scratch256, (short)32, (short)(TC.SIZEOF_RIPEMD + 1), scratch256, (short)(32 + TC.SIZEOF_RIPEMD + 1));
                Crypto.digestScratch.doFinal(scratch256, (short)(32 + TC.SIZEOF_RIPEMD + 1), TC.SIZEOF_SHA256, scratch256, (short)(32 + TC.SIZEOF_RIPEMD + 1));
                short addressOffset = Base58.encode(scratch256, (short)32, (short)(TC.SIZEOF_RIPEMD + 1 + 4), scratch256, (short)100, scratch256, (short)150);
                verified = Keycard.check(scratch256, (short)100, (byte)(addressOffset - 100),
                    buffer, offset, (byte)authorizationLength,
                    TC.ctxP, TC.P_TX_A_KEYCARD_INDEXES,
                    scratch256, (short)150);
            }
            if (!verified) {
                if (!transactionPin.check(buffer, offset, (byte)authorizationLength)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
            }
        }
        else
        if (TC.ctxP[TC.P_TX_Z_CONSUME_P2SH] != TC.TRUE) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        offset += authorizationLength;
        Uint32Helper.swap(scratch256, (short)100, buffer, offset);
        offset += 4;
        byte sigHashType = buffer[offset++];
        Uint32Helper.clear(scratch256, (short)104);
        scratch256[(short)104] = sigHashType;
        Crypto.digestFull.doFinal(scratch256, (short)100, (short)8, scratch256, (short)100);
        signTransientPrivate(scratch256, (short)0, scratch256, (short)100, buffer, (short)0);
        short signatureSize = (short)((short)(buffer[1] & 0xff) + 2);
        buffer[signatureSize] = sigHashType;
        TC.clear();
        apdu.setOutgoingAndSend((short)0, (short)(signatureSize + 1));
    }
    private static void handleSignMessage(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;
        if (buffer[ISO7816.OFFSET_P1] == P1_PREPARE_MESSAGE) {
            byte derivationSize = buffer[offset++];
            boolean addressVerified = false;
            if (Util.arrayCompare(buffer, offset, SLIP13_HEAD, (short)0, (short)SLIP13_HEAD.length) == (short)0) {
                addressVerified = true;
            }
            else {
                for (byte i=0; i<derivationSize; i++) {
                    if ((Util.arrayCompare(buffer, (short)(offset + 2), BITID_DERIVE, (short)0, (short)BITID_DERIVE.length) == (short)0) ||
                        (Util.arrayCompare(buffer, (short)(offset + 2), BITID_DERIVE_MULTIPLE, (short)0, (short)BITID_DERIVE_MULTIPLE.length) == (short)0)) {
                        addressVerified = true;
                        break;
                    }
                    offset += 4;
                }
            }
            if (!addressVerified) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            offset = (short)(ISO7816.OFFSET_CDATA + 1 + 4 * derivationSize);
            short messageLength = (short)(buffer[offset++] & 0xff);
            Crypto.digestFull.reset();
            Crypto.digestFull.update(SIGNMAGIC, (short)0, (short)SIGNMAGIC.length);
            scratch256[(short)100] = (byte)messageLength;
            Crypto.digestFull.update(scratch256, (short)100, (short)1);
            Crypto.digestFull.doFinal(buffer, offset, messageLength, scratch256, (short)32);
            signTransientPrivate(scratch256, (short)0, scratch256, (short)32, scratch256, (short)100);
            Util.arrayFillNonAtomic(scratch256, (short)0, (short)64, (byte)0x00);
            buffer[(short)0] = (byte)0x00;
            TC.ctx[TC.TX_B_MESSAGE_SIGN_READY] = (byte)0x01;
            apdu.setOutgoingAndSend((short)0, (short)1);
        }
        else
        if (buffer[ISO7816.OFFSET_P1] == P1_SIGN_MESSAGE) {
            if (TC.ctx[TC.TX_B_MESSAGE_SIGN_READY] != (byte)0x01) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            TC.ctx[TC.TX_B_MESSAGE_SIGN_READY] = (byte)0x00;
            short signatureSize = (short)((short)(scratch256[(short)101] & 0xff) + 2);
            Util.arrayCopyNonAtomic(scratch256, (short)100, buffer, (short)0, signatureSize);
            apdu.setOutgoingAndSend((short)0, signatureSize);
        }
        else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }
    private static void handleSetUserKeycard(APDU apdu, boolean airgap) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;
        apdu.setIncomingAndReceive();
        if ((setup == TC.FALSE) || (setup != TC.TRUE)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (Keycard.issuerKeycardSize == (byte)0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (buffer[ISO7816.OFFSET_P1] == P1_SET_KEYCARD) {
            if (buffer[ISO7816.OFFSET_LC] != (byte)(KEYCARD_KEY_LENGTH + 1)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Keycard.setPairingData(buffer, ISO7816.OFFSET_CDATA);
            Keycard.generateRandomIndexes(Keycard.challenge, (short)0, KEYCARD_CHALLENGE_LENGTH);
            buffer[0] = CONFIRM_PREVIOUS_KEYCARD;
            Util.arrayCopyNonAtomic(Keycard.challenge, (short)0, buffer, (short)1, KEYCARD_CHALLENGE_LENGTH);
            apdu.setOutgoingAndSend((short)0, (short)(KEYCARD_CHALLENGE_LENGTH + 1));
        }
        else
        if (buffer[ISO7816.OFFSET_P1] == P1_CONFIRM_KEYCARD) {
            if (buffer[ISO7816.OFFSET_LC] != KEYCARD_CHALLENGE_LENGTH) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            if (!Keycard.check(null, (short)0, (byte)0,
                   buffer, ISO7816.OFFSET_CDATA, (byte)4,
                   Keycard.challenge, (short)0,
                   scratch256, (short)150)) {
                Keycard.clearPairingData();
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            else {
                Keycard.getPairingData(scratch256, (short)0);
                if (!airgap) {
                    Keycard.setUser(scratch256[0], scratch256, (short)1);
                }
                else {
                    Crypto.initCipherAES(pairingKey, false);
                    Crypto.blobEncryptDecryptAES.doFinal(scratch256, (short)1, (short)16, scratch256, (short)100);
                    Keycard.setUser(scratch256[0], scratch256, (short)100);
                }
            }
        }
        else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }
    private static void handleSetup(APDU apdu, boolean airgap) throws ISOException {
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
        Bip32Cache.reset();
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
            if (airgap) {
                Util.arrayCopyNonAtomic(scratch256, (short)0, scratch256, (short)(256 - DEFAULT_SEED_LENGTH), DEFAULT_SEED_LENGTH);
            }
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
            if (airgap) {
                Crypto.initCipherAES(pairingKey, false);
                Crypto.blobEncryptDecryptAES.doFinal(buffer, offset, keyLength, scratch256, (short)0);
            }
            else {
            Util.arrayCopyNonAtomic(buffer, offset, scratch256, (short)0, keyLength);
            }
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
        buffer[offset++] = (airgap ? SEED_ENCODED_AIRGAP : SEED_NOT_TYPED);
        if ((supportedModes & MODE_DEVELOPER) != 0) {
         trustedInputKey.getKey(buffer, offset);
         offset += (short)16;
         developerKey.getKey(buffer, offset);
         offset += (short)16;
        }
        if (airgap) {
            Crypto.initCipherAES(pairingKey, true);
            Crypto.blobEncryptDecryptAES.doFinal(scratch256, (short)(256 - DEFAULT_SEED_LENGTH), DEFAULT_SEED_LENGTH, buffer, offset);
            offset += DEFAULT_SEED_LENGTH;
        }
        apdu.setOutgoingAndSend((short)0, offset);
        setup = TC.TRUE;
    }
    private static void handleVerifyPin(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        if ((setup == TC.FALSE) || (setup != TC.TRUE)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (buffer[ISO7816.OFFSET_P1] == P1_GET_REMAINING_ATTEMPTS) {
         buffer[0] = walletPin.getTriesRemaining();
         apdu.setOutgoingAndSend((short)0, (short)1);
         return;
        }
        apdu.setIncomingAndReceive();
        if (buffer[ISO7816.OFFSET_LC] != walletPinSize) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayFillNonAtomic(scratch256, (short)0, WALLET_PIN_SIZE, (byte)0xff);
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, scratch256, (short)0, walletPinSize);
        if (!walletPin.check(scratch256, (short)0, WALLET_PIN_SIZE)) {
            if (walletPin.getTriesRemaining() == 0) {
                reset();
            }
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
    private static void handleAdmSetKeycardSeed(APDU apdu, boolean airgap) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;
        byte keyLength;
        apdu.setIncomingAndReceive();
        if ((setup == TC.TRUE) || (setup != TC.FALSE)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (buffer[ISO7816.OFFSET_LC] != (byte)(KEYCARD_KEY_LENGTH + 1)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if ((buffer[offset] == (byte)0) || (buffer[offset] > TC.MAX_KEYCARD_DIGIT_ADDRESS)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (!airgap) {
            Keycard.setIssuer(buffer[offset], buffer, (short)(offset + 1));
        }
        else {
            Crypto.initCipherAES(pairingKey, false);
            Crypto.blobEncryptDecryptAES.doFinal(buffer, (short)(offset + 1), (short)16, scratch256, (short)0);
            Keycard.setIssuer(buffer[offset], scratch256, (short)0);
        }
    }
    public static void clearScratch() {
        if (TC.ctx[TC.TX_B_MESSAGE_SIGN_READY] != (byte)0x01) {
            Util.arrayFillNonAtomic(scratch256, (short)0, (short)scratch256.length, (byte)0x00);
        }
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
        if (isContactless()) {
        apdu.waitExtension();
        }
            try {
                switch(buffer[ISO7816.OFFSET_INS]) {
                    case INS_SETUP:
                        handleSetup(apdu, false);
                        break;
                    case INS_SET_USER_KEYCARD:
                        handleSetUserKeycard(apdu, false);
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
                    case INS_UNTRUSTED_HASH_FINALIZE_FULL:
                        if (buffer[ISO7816.OFFSET_P1] == P1_FINALIZE_CHANGEINFO) {
                            handleHashOutputFullChange(apdu);
                        }
                        else {
                            handleHashOutputFull(apdu);
                        }
                        break;
                    case INS_UNTRUSTED_HASH_SIGN:
                        handleHashSignDerive(apdu, true);
                        handleHashSign(apdu);
                        break;
                    case INS_SIGN_MESSAGE:
                        if (buffer[ISO7816.OFFSET_P1] == P1_PREPARE_MESSAGE) {
                            handleHashSignDerive(apdu, false);
                        }
                        handleSignMessage(apdu);
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
        else
        if (buffer[ISO7816.OFFSET_CLA] == CLA_BTC_ADMIN) {
            clearScratch();
            try {
                switch(buffer[ISO7816.OFFSET_INS]) {
                    case INS_ADM_SET_KEYCARD_SEED:
                        handleAdmSetKeycardSeed(apdu, false);
                        break;
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
            }
            catch(Exception e) {
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
        else
        if (buffer[ISO7816.OFFSET_CLA] == CLA_BTC_JC_EXTENSIONS) {
         clearScratch();
         try {
          switch(buffer[ISO7816.OFFSET_INS]) {
           case INS_EXT_GET_HALF_PUBLIC_KEY:
            if (TC.ctx[TC.TX_B_TRANSACTION_STATE] != Transaction.STATE_SIGN_READY) {
             checkAccess(true);
            }
            handleGetHalfPublicKey(apdu);
            break;
           case INS_EXT_PUT_PUBLIC_KEY_CACHE:
            handleStorePublicKey(apdu);
            break;
           case INS_EXT_HAS_PUBLIC_KEY_CACHE:
            handleHasCachedPublicKey(apdu);
            break;
           case INS_EXT_GET_FEATURES:
            handleGetFeatures(apdu);
            break;
                    case INS_EXT_AIRGAP_SET_ATTESTATION_PUBLIC:
                        handleSetAttestationPublic(apdu);
                        break;
                    case INS_EXT_AIRGAP_KEY_AGREEMENT:
                        handleAirgapKeyAgreement(apdu);
                        break;
                    case INS_EXT_AIRGAP_SETUP:
                        if (!pairingDone) {
                            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                        }
                        handleSetup(apdu, true);
                        break;
                    case INS_EXT_AIRGAP_INITIALIZE_KEYCARD_SEED:
                        if (!pairingDone) {
                            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                        }
                        handleAdmSetKeycardSeed(apdu, true);
                        break;
                    case INS_EXT_AIRGAP_GET_ATTESTATION:
                        handleGetAttestation(apdu);
                        break;
                    case INS_EXT_AIRGAP_SET_USER_KEYCARD:
                        handleSetUserKeycard(apdu, true);
                        break;
           default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
          }
         }
         catch(Exception e) {
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
        else {
         ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }
    public static void install (byte bArray[], short bOffset, byte bLength) throws ISOException {
        short offset = bOffset;
        offset += (short)(bArray[offset] + 1);
        offset += (short)(bArray[offset] + 1);
        new LedgerWalletApplet(bArray, (short)(offset + 1), bArray[offset]).register(bArray, (short)(bOffset + 1), bArray[bOffset]);
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
    private static final byte AUTHORIZATION_NONE = (byte)0x00;
    private static final byte AUTHORIZATION_KEYCARD = (byte)0x04;
    private static final byte AUTHORIZATION_NFC_KEYCARD = (byte)0x05;
    private static final byte TRANSACTION_OUTPUT_SCRIPT_PRE[] = { (byte)0x19, (byte)0x76, (byte)0xA9, (byte)0x14 };
    private static final byte TRANSACTION_OUTPUT_SCRIPT_POST[] = { (byte)0x88, (byte)0xAC };
    private static final byte TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE[] = { (byte)0x17, (byte)0xA9, (byte)0x14 };
    private static final byte TRANSACTION_OUTPUT_SCRIPT_P2SH_POST[] = { (byte)0x87 };
    private static final byte OP_RETURN = (byte)0x6A;
    private static final byte KEY_VERSION_P2SH = (byte)0x05;
    private static final byte KEY_VERSION_P2SH_TESTNET = (byte)0xC4;
    private static final byte KEY_VERSION_PRIVATE = (byte)0x80;
    private static final byte KEY_VERSION = (byte)0x00;
    private static final byte KEY_VERSION_TESTNET = (byte)0x6F;
    private static final byte PUBLIC_KEY_W_LENGTH = 65;
    private static final byte PRIVATE_KEY_S_LENGTH = 32;
    private static final byte CLA_BTC_ADMIN = (byte)0xD0;
    private static final byte CLA_BTC = (byte)0xE0;
    private static final byte CLA_BTC_JC_EXTENSIONS = (byte)0xF0;
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
    private static final byte INS_ADM_SET_KEYCARD_SEED = (byte)0x26;
    private static final byte INS_SET_CONTACTLESS_LIMIT = (byte)0xA4;
    private static final byte INS_GET_CONTACTLESS_LIMIT = (byte)0xA6;
    private static final byte INS_EXT_GET_HALF_PUBLIC_KEY = (byte)0x20;
    private static final byte INS_EXT_PUT_PUBLIC_KEY_CACHE = (byte)0x22;
    private static final byte INS_EXT_HAS_PUBLIC_KEY_CACHE = (byte)0x24;
    private static final byte INS_EXT_GET_FEATURES = (byte)0x26;
    private static final byte INS_EXT_AIRGAP_KEY_AGREEMENT = (byte)0x40;
    private static final byte INS_EXT_AIRGAP_SETUP = (byte)0x42;
    private static final byte INS_EXT_AIRGAP_INITIALIZE_KEYCARD_SEED = (byte)0x44;
    private static final byte INS_EXT_AIRGAP_SET_USER_KEYCARD = (byte)0x46;
    private static final byte INS_EXT_AIRGAP_SET_ATTESTATION_PUBLIC = (byte)0x48;
    private static final byte INS_EXT_AIRGAP_GET_ATTESTATION = (byte)0x4A;
    private static final byte P1_REGULAR_SETUP = (byte)0x00;
    private static final byte P1_TRUSTED_INPUT_FIRST = (byte)0x00;
    private static final byte P1_TRUSTED_INPUT_NEXT = (byte)0x80;
    private static final byte P1_HASH_TRANSACTION_FIRST = (byte)0x00;
    private static final byte P1_HASH_TRANSACTION_NEXT = (byte)0x80;
    private static final byte P2_HASH_TRANSACTION_NEW_INPUT = (byte)0x00;
    private static final byte P2_HASH_TRANSACTION_CONTINUE_INPUT = (byte)0x80;
    private static final byte P1_FINALIZE_MORE = (byte)0x00;
    private static final byte P1_FINALIZE_LAST = (byte)0x80;
    private static final byte P1_FINALIZE_CHANGEINFO = (byte)0xFF;
    private static final byte[] SLIP13_HEAD = { (byte)0x80, (byte)0x00, (byte)0x00, (byte)0x0D };
    private static final byte[] BITID_DERIVE = { (byte)0xB1, (byte)0x1D };
    private static final byte[] BITID_DERIVE_MULTIPLE = { (byte)0xB1, (byte)0x1E };
    private static final byte[] SIGNMAGIC = { (byte)0x18, (byte)'B', (byte)'i', (byte)'t', (byte)'c', (byte)'o', (byte)'i', (byte)'n', (byte)' ', (byte)'S', (byte)'i', (byte)'g', (byte)'n', (byte)'e', (byte)'d', (byte)' ', (byte)'M', (byte)'e', (byte)'s', (byte)'s', (byte)'a', (byte)'g', (byte)'e', (byte)':', (byte)'\n' };
    private static final byte P1_PREPARE_MESSAGE = (byte)0x00;
    private static final byte P1_SIGN_MESSAGE = (byte)0x80;
    private static final byte P1_GET_REMAINING_ATTEMPTS = (byte)0x80;
    private static final byte P1_GET_OPERATION_MODE = (byte)0x00;
    private static final byte P1_GET_OPERATION_MODE_2FA = (byte)0x01;
    private static final byte P1_INITIATE_PAIRING = (byte)0x01;
    private static final byte P1_CONFIRM_PAIRING = (byte)0x02;
    private static final byte P1_SET_KEYCARD = (byte)0x01;
    private static final byte P1_CONFIRM_KEYCARD = (byte)0x02;
    private static final byte CONFIRM_PREVIOUS_KEYCARD = (byte)0x02;
    public static final byte BLOB_MAGIC_TRUSTED_INPUT = (byte)0x32;
    private static final byte LIMIT_GLOBAL_AMOUNT = (byte)0;
    private static final byte LIMIT_MAX_FEES = (byte)(LIMIT_GLOBAL_AMOUNT + TC.SIZEOF_AMOUNT);
    private static final byte LIMIT_MAX_CHANGE = (byte)(LIMIT_MAX_FEES + TC.SIZEOF_AMOUNT);
    private static final byte LIMIT_LAST = (byte)(LIMIT_MAX_CHANGE + TC.SIZEOF_AMOUNT);
    protected static final byte MODE_WALLET = (byte)0x01;
    protected static final byte MODE_RELAXED_WALLET = (byte)0x02;
    protected static final byte MODE_SERVER = (byte)0x04;
    protected static final byte MODE_DEVELOPER = (byte)0x08;
    private static final byte SFA_NONE = (byte)0x00;
    private static final byte SFA_ORIGINAL = (byte)0x11;
    private static final byte SFA_SECURITY_CARD = (byte)0x12;
    private static final byte SFA_SECURE_SCREEN = (byte)0x13;
    private static final byte SFA_NFC = (byte)0x20;
    protected static final byte FEATURE_UNCOMPRESSED_KEYS = (byte)0x01;
    protected static final byte FEATURE_RFC_6979 = (byte)0x02;
    protected static final byte FEATURE_ALL_HASHTYPES = (byte)0x04;
    protected static final byte FEATURE_NO_2FA_P2SH = (byte)0x08;
    protected static final byte FEATURE_ARBITRARY_CHANGE = (byte)0x10;
    private static final byte DEFAULT_SEED_LENGTH = (byte)64;
    private static final byte KEYCARD_KEY_LENGTH = (byte)16;
    private static final byte KEYCARD_CHALLENGE_LENGTH = (byte)4;
    private static final byte MAX_DERIVATION_PATH = (byte)10;
    private static final byte SEED_NOT_TYPED = (byte)0x00;
    private static final byte SEED_ENCODED_AIRGAP = (byte)0xF0;
    private static final byte AVAILABLE_MODES[] = { MODE_WALLET, MODE_RELAXED_WALLET, MODE_SERVER, MODE_DEVELOPER };
    private static final byte JC_FEATURE_HAS_PROPRIETARY_API = (byte)0x01;
    public static byte[] scratch256;
    private static OwnerPIN transactionPin;
    private static OwnerPIN walletPin;
    private static byte walletPinSize;
    private static OwnerPIN secondaryPin;
    private static byte secondaryPinSize;
    private static byte setup;
    private static byte limitsSet;
    protected static DESKey chipKey;
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
    protected static AESKey pairingKey;
    protected static ECPrivateKey attestationPrivate;
    protected static byte[] attestationPublic;
    protected static byte[] attestationSignature;
    protected static boolean pairingDone;
}
