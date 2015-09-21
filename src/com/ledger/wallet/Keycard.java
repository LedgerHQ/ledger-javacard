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
import javacard.security.DESKey;
import javacard.security.KeyBuilder;

/**
 * Hardware Wallet Security Card implementation
 * @author BTChip
 *
 */
public class Keycard {

    public static void init() {
        issuerKeycard = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
        userKeycard = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
        pairingData = JCSystem.makeTransientByteArray((byte)(PAIRING_DATA_SIZE + 1), JCSystem.CLEAR_ON_DESELECT);
        challenge = JCSystem.makeTransientByteArray((byte)4, JCSystem.CLEAR_ON_DESELECT);
    }

    public static void setPairingData(byte[] data, short offset) {
        pairingData[0] = (byte)0x01;
        Util.arrayCopyNonAtomic(data, offset, pairingData, (short)1, PAIRING_DATA_SIZE);
    }

    public static boolean getPairingData(byte[] data, short offset) {
        if (pairingData[0] == (byte)0) {
            return false;
        }
        Util.arrayCopyNonAtomic(pairingData, (short)1, data, offset, PAIRING_DATA_SIZE);
        pairingData[0] = (byte)0x00;
        return true;
    }

    public static void clearPairingData() {
        pairingData[0] = (byte)0x00;
    }

    public static void setIssuer(byte issuerKeycardSize, byte[] buffer, short offset) {        
        issuerKeycard.setKey(buffer, offset);
        Keycard.issuerKeycardSize = issuerKeycardSize;
    }

    public static void setUser(byte userKeycardSize, byte[] buffer, short offset) {
        userKeycard.setKey(buffer, offset);
        Keycard.userKeycardSize = userKeycardSize;
    }

    public static boolean isInitialized() {
        return (issuerKeycardSize != (byte)0);
    }

    public static boolean isInitializedUser() {
        return (userKeycardSize != (byte)0);
    }

    public static void generateIndexes(byte[] target, short offset, byte addressSize) {
        byte size = (userKeycardSize != (byte)0 ? userKeycardSize : issuerKeycardSize);
        for (byte i=0; i<size; i++) {
            boolean unique = true;
            do {
                target[(short)(offset + i)] = Crypto.getRandomByteModulo(addressSize);
                for (byte k=0; k<i; k++) {
                    if (target[(short)(offset + k)] == target[(short)(offset + i)]) {
                        unique = false;
                        break;
                    }
                }
            }
            while (!unique);
        }
    }

    public static void generateRandomIndexes(byte[] target, short offset, byte randomSize) {
        for (byte i=0; i<randomSize; i++) {
            byte index;
            do {
                index = Crypto.getRandomByteModulo((short)128);
            }
            while(Base58.BASE58TABLE[index] == (byte)0xff);
            target[(short)(offset + i)] = (byte)(index - 0x30);
        }
    }

    public static boolean check(byte[] address, short addressOffset, byte addressSize, byte[] code, short codeOffset, byte codeSize, byte[] indexes, short indexesOffset, byte[] scratch, short scratchOffset) {
        byte size = (userKeycardSize != (byte)0 ? userKeycardSize : issuerKeycardSize);                
        DESKey key = (userKeycardSize != (byte)0 ? userKeycard : issuerKeycard);
        byte i;
        for (i=0; i<KEYCARD_SIZE; i++) {
            scratch[(short)(scratchOffset + i)] = i;
        }
        Crypto.initCipher(key, true);
        Crypto.blobEncryptDecrypt.doFinal(scratch, scratchOffset, KEYCARD_SIZE, scratch, scratchOffset);
        for (i=0; i<KEYCARD_SIZE; i++) {
            scratch[(short)(scratchOffset + i)] = (byte)(((scratch[(short)(scratchOffset + i)] >> 4) & 0x0f) ^ (scratch[(short)(scratchOffset + i)] & 0x0f));
        }
        for (i=0; i<size; i++) {
            short addressCode;
            if (address != null) {
                addressCode = (short)((address[(short)(addressOffset + indexes[(short)(indexesOffset + i)])] & 0xff) - (short)0x30);
            }
            else {
                addressCode = indexes[(short)(indexesOffset + i)];
            }
            if (code[(short)(codeOffset + i)] != scratch[(short)(scratchOffset + addressCode)]) {
                return false;
            }
        }
        return true;
    }

    private static final byte KEYCARD_SIZE = (byte)0x50;
    private static final byte PAIRING_DATA_SIZE = (byte)17;

    protected static byte issuerKeycardSize;
    private static DESKey issuerKeycard;
    protected static byte userKeycardSize;
    private static DESKey userKeycard;
    protected static byte[] pairingData;	
    protected static byte[] challenge;
}
