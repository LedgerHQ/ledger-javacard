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
    }

    public static void uninit() {
        issuerKeycard = null;
    }

    public static void set(byte issuerKeycardSize, byte[] buffer, short offset) {        
        issuerKeycard.setKey(buffer, offset);
        Keycard.issuerKeycardSize = issuerKeycardSize;
    }

    public static boolean isInitialized() {
        return (issuerKeycardSize != (byte)0);
    }

    public static void generateIndexes(byte[] target, short offset, byte addressSize) {
        for (byte i=0; i<issuerKeycardSize; i++) {
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

    public static boolean check(byte[] address, short addressOffset, byte addressSize, byte[] code, short codeOffset, byte codeSize, byte[] indexes, short indexesOffset, byte[] scratch, short scratchOffset) {
        byte i;
        for (i=0; i<KEYCARD_SIZE; i++) {
            scratch[(short)(scratchOffset + i)] = i;
        }
        Crypto.initCipher(issuerKeycard, true);
        Crypto.blobEncryptDecrypt.doFinal(scratch, scratchOffset, KEYCARD_SIZE, scratch, scratchOffset);
        for (i=0; i<KEYCARD_SIZE; i++) {
            scratch[(short)(scratchOffset + i)] = (byte)(((scratch[(short)(scratchOffset + i)] >> 4) & 0x0f) ^ (scratch[(short)(scratchOffset + i)] & 0x0f));
        }
        for (i=0; i<issuerKeycardSize; i++) {
            short addressCode = (short)((address[(short)(addressOffset + indexes[(short)(indexesOffset + i)])] & 0xff) - (short)0x30);
            if (code[(short)(codeOffset + i)] != scratch[(short)(scratchOffset + addressCode)]) {
                return false;
            }
        }
        return true;
    }

    private static final byte KEYCARD_SIZE = (byte)0x50;

    protected static byte issuerKeycardSize;
    private static DESKey issuerKeycard;

	
}
