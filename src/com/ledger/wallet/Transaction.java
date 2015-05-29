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

import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Bitcoin transaction parsing
 * @author BTChip
 *
 */
public class Transaction {
    
    public static void init() {
        h = JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_DESELECT);
    }
    
    private static void consumeTransaction(byte buffer[], short length) {
        if ((TC.ctx[TC.TX_B_HASH_OPTION] & HASH_FULL) != 0) {
            Crypto.digestFull.update(buffer, h[CURRENT], length);
        }
        if ((TC.ctx[TC.TX_B_HASH_OPTION] & HASH_AUTHORIZATION) != 0) {
            Crypto.digestAuthorization.update(buffer, h[CURRENT], length);
        }
        h[REMAINING] -= length;
        h[CURRENT] += length;
    }
    
    private static boolean parseVarint(byte[] buffer, byte[] target, short targetOffset) {
        if (h[REMAINING] < (short)1) {
            return false;
        }
        short firstByte = (short)(buffer[h[CURRENT]] & 0xff);
        if (firstByte < (short)0xfd) {
            Uint32Helper.setByte(target, targetOffset, (byte)firstByte);
            consumeTransaction(buffer, (short)1);            
        }
        else
        if (firstByte == (short)0xfd) {
            consumeTransaction(buffer, (short)1);
            if (h[REMAINING] < (short)2) {
                return false;
            }
            Uint32Helper.setShort(target, targetOffset, buffer[(short)(h[CURRENT] + 1)], buffer[h[CURRENT]]);
            consumeTransaction(buffer, (short)2);
        }
        else
        if (firstByte == (short)0xfe) {
            consumeTransaction(buffer, (short)1);
            if (h[REMAINING] < (short)2) {
                return false;
            }
            Uint32Helper.setInt(target, targetOffset, buffer[(short)(h[CURRENT] + 3)], buffer[(short)(h[CURRENT] + 2)], buffer[(short)(h[CURRENT] + 1)], buffer[h[CURRENT]]);
            consumeTransaction(buffer, (short)4);
        }
        else {
            return false;
        }
        return true;
    }
        
    public static byte parseTransaction(byte parseMode, byte buffer[], short offset, short remaining) {
        h[CURRENT] = offset;
        h[REMAINING] = remaining;
        for (;;) {
            if (TC.ctx[TC.TX_B_TRANSACTION_STATE] == STATE_NONE) {
                Uint32Helper.clear(TC.ctx, TC.TX_I_REMAINING_IO);
                Uint32Helper.clear(TC.ctx, TC.TX_I_CURRENT_IO);
                Uint32Helper.clear(TC.ctx, TC.TX_I_SCRIPT_REMAINING);
                Uint64Helper.clear(TC.ctx, TC.TX_A_TRANSACTION_AMOUNT);
                Crypto.digestFull.reset();
                Crypto.digestAuthorization.reset();
                // Parse the beginning of the transaction
                // Version
                if (h[REMAINING] < (short)4) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)4);
                // Number of inputs
                if (!parseVarint(buffer, TC.ctx, TC.TX_I_REMAINING_IO)) {
                    return RESULT_ERROR;
                }
                TC.ctx[TC.TX_B_TRANSACTION_STATE] = STATE_DEFINED_WAIT_INPUT;
            }
            if (TC.ctx[TC.TX_B_TRANSACTION_STATE] == STATE_DEFINED_WAIT_INPUT) {
                if (Uint32Helper.isZero(TC.ctx, TC.TX_I_REMAINING_IO)) {
                    // No more inputs to hash, move forward
                    TC.ctx[TC.TX_B_TRANSACTION_STATE] = STATE_INPUT_HASHING_DONE;
                    continue;
                }
                if (h[REMAINING] < (short)1) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                // Proceed with the next input
                if (parseMode == PARSE_TRUSTED_INPUT) {
                    if (h[REMAINING] < (short)36) { // prevout : 32 hash + 4 index
                        return RESULT_ERROR;
                    }
                    consumeTransaction(buffer, (short)36);
                }
                if (parseMode == PARSE_SIGNATURE) {
                    // Expect the trusted input keyset and trusted input length
                    if (h[REMAINING] < (short)2) {
                        return RESULT_ERROR;
                    }
                    byte trustedInputKeyset = buffer[h[CURRENT]];
                    short trustedInputLength = (short)(buffer[(short)(h[CURRENT] + 1)] & 0xff);
                    if (trustedInputLength > BTChipPocApplet.scratch255.length) {
                        return RESULT_ERROR;
                    }
                    if (h[REMAINING] < (short)(2 + trustedInputLength)) {
                        return RESULT_ERROR;
                    }
                    if (buffer[(short)(h[CURRENT] + 2)] != BTChipPocApplet.BLOB_MAGIC_TRUSTED_INPUT) {
                        return RESULT_ERROR;
                    }                                        
                    WrappingKeyRepository.WrappingKey encryptionKey = WrappingKeyRepository.find(trustedInputKeyset, WrappingKeyRepository.ROLE_TRUSTED_INPUT_ENCRYPTION);
                    if (encryptionKey == null) {
                        return RESULT_ERROR;
                    }
                    // Check the "signature"
                    encryptionKey.initCipher(true);
                    Crypto.blobEncryptDecrypt.doFinal(buffer, (short)(h[CURRENT] + 2), (short)(trustedInputLength - 8), BTChipPocApplet.scratch255, (short)0);
                    if (Util.arrayCompare(buffer, (short)(h[CURRENT] + 2 + trustedInputLength - 8), BTChipPocApplet.scratch255, (short)(trustedInputLength - 16), (short)8) != 0) {
                        return RESULT_ERROR;
                    }
                    // Update the amount
                    Uint64Helper.swap(BTChipPocApplet.scratch255, (short)0, buffer, (short)(h[CURRENT] + 2 + 40)); 
                    Uint64Helper.add(TC.ctx, TC.TX_A_TRANSACTION_AMOUNT, BTChipPocApplet.scratch255, (short)0);                    
                    // Update the hash with prevout data
                    short savedCurrent = h[CURRENT];
                    short savedRemaining = h[REMAINING];
                    h[CURRENT] += (short)(4 + 2);
                    consumeTransaction(buffer, (short)36);
                    h[CURRENT] = (short)(savedCurrent + 2 + trustedInputLength);
                    h[REMAINING] = (short)(savedRemaining - 2 - trustedInputLength);
                    // Do not include the input script length + value in the authentication hash
                    TC.ctx[TC.TX_B_HASH_OPTION] = HASH_FULL;                                            
                }
                // Read the script length
                if (!parseVarint(buffer, TC.ctx, TC.TX_I_SCRIPT_REMAINING)) {
                    return RESULT_ERROR;
                }
                TC.ctx[TC.TX_B_TRANSACTION_STATE] = STATE_INPUT_HASHING_IN_PROGRESS_INPUT_SCRIPT;                
            }
            if (TC.ctx[TC.TX_B_TRANSACTION_STATE] == STATE_INPUT_HASHING_IN_PROGRESS_INPUT_SCRIPT) {
                if (h[REMAINING] < (short)1) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                if (Uint32Helper.isZero(TC.ctx,TC.TX_I_SCRIPT_REMAINING)) {
                    if (parseMode == PARSE_SIGNATURE) {
                        // Restore dual hash for signature + authentication
                        TC.ctx[TC.TX_B_HASH_OPTION] = HASH_BOTH;
                    }
                    // Sequence
                    if (h[REMAINING] < (short)4) {
                        return RESULT_ERROR;
                    }
                    // TODO : enforce sequence
                    consumeTransaction(buffer, (short)4);
                    // Move to next input
                    Uint32Helper.decrease(TC.ctx, TC.TX_I_REMAINING_IO);
                    Uint32Helper.increase(TC.ctx, TC.TX_I_CURRENT_IO);
                    TC.ctx[TC.TX_B_TRANSACTION_STATE] = STATE_DEFINED_WAIT_INPUT;
                    continue;
                }
                short scriptRemaining = Uint32Helper.getU8(TC.ctx, TC.TX_I_SCRIPT_REMAINING);
                short dataAvailable = (h[REMAINING] > scriptRemaining ? scriptRemaining : h[REMAINING]);
                if (dataAvailable == 0) {
                    return RESULT_MORE;
                }
                consumeTransaction(buffer, dataAvailable);
                Uint32Helper.setByte(BTChipPocApplet.scratch255, (short)0, (byte)dataAvailable);
                Uint32Helper.sub(TC.ctx, TC.TX_I_SCRIPT_REMAINING, BTChipPocApplet.scratch255, (short)0);
            }
            if (TC.ctx[TC.TX_B_TRANSACTION_STATE] == STATE_INPUT_HASHING_DONE) {
                if (parseMode == PARSE_SIGNATURE) {
                    // inputs have been prepared, stop the parsing here
                    TC.ctx[TC.TX_B_TRANSACTION_STATE] = STATE_PRESIGN_READY;
                    continue;
                }
                if (h[REMAINING] < (short)1) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                // Number of outputs
                if (!parseVarint(buffer, TC.ctx, TC.TX_I_REMAINING_IO)) {
                    return RESULT_ERROR;
                }
                Uint32Helper.clear(TC.ctx, TC.TX_I_CURRENT_IO);
                TC.ctx[TC.TX_B_TRANSACTION_STATE] = STATE_DEFINED_WAIT_OUTPUT;
            }
            if (TC.ctx[TC.TX_B_TRANSACTION_STATE] == STATE_DEFINED_WAIT_OUTPUT) {
                if (Uint32Helper.isZero(TC.ctx, TC.TX_I_REMAINING_IO)) {
                    // No more outputs to hash, move forward
                    TC.ctx[TC.TX_B_TRANSACTION_STATE] = STATE_OUTPUT_HASHING_DONE;
                    continue;
                }
                if (h[REMAINING] < (short)1) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                // Amount
                if (h[REMAINING] < (short)8) {
                    return RESULT_ERROR;
                }
                if ((parseMode == PARSE_TRUSTED_INPUT) && (
                  Util.arrayCompare(TC.ctx, TC.TX_I_CURRENT_IO, TC.ctx, TC.TX_I_TRANSACTION_TARGET_INPUT, TC.SIZEOF_U32) == 0)) {
                    // Save the amount
                    Util.arrayCopyNonAtomic(buffer, h[CURRENT], TC.ctx, TC.TX_A_TRANSACTION_AMOUNT, TC.SIZEOF_AMOUNT);
                    TC.ctx[TC.TX_B_TRUSTED_INPUT_PROCESSED] = (byte)0x01;
                }
                consumeTransaction(buffer, (short)8);
                // Read the script length
                if (!parseVarint(buffer, TC.ctx, TC.TX_I_SCRIPT_REMAINING)) {
                    return RESULT_ERROR;
                }
                TC.ctx[TC.TX_B_TRANSACTION_STATE] = STATE_OUTPUT_HASHING_IN_PROGRESS_OUTPUT_SCRIPT;
            }
            if (TC.ctx[TC.TX_B_TRANSACTION_STATE] == STATE_OUTPUT_HASHING_IN_PROGRESS_OUTPUT_SCRIPT) {
                if (h[REMAINING] < (short)1) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                if (Uint32Helper.isZero(TC.ctx,TC.TX_I_SCRIPT_REMAINING)) {
                    // Move to next output
                    Uint32Helper.decrease(TC.ctx, TC.TX_I_REMAINING_IO);
                    Uint32Helper.increase(TC.ctx, TC.TX_I_CURRENT_IO);
                    TC.ctx[TC.TX_B_TRANSACTION_STATE] = STATE_DEFINED_WAIT_OUTPUT;
                    continue;
                }
                short scriptRemaining = Uint32Helper.getU8(TC.ctx, TC.TX_I_SCRIPT_REMAINING);
                short dataAvailable = (h[REMAINING] > scriptRemaining ? scriptRemaining : h[REMAINING]);
                if (dataAvailable == 0) {
                    return RESULT_MORE;
                }
                consumeTransaction(buffer, dataAvailable);
                Uint32Helper.setByte(BTChipPocApplet.scratch255, (short)0, (byte)dataAvailable);
                Uint32Helper.sub(TC.ctx, TC.TX_I_SCRIPT_REMAINING, BTChipPocApplet.scratch255, (short)0);
            }
            if (TC.ctx[TC.TX_B_TRANSACTION_STATE] == STATE_OUTPUT_HASHING_DONE) {
                if (h[REMAINING] < (short)1) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                // Locktime
                if (h[REMAINING] < (short)4) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)4);
                TC.ctx[TC.TX_B_TRANSACTION_STATE] = STATE_PARSED;
            }
            if (TC.ctx[TC.TX_B_TRANSACTION_STATE] == STATE_PARSED) {
                return RESULT_FINISHED;
            }
            if (TC.ctx[TC.TX_B_TRANSACTION_STATE] == STATE_PRESIGN_READY) {
                return RESULT_FINISHED;
            }
            if (TC.ctx[TC.TX_B_TRANSACTION_STATE] == STATE_SIGN_READY) {
                return RESULT_FINISHED;
            }                        
        }
    }
    
    private static short[] h;
    
    private static final byte CURRENT = (byte)0;
    private static final byte REMAINING = (byte)1;
    
    public static final byte STATE_NONE = (byte)0x00;
    public static final byte STATE_DEFINED_WAIT_INPUT = (byte)0x01;
    public static final byte STATE_INPUT_HASHING_IN_PROGRESS_INPUT_SCRIPT = (byte)0x02;
    public static final byte STATE_INPUT_HASHING_DONE = (byte)0x03;
    public static final byte STATE_DEFINED_WAIT_OUTPUT = (byte)0x04;
    public static final byte STATE_OUTPUT_HASHING_IN_PROGRESS_OUTPUT_SCRIPT = (byte)0x05;
    public static final byte STATE_OUTPUT_HASHING_DONE = (byte)0x06;
    public static final byte STATE_PARSED = (byte)0x07;
    public static final byte STATE_PRESIGN_READY = (byte)0x08;
    public static final byte STATE_SIGN_READY = (byte)0x09;
    
    public static final byte HASH_NONE = (byte)0x00;
    public static final byte HASH_FULL = (byte)0x01;
    public static final byte HASH_AUTHORIZATION = (byte)0x02;
    public static final byte HASH_BOTH = (byte)0x03;
    
    public static final byte PARSE_TRUSTED_INPUT = (byte)0x01;
    public static final byte PARSE_SIGNATURE = (byte)0x02;
    
    public static final byte RESULT_FINISHED = (byte)0x13;
    public static final byte RESULT_ERROR = (byte)0x79;
    public static final byte RESULT_MORE = (byte)0x00;

}
