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

/**
 * Storage of transaction context
 * @author BTChip
 *
 */
public class TC {
    
    public static void init() {
        ctx = JCSystem.makeTransientByteArray(TX_CONTEXT_SIZE, JCSystem.CLEAR_ON_DESELECT);
        ctxP = new byte[P_TX_CONTEXT_SIZE];
    }

    public static void uninit() {
        ctx = null;
        ctxP = null;
    }
    
    public static void clear() {
        Util.arrayFillNonAtomic(ctx, (short)0, (short)ctx.length, (byte)0x00);
    }
    
    protected static final byte SIZEOF_U32 = 4;
    protected static final byte SIZEOF_U8 = 1;
    protected static final byte SIZEOF_AMOUNT = 8;
    protected static final byte SIZEOF_NONCE = 8;
    protected static final byte SIZEOF_SHA256 = 32;
    protected static final byte SIZEOF_RIPEMD = 20;
    protected static final byte MAX_KEYCARD_DIGIT_ADDRESS = 10;
    
    protected static final byte TRUE = (byte)0x37;
    protected static final byte FALSE = (byte)0xda;
    
    protected static final short TX_B_HASH_OPTION = (short)0;
    protected static final short TX_B_TRUSTED_INPUT_PROCESSED = (short)(TX_B_HASH_OPTION + SIZEOF_U8); 
    protected static final short TX_I_TRANSACTION_TARGET_INPUT = (short)(TX_B_TRUSTED_INPUT_PROCESSED + SIZEOF_U8); 
    protected static final short TX_I_REMAINING_IO = (short)(TX_I_TRANSACTION_TARGET_INPUT + SIZEOF_U32);
    protected static final short TX_I_CURRENT_IO = (short)(TX_I_REMAINING_IO + SIZEOF_U32);
    protected static final short TX_I_SCRIPT_REMAINING = (short)(TX_I_CURRENT_IO + SIZEOF_U32);
    protected static final short TX_B_TRANSACTION_STATE = (short)(TX_I_SCRIPT_REMAINING + SIZEOF_U32);
    protected static final short TX_A_TRANSACTION_AMOUNT = (short)(TX_B_TRANSACTION_STATE + SIZEOF_U8);
    protected static final short TX_Z_CHANGE_INITIALIZED = (short)(TX_A_TRANSACTION_AMOUNT + SIZEOF_AMOUNT);
    protected static final short TX_Z_CHANGE_ACCEPTED = (short)(TX_Z_CHANGE_INITIALIZED + SIZEOF_U8);
    protected static final short TX_Z_MULTIPLE_OUTPUT = (short)(TX_Z_CHANGE_ACCEPTED + SIZEOF_U8);
    protected static final short TX_Z_CHANGE_CHECKED = (short)(TX_Z_MULTIPLE_OUTPUT + SIZEOF_U8);
    protected static final short TX_A_OUTPUT_AMOUNT = (short)(TX_Z_CHANGE_CHECKED + SIZEOF_U8);
    protected static final short TX_A_FEE_AMOUNT = (short)(TX_A_OUTPUT_AMOUNT + SIZEOF_AMOUNT);
    protected static final short TX_A_CHANGE_AMOUNT = (short)(TX_A_FEE_AMOUNT + SIZEOF_AMOUNT);  
    protected static final short TX_A_CHANGE_ADDRESS = (short)(TX_A_CHANGE_AMOUNT + SIZEOF_AMOUNT);
    protected static final short TX_CONTEXT_SIZE = (short)(TX_A_CHANGE_ADDRESS + SIZEOF_RIPEMD + 1);
    
    protected static final short P_TX_Z_WIRED = (short)0;
    protected static final short P_TX_Z_RELAXED = (short)(P_TX_Z_WIRED + SIZEOF_U8); 
    protected static final short P_TX_A_AUTHORIZATION_HASH = (short)(P_TX_Z_RELAXED + SIZEOF_U8);
    protected static final short P_TX_Z_FIRST_SIGNED = (short)(P_TX_A_AUTHORIZATION_HASH + SIZEOF_SHA256);
    protected static final short P_TX_Z_USE_KEYCARD = (short)(P_TX_Z_FIRST_SIGNED + SIZEOF_U8);
    protected static final short P_TX_Z_CONSUME_P2SH = (short)(P_TX_Z_USE_KEYCARD + SIZEOF_U8);
    protected static final short P_TX_A_KEYCARD_INDEXES = (short)(P_TX_Z_CONSUME_P2SH + SIZEOF_U8);
    protected static final short P_TX_A_NONCE = (short)(P_TX_A_KEYCARD_INDEXES + MAX_KEYCARD_DIGIT_ADDRESS); // must be a counter
    protected static final short P_TX_A_OUTPUT_ADDRESS = (short)(P_TX_A_NONCE + SIZEOF_NONCE);
    protected static final short P_TX_CONTEXT_SIZE = (short)(P_TX_A_OUTPUT_ADDRESS + SIZEOF_RIPEMD + 1);
        
    protected static byte[] ctx;
    protected static byte[] ctxP;

}
