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

/**
 * Base 58 encoding and decoding
 * @author BTChip
 *
 */
public class Base58 {
    
    public static short encode(byte[] in, short inOffset, short inLength, byte[] out, short outOffset, byte[] scratch, short scratchOffset) {
        short zeroCount = (short)0, j, startAt;
        while ((zeroCount < inLength) && (in[(short)(inOffset + zeroCount)] == 0)) {
            ++zeroCount;
        }
        Util.arrayCopyNonAtomic(in, inOffset, scratch, scratchOffset, inLength);
        j = (short)(2 * inLength);
        startAt = zeroCount;
        while(startAt < inLength) {
            short remainder = 0;
            short divLoop;
            for (divLoop = startAt ; divLoop < inLength; divLoop++) {
                short digit256 = (short)(scratch[(short)(scratchOffset + divLoop)] & 0xff);
                short tmpDiv = (short)(remainder * 256 + digit256);
                scratch[(short)(scratchOffset + divLoop)] = (byte)(tmpDiv / 58);
                remainder = (short)(tmpDiv % 58);
            }
            if (scratch[(short)(scratchOffset + startAt)] == 0) {
                ++startAt;
            }
            out[(short)(outOffset + --j)] = (byte)ALPHABET[remainder];            
        }
        while ((j < ((short)(2 * inLength))) && (out[(short)(outOffset + j)] == ALPHABET[0])) {
            ++j;
        }
        while (--zeroCount >= 0) {
            out[(short)(outOffset + --j)] = (byte)ALPHABET[0];
        }
        short resultLength = (short)((2 * inLength) - j);
        Util.arrayCopyNonAtomic(out, (short)(outOffset + j), out, outOffset, resultLength);
        return (short)(outOffset + resultLength);                
    }
    
    public static short decode(byte[] in, short inOffset, short inLength, byte[] out, short outOffset, byte[] scratch, short scratchOffset) {
      try {  
        short zeroCount = (short)0, j, startAt;
        for (short i=0; i<inLength; i++) {
            short value = (short)(in[(short)(inOffset + i)] & 0xff);
            if (value > 128) {
                return (short)-1;
            }
            byte base58Value = BASE58TABLE[value];
            if (base58Value == (byte)0xff) {
                return (short)-1;
            }
            scratch[(short)(scratchOffset + i)] = base58Value;
        }
        while ((zeroCount < inLength) && (scratch[(short)(scratchOffset + zeroCount)] == 0)) {
            ++zeroCount;
        }
        j = inLength;
        startAt = zeroCount;
        while (startAt < inLength) {
            short remainder = 0;
            short divLoop;
            for (divLoop = startAt ; divLoop < inLength; divLoop++) {
                short digit256 = (short)(scratch[(short)(scratchOffset + divLoop)] & 0xff);
                short tmpDiv = (short)(remainder * 58 + digit256);
                scratch[(short)(scratchOffset + divLoop)] = (byte)(tmpDiv / 256);
                remainder = (short)(tmpDiv % 256);
            }
            if (scratch[(short)(scratchOffset + startAt)] == 0) {
                ++startAt;
            }
            out[(short)(outOffset + --j)] = (byte)remainder;
        }
        while ((j < inLength) && (out[(short)(outOffset + j)] == 0)) {
            j++;
        }
        short resultLength = (short)(inLength - (j - zeroCount));
        Util.arrayCopyNonAtomic(out, (short)(outOffset + j - zeroCount), out, outOffset, resultLength);
        return resultLength;
      }
      catch(Throwable t) {
          return (short)-1;
      }
    }
            
    private static final byte BASE58TABLE[] = {
        (byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,
        (byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,
        (byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0x0,(byte)0x1,(byte)0x2,(byte)0x3,(byte)0x4,(byte)0x5,(byte)0x6,(byte)0x7,(byte)0x8,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,
        (byte)0x9,(byte)0xa,(byte)0xb,(byte)0xc,(byte)0xd,(byte)0xe,(byte)0xf,(byte)0x10,(byte)0xff,(byte)0x11,(byte)0x12,(byte)0x13,(byte)0x14,(byte)0x15,(byte)0xff,(byte)0x16,(byte)0x17,(byte)0x18,(byte)0x19,(byte)0x1a,(byte)0x1b,(byte)0x1c,(byte)0x1d,
        (byte)0x1e,(byte)0x1f,(byte)0x20,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0x21,(byte)0x22,(byte)0x23,(byte)0x24,(byte)0x25,(byte)0x26,(byte)0x27,(byte)0x28,(byte)0x29,(byte)0x2a,(byte)0x2b,(byte)0xff,(byte)0x2c,
        (byte)0x2d,(byte)0x2e,(byte)0x2f,(byte)0x30,(byte)0x31,(byte)0x32,(byte)0x33,(byte)0x34,(byte)0x35,(byte)0x36,(byte)0x37,(byte)0x38,(byte)0x39,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff
    };
    
    private static final byte ALPHABET[] = {
        '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 
        'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's',
        't', 'u', 'v', 'w', 'x', 'y', 'z'
    };
}

