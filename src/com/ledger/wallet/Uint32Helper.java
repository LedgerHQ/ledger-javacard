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
 * Basic operations on 32 bits unsigned integers
 * @author BTChip
 *
 */
public class Uint32Helper {
    
    public static void clear(byte[] buffer, short offset) {
        Util.arrayFillNonAtomic(buffer, offset, (short)4, (byte)0x00);
    }
    
    public static void swap(byte[] target, short targetOffset, byte[] a, short aOffset) {
        GenericBEHelper.swap((byte)4, target, targetOffset, a, aOffset);
    }
    
    public static void setByte(byte[] buffer, short offset, byte value) {
        clear(buffer, offset);
        buffer[(short)(offset + 3)] = value;
    }

    public static void setShort(byte[] buffer, short offset, byte high, byte low) {
        clear(buffer, offset);
        buffer[(short)(offset + 2)] = high;
        buffer[(short)(offset + 3)] = low;
    }

    public static void setInt(byte[] buffer, short offset, byte hh, byte hl, byte lh, byte ll) {
        buffer[offset] = hh;
        buffer[(short)(offset + 1)] = hl;
        buffer[(short)(offset + 2)] = lh;
        buffer[(short)(offset + 3)] = ll;
    }
    
    public static boolean isZero(byte[] buffer, short offset) {
        return GenericBEHelper.isZero((byte)4, buffer, offset);
    }
    
    public static void increase(byte[] buffer, short offset) {
        GenericBEHelper.add((byte)4, buffer, offset, buffer, offset, ONE, (short)0);
    }
    
    public static void decrease(byte[] buffer, short offset) {
        GenericBEHelper.sub((byte)4, buffer, offset, buffer, offset, ONE, (short)0);
    }
    
    public static void sub(byte[] a, short aOffset, byte[] b, short bOffset) {
        GenericBEHelper.sub((byte)4, a, aOffset, a, aOffset, b, bOffset);
    }
    
    public static short getU8(byte[] buffer, short offset) {
        if ((buffer[offset] != 0) || (buffer[(short)(offset + 1)] != 0) || (buffer[(short)(offset + 2)] != 0)) {
            return (short)0xff;
        }
        return (short)(buffer[(short)(offset + 3)] & 0xff);
    }
        
    private static final byte ONE[] = { (byte)0, (byte)0, (byte)0, (byte)1 };
    
}
