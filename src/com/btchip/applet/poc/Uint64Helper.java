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
 * Basic operations on 64 bits unsigned integers
 * @author BTChip
 *
 */
public class Uint64Helper {

    public static void clear(byte[] buffer, short offset) {
        Util.arrayFillNonAtomic(buffer, offset, (short)8, (byte)0x00);
    }
    
    public static void add(byte[] a, short aOffset, byte[] b, short bOffset) {
        GenericBEHelper.add((byte)8, a, aOffset, a, aOffset, b, bOffset);
    }

    public static void add(byte[] target, short targetOffset, byte[] a, short aOffset, byte[] b, short bOffset) {
        GenericBEHelper.add((byte)8, target, targetOffset, a, aOffset, b, bOffset);
    }
    
    public static void sub(byte[] target, short targetOffset, byte[] a, short aOffset, byte[] b, short bOffset) {
        GenericBEHelper.sub((byte)8, target, targetOffset, a, aOffset, b, bOffset);
    }
    
    public static void swap(byte[] target, short targetOffset, byte[] a, short aOffset) {
        GenericBEHelper.swap((byte)8, target, targetOffset, a, aOffset);
    }
    
    public static boolean isZero(byte[] a, short aOffset) {
        return GenericBEHelper.isZero((byte)8, a, aOffset);
    }
}
