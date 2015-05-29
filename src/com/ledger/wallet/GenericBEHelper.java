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

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/**
 * Basic operations on large unsigned integers
 * @author BTChip
 *
 */
public class GenericBEHelper {
            
    public static boolean isZero(byte size, byte[] buffer, short offset) {
        for (byte i=0; i<size; i++) {
            if (buffer[(short)(offset + i)] != 0) {
                return false;
            }
        }
        return true;        
    }
    
    public static void swap(byte size, byte[] target, short targetOffset, byte[] a, short aOffset) {
        for (byte i=0; i<size; i++) {
            target[(short)(targetOffset + size - 1 - i)] = a[(short)(aOffset + i)];
        }
    }
        
    public static void add(byte size, byte[] target, short targetOffset, byte[] a, short aOffset, byte[] b, short bOffset) {
        boolean carry = false;
        for (byte i=0; i<size; i++) {
            short val = (short)((short)(a[(short)(aOffset + size - 1 - i)] & 0xff) + (short)(b[(short)(bOffset + size - 1 - i)] & 0xff));
            if (carry) {
                val++;
            }
            carry = (val > 255);
            target[(short)(targetOffset + size - 1 - i)] = (byte)val;
        }
        if (carry) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }
    
    public static void sub(byte size, byte[] target, short targetOffset, byte[] a, short aOffset, byte[] b, short bOffset) {
        boolean borrow = false;
        for (byte i=0; i<size; i++) {
            short tmpA = (short)(a[(short)(aOffset + size - 1 - i)] & 0xff);
            short tmpB = (short)(b[(short)(bOffset + size - 1 - i)] & 0xff);
            if (borrow) {
                if (tmpA <= tmpB) {
                    tmpA += (255 + 1) - 1;
                }
                else {
                    borrow = false;
                    tmpA--;
                }
            }
            if (tmpA < tmpB) {
                borrow = true;
                tmpA += 255 + 1;
            }
            target[(short)(targetOffset + size - 1 - i)] = (byte)(tmpA - tmpB);
        }
        if (borrow) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }

}
