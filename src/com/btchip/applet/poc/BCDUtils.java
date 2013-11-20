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

/**
 * Convert a bitcoin amount to a displyable representation for the second factor validation
 * @author BTChip
 *
 */
public class BCDUtils {
    
    public static void init() {
        scratch = JCSystem.makeTransientShortArray((short)(8 * 8 / 3), JCSystem.CLEAR_ON_DESELECT);
    }
    
    private static void doubleDabble(byte[] source, short sourceOffset) {
        for (byte i=0; i<(short)scratch.length; i++) {
            scratch[i] = (short)0;
        }
        byte nscratch = (byte)(8 * 8 / 3);
        byte smin = (byte)(nscratch - 2);
        for (byte i=0; i<8; i++) {
            for (byte j=0; j<8; j++) {
                short shifted_in = (((source[(short)(sourceOffset + i)] & 0xff) & ((short)(1 << (7 - j)))) != 0) ? (short)1 : (short)0;
                for (byte k=smin; k<nscratch; k++) {
                    scratch[k] += ((scratch[k] >= 5) ? 3 : 0);
                }
                if (scratch[smin] >= 8) {
                    smin -= 1;
                }
                for (byte k=smin; k < nscratch - 1; k++) {
                    scratch[k] <<= 1;
                    scratch[k] &= 0x0f;
                    scratch[k] |= ((scratch[k + 1] >= 8) ? 1 : 0);
                }
                scratch[nscratch - 1] <<= 1;
                scratch[nscratch - 1] &= 0x0f;
                scratch[nscratch - 1] |= (shifted_in == 1 ? 1 : 0);
            }
        }
    }
    
    public static short hexAmountToDisplayable(byte[] source, short sourceOffset, byte[] target, short targetOffset) {
        short start = targetOffset;
        doubleDabble(source, sourceOffset);        
        short offset = (short)0;
        boolean nonZero = false;
        for (byte i=0; i<13; i++) {
            if (!nonZero && (scratch[offset] == 0)) {
                offset++;
            }
            else {
                nonZero = true;
                target[targetOffset++] = (byte)(scratch[offset++] + '0');
            }            
        }
        if (targetOffset == start) {
            target[targetOffset++] = '0';
        }
        target[targetOffset++] = '.';
        short workOffset = offset;
        for (byte i=0; i<8; i++) {
            boolean allZero = true;
            for (byte j=i; j<8; j++) {
                if (scratch[(short)(workOffset + j)] != 0) {
                    allZero = false;
                    break;
                }
            }
            if (allZero) {
                break;
            }
            target[targetOffset++] = (byte)(scratch[offset++] + '0');
        }
        if ((short)(targetOffset - start) == 2) {
            targetOffset--; // only 0
        }
        return targetOffset;
    }
        
    private static short scratch[];

}
