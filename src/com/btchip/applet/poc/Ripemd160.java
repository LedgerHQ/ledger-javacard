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
 * RIPEMD160 implementation using shorts
 * @author BTChip
 *
 */
public class Ripemd160 {
    
    public static void init() {
        scratch = JCSystem.makeTransientByteArray((short)BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
        data = JCSystem.makeTransientShortArray(DATA_SIZE, JCSystem.CLEAR_ON_DESELECT);
    }
    
    private static void set(short offset, short a, short b) {
        data[offset] = a;
        data[(short)(offset + 1)] = b;
    }
    
    private static void copy(short offsetSrc, short offset2) {
        data[offsetSrc] = data[offset2];
        data[(short)(offsetSrc + 1)] = data[(short)(offset2 + 1)];
    }
    
    private static void set(short offset, short value) {
        data[offset] = 0;
        data[(short)(offset + 1)] = value;
    }
    
    private static void xor(short offsetSrc, short offset2) {
        data[offsetSrc] ^= data[offset2];
        data[(short)(offsetSrc + 1)] ^= data[(short)(offset2 + 1)];
    }
    
    private static void or(short offsetSrc, short offset2) {
        data[offsetSrc] |= data[offset2];
        data[(short)(offsetSrc + 1)] |= data[(short)(offset2 + 1)];
    }
    
    private static void and(short offsetSrc, short offset2) {
        data[offsetSrc] &= data[offset2];
        data[(short)(offsetSrc + 1)] &= data[(short)(offset2 + 1)];
    }
    
    private static void neg(short offset) {
        data[offset] = (short)(~data[offset]);
        data[(short)(offset + 1)] = (short)(~data[(short)(offset + 1)]);
    }
    
    private static void add(short offsetSrc, short high, short low) {
        short x = data[(short)(offsetSrc + 1)];        
        short y = low;
        short addLow = (short)(x + y);
        short carry = (short) ((((x & y) | (x & ~y & ~addLow) | (~x & y & ~addLow)) >>> 15) & 1);
        data[offsetSrc] += carry;
        data[(short)(offsetSrc + 1)] = addLow;
        data[offsetSrc] += high;
    }
    
    private static void add(short offsetSrc, short offset2) {
        add(offsetSrc, data[offset2], data[(short)(offset2 + 1)]);
    }
        
    private static void rotate(short offset, short rot) {
        short h,l;
        short  msk;
        short sl_rot, sh_rot;

        //cache
        msk = mask[rot];     
        h = data[offset];
        l = data[(short)(offset + 1)];

        //grab rotated bits, play around cast and sign extension 
        sh_rot = (short) (msk & ((short) (h >>> ((short)(16-rot)))));
        sl_rot = (short) (msk & ((short) (l  >>> ((short)(16-rot)))));

        //rotate
        data[offset] = (short) ((h<<rot) | sl_rot);
        data[(short)(offset + 1)]  = (short) ((l<<rot) | sh_rot);        
      }            
            
    private static short copy(short offset, byte[] target, short targetOffset) {
        short high = data[offset];
        short low = data[(short)(offset + 1)];
        target[targetOffset++] = (byte)low;
        target[targetOffset++] = (byte)(low >>> 8);
        target[targetOffset++] = (byte)high;
        target[targetOffset++] = (byte)(high >>> 8);
        return targetOffset;
    }
        
    public static void hash32(byte[] buffer, short offset, byte[] target, short targetOffset)
    {
      byte i;
      set(Harray, (short)0x6745, (short)0x2301);
      set((short)(Harray + 2), (short)0xEFCD, (short)0xAB89);
      set((short)(Harray + 4), (short)0x98BA, (short)0xDCFE);
      set((short)(Harray + 6), (short)0x1032, (short)0x5476);
      set((short)(Harray + 8), (short)0xC3D2, (short)0xE1F0);
      Util.arrayCopyNonAtomic(buffer, offset, scratch, (short)0, (short)32);
      scratch[32] = (byte)0x80;
      scratch[64 - 7] = (byte)0x01;
      transform(scratch, (short)0);
      for (i=0; i<5; i++) {
          targetOffset = copy((short)(Harray + 2 * i), target, targetOffset);
      }
    }    

    protected static void transform(byte[] in, short offset)
    {      
      // TODO : fully inline for speedup
      byte i;
      // encode 64 bytes from input block into an array of 16 unsigned integers
      for (i = 0; i < 16; i++) {
        short low = (short)((in[offset++] & 0xff) | ((in[offset++] & 0xff) << 8));
        short high = (short)((in[offset++] & 0xff) | ((in[offset++] & 0xff) << 8));
        set((short)(Xarray + 2 * i), high, low);
      }
      
      copy(A, Harray);
      copy(Ap, Harray);
      copy(B, (short)(Harray + 2));
      copy(Bp, (short)(Harray + 2));
      copy(C, (short)(Harray + 4));
      copy(Cp, (short)(Harray + 4));
      copy(D, (short)(Harray + 6));
      copy(Dp, (short)(Harray + 6));
      copy(E, (short)(Harray + 8));
      copy(Ep, (short)(Harray + 8));
                  
      for (i = 0; i < 80; i++) // rounds 0...15
        {
          set(s, S[i]);          
          switch(i >> 4) {
              case 0:
                  //T = A + (B ^ C ^ D) + X[i];
                  copy(T, B);
                  xor(T, C);
                  xor(T, D);
                  add(T, A);
                  add(T, (short)(Xarray + 2 * i));                  
                  break;
              case 1:
                  copy(T, B);
                  and(T, C);
                  copy(tmp, B);
                  neg(tmp);
                  and(tmp, D);
                  or(T, tmp);
                  add(T, A);
                  add(T, (short)(Xarray + 2 * R[i]));
                  add(T, (short)0x5A82, (short)0x7999);
                  //T = A + ((B & C) | (~B & D)) + X[R[i]] + 0x5A827999;
                  break;
              case 2:
                  copy(T, C);
                  neg(T);
                  or(T, B);
                  xor(T, D);
                  add(T, A);
                  add(T, (short)(Xarray + 2 * R[i]));
                  add(T, (short)0x6ED9, (short)0xEBA1);
                  //T = A + ((B | ~C) ^ D) + X[R[i]] + 0x6ED9EBA1;
                  break;
              case 3:
                  copy(T, B);
                  and(T, D);
                  copy(tmp, D);
                  neg(tmp);
                  and(tmp, C);
                  or(T, tmp);
                  add(T, A);
                  add(T, (short)(Xarray + 2 * R[i]));
                  add(T, (short)0x8F1B, (short)0xBCDC);
                  //T = A + ((B & D) | (C & ~D)) + X[R[i]] + 0x8F1BBCDC;
                  break;
              case 4:
                  copy(T, D);
                  neg(T);
                  or(T, C);
                  xor(T, B);
                  add(T, A);
                  add(T, (short)(Xarray + 2 * R[i]));
                  add(T, (short)0xA953, (short)0xFD4E);
                  //T = A + (B ^ (C | ~D)) + X[R[i]] + 0xA953FD4E;
                  break;
          }
          copy(A, E);
          copy(E, D);
          copy(D, C);
          rotate(D, (short)10);
          copy(C, B);
          copy(B, T);
          rotate(B, data[(short)(s + 1)]);
          add(B, A);
          /*
          A = E;
          E = D;
          D = C << 10 | C >>> 22;
          C = B;
          B = (T << s | T >>> (32 - s)) + A;
          */
          set(s, Sp[i]);
          switch(i >> 4) {
              case 0:
                  copy(T, Dp);
                  neg(T);
                  or(T, Cp);
                  xor(T, Bp);
                  add(T, Ap);
                  add(T, (short)(Xarray + 2 * Rp[i]));
                  add(T, (short)0x50A2, (short)0x8BE6);
                  //T = Ap + (Bp ^ (Cp | ~Dp)) + X[Rp[i]] + 0x50A28BE6;
                  break;
              case 1:
                  copy(T, Bp);
                  and(T, Dp);
                  copy(tmp, Dp);
                  neg(tmp);
                  and(tmp, Cp);
                  or(T, tmp);
                  add(T, Ap);
                  add(T, (short)(Xarray + 2 * Rp[i]));
                  add(T, (short)0x5C4D, (short)0xD124);
                  //T = Ap + ((Bp & Dp) | (Cp & ~Dp)) + X[Rp[i]] + 0x5C4DD124;
                  break;
              case 2:
                  copy(T, Cp);
                  neg(T);
                  or(T, Bp);
                  xor(T, Dp);
                  add(T, Ap);
                  add(T, (short)(Xarray + 2 * Rp[i]));
                  add(T, (short)0x6D70, (short)0x3EF3);
                  //T = Ap + ((Bp | ~Cp) ^ Dp) + X[Rp[i]] + 0x6D703EF3;
                  break;
              case 3:
                  copy(T, Bp);
                  and(T, Cp);
                  copy(tmp, Bp);
                  neg(tmp);
                  and(tmp, Dp);
                  or(T, tmp);
                  add(T, Ap);
                  add(T, (short)(Xarray + 2 * Rp[i]));
                  add(T, (short)0x7A6D, (short)0x76E9);
                  //T = Ap + ((Bp & Cp) | (~Bp & Dp)) + X[Rp[i]] + 0x7A6D76E9;
                  break;
              case 4:
                  copy(T, Bp);
                  xor(T, Cp);
                  xor(T, Dp);
                  add(T, Ap);
                  add(T, (short)(Xarray + 2 * Rp[i]));
                  //T = Ap + (Bp ^ Cp ^ Dp) + X[Rp[i]];
                  break;                                    
          }          
          copy(Ap, Ep);
          copy(Ep, Dp);
          copy(Dp, Cp);
          rotate(Dp, (short)10);
          copy(Cp, Bp);
          copy(Bp, T);
          rotate(Bp, data[(short)(s + 1)]);
          add(Bp, Ap);
          /*
          Ap = Ep;
          Ep = Dp;
          Dp = Cp << 10 | Cp >>> 22;
          Cp = Bp;
          Bp = (T << s | T >>> (32 - s)) + Ap;
          */
      }
      copy(T, (short)(Harray + 2));
      add(T, C);
      add(T, Dp);
      copy((short)(Harray + 2), (short)(Harray + 4));
      add((short)(Harray + 2), D);
      add((short)(Harray + 2), Ep);
      copy((short)(Harray + 4), (short)(Harray + 6));
      add((short)(Harray + 4), E);
      add((short)(Harray + 4), Ap);
      copy((short)(Harray + 6), (short)(Harray + 8));
      add((short)(Harray + 6), A);
      add((short)(Harray + 6), Bp);
      copy((short)(Harray + 8), Harray);
      add((short)(Harray + 8), B);
      add((short)(Harray + 8), Cp);
      copy(Harray, T);
      /*
      T = h[1] + C + Dp;
      h[1] = h[2] + D + Ep;
      h[2] = h[3] + E + Ap;
      h[3] = h[4] + A + Bp;
      h[4] = h[0] + B + Cp;
      h[0] = T;
      */
    } 
    
    
    // selection of message word
    private static final short[] R = {
        0,  1,  2,  3,  4,  5,  6,  7,  8, 9, 10, 11, 12, 13, 14, 15,
        7,  4, 13,  1, 10,  6, 15,  3, 12, 0,  9,  5,  2, 14, 11,  8,
        3, 10, 14,  4,  9, 15,  8,  1,  2, 7,  0,  6, 13, 11,  5, 12,
        1,  9, 11, 10,  0,  8, 12,  4, 13, 3,  7, 15, 14,  5,  6,  2,
        4,  0,  5,  9,  7, 12,  2, 10, 14, 1,  3,  8, 11,  6, 15, 13 };

    private static final short[] Rp = {
         5, 14,  7, 0, 9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
         6, 11,  3, 7, 0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
        15,  5,  1, 3, 7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
         8,  6,  4, 1, 3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
        12, 15, 10, 4, 1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11 };

    // amount for rotate left (rol)
    private static final short[] S = {
        11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
         7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
        11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
        11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
         9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6 };

    private static final short[] Sp = {
         8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
         9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
         9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
        15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
         8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11 };
    
    private static final short Harray = (short)0;
    private static final short Xarray = (short)(Harray + 5 * 2);
    private static final short A = (short)(Xarray + 16 * 2);
    private static final short B = (short)(A + 2);
    private static final short C = (short)(B + 2);
    private static final short D = (short)(C + 2);
    private static final short E = (short)(D + 2);
    private static final short Ap = (short)(E + 2);
    private static final short Bp = (short)(Ap + 2);
    private static final short Cp = (short)(Bp + 2);
    private static final short Dp = (short)(Cp + 2);
    private static final short Ep = (short)(Dp + 2);
    private static final short T = (short)(Ep + 2);
    private static final short s = (short)(T + 2);
    private static final short tmp = (short)(s + 2);
    private static final short DATA_SIZE = (short)(tmp + 2);
    
    private static short[] data;
    
    private static byte[] scratch;
    
    private static final short[] mask = {
        (short)0x0000, (short)0x0001, (short)0x0003, (short)0x0007,  
        (short)0x000F, (short)0x001F, (short)0x003F, (short)0x007F,  
        (short)0x00FF, (short)0x01FF, (short)0x03FF, (short)0x07FF,  
        (short)0x0FFF, (short)0x1FFF, (short)0x3FFF, (short)0x7FFF,  
    };          
        
    private static final byte BLOCK_SIZE = 64;
        
}
