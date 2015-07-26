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

/* This file is automatically processed from the .javap version and only included for convenience. Please refer to the .javap file
   for more readable code */

package com.ledger.wallet;
import javacard.framework.JCSystem;
public class SHA512 {
  public SHA512() {
    working = JCSystem.makeTransientShortArray((short)(2 + 8*4
                                                         ),
                                                 JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
    blk = JCSystem.makeTransientShortArray((short)(64),
                                                 JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
    init();
  }
  public void uninit() {
    working = null;
    blk = null;
  }
  public byte getAlgorithm() {
    return 0x61;
  }
  public byte getLength() {
    return 64;
  }
  public void reset() {
    init();
  }
  public void update(byte[] inBuff, short inOffset, short inLength) {
    short blen = working [BLEN];
    short cnt = working[CNT];
    if ((short)(blen + inLength) >= BLOCK_SIZE) {
      short r = (short)(BLOCK_SIZE - blen);
      load(inBuff, inOffset, r);
      hashBlock();
      inOffset += r;
      inLength -= r;
      working[BLEN] = 0;
      cnt++;
    }
    while (inLength >= BLOCK_SIZE) {
      load(inBuff, inOffset, BLOCK_SIZE);
      hashBlock();
      cnt++;
      inOffset += BLOCK_SIZE;
      inLength -= BLOCK_SIZE;
    }
    load(inBuff, inOffset, inLength);
    working[BLEN] = inLength;
    working[CNT] = cnt;
  }
  public short doFinal(byte[] inBuff, short inOffset, short inLength,
                       byte[] outBuff, short outOffset) {
    update(inBuff,inOffset,inLength);
    zeroFillBlk();
    short cnt = working[CNT];
    short blen = working[BLEN];
    short bitsLen_H, bitsLen_L;
    bitsLen_H = (short)(cnt>>6);
    bitsLen_L = (short)((cnt<<10) + (blen<<3));
    short off = (short)(blen>>1);
    if ((blen &1) == 0) {
      blk[off] = (short)0x8000;
    } else {
      blk[off] |= 0x0080;
    }
    blen++;
    if ((short)(128-blen) < 8) {
      hashBlock();
      zeroFillBlk();
    }
    blk[(short)62] = bitsLen_H;
    blk[(short)63] = bitsLen_L;
    hashBlock();
    for (short i = 0; i<32; i++) {
      outBuff[(short)(outOffset+2*i )] = (byte)(working[(short)(H0+i)] >> 8);
      outBuff[(short)(outOffset+2*i+1)] = (byte)(working[(short)(H0+i)] & 0xFF);
    }
    init();
    return getLength();
  }
  protected void init() {
    short len = (short)working.length;
    while(len != 0) {
      len--;
      working[len] = 0;
    }
    for (short i = 0; i < 32; i++) {
      working[(short)(H0+i)] = HINIT[i];
    }
  }
  private void load(byte[] inBuff, short inOffset, short inLength) {
    short blen = working[BLEN];
    short off = (short)(blen>>1);
    if (inLength == 0) return;
    if ((blen&1) == 1) {
      blk[off] |= inBuff[inOffset] & 0xff;
      inOffset ++;
      inLength --;
      off++;
    }
    while (inLength > 1) {
      blk[off] = (short)((inBuff[inOffset] <<8) | (inBuff[(short)(inOffset+1)] & 0xff));
      inOffset += 2;
      inLength -= 2;
      off ++;
    }
    if (inLength > 0) {
      blk[off] = (short)(inBuff[inOffset] <<8);
    }
  }
  void zeroFillBlk() {
    short blen = working[BLEN];
    if ((blen&1) == 1) {
      blen ++;
    }
    short off = (short)(blen>>1);
    while (off<64) {
      blk[off] = 0;
      off++;
    }
  }
  static private final short primeSqrt[] = {
    (short)0x428a, (short)0x2f98, (short)0xd728, (short)0xae22,
    (short)0x7137, (short)0x4491, (short)0x23ef, (short)0x65cd,
    (short)0xb5c0, (short)0xfbcf, (short)0xec4d, (short)0x3b2f,
    (short)0xe9b5, (short)0xdba5, (short)0x8189, (short)0xdbbc,
    (short)0x3956, (short)0xc25b, (short)0xf348, (short)0xb538,
    (short)0x59f1, (short)0x11f1, (short)0xb605, (short)0xd019,
    (short)0x923f, (short)0x82a4, (short)0xaf19, (short)0x4f9b,
    (short)0xab1c, (short)0x5ed5, (short)0xda6d, (short)0x8118,
    (short)0xd807, (short)0xaa98, (short)0xa303, (short)0x0242,
    (short)0x1283, (short)0x5b01, (short)0x4570, (short)0x6fbe,
    (short)0x2431, (short)0x85be, (short)0x4ee4, (short)0xb28c,
    (short)0x550c, (short)0x7dc3, (short)0xd5ff, (short)0xb4e2,
    (short)0x72be, (short)0x5d74, (short)0xf27b, (short)0x896f,
    (short)0x80de, (short)0xb1fe, (short)0x3b16, (short)0x96b1,
    (short)0x9bdc, (short)0x06a7, (short)0x25c7, (short)0x1235,
    (short)0xc19b, (short)0xf174, (short)0xcf69, (short)0x2694,
    (short)0xe49b, (short)0x69c1, (short)0x9ef1, (short)0x4ad2,
    (short)0xefbe, (short)0x4786, (short)0x384f, (short)0x25e3,
    (short)0x0fc1, (short)0x9dc6, (short)0x8b8c, (short)0xd5b5,
    (short)0x240c, (short)0xa1cc, (short)0x77ac, (short)0x9c65,
    (short)0x2de9, (short)0x2c6f, (short)0x592b, (short)0x0275,
    (short)0x4a74, (short)0x84aa, (short)0x6ea6, (short)0xe483,
    (short)0x5cb0, (short)0xa9dc, (short)0xbd41, (short)0xfbd4,
    (short)0x76f9, (short)0x88da, (short)0x8311, (short)0x53b5,
    (short)0x983e, (short)0x5152, (short)0xee66, (short)0xdfab,
    (short)0xa831, (short)0xc66d, (short)0x2db4, (short)0x3210,
    (short)0xb003, (short)0x27c8, (short)0x98fb, (short)0x213f,
    (short)0xbf59, (short)0x7fc7, (short)0xbeef, (short)0x0ee4,
    (short)0xc6e0, (short)0x0bf3, (short)0x3da8, (short)0x8fc2,
    (short)0xd5a7, (short)0x9147, (short)0x930a, (short)0xa725,
    (short)0x06ca, (short)0x6351, (short)0xe003, (short)0x826f,
    (short)0x1429, (short)0x2967, (short)0x0a0e, (short)0x6e70,
    (short)0x27b7, (short)0x0a85, (short)0x46d2, (short)0x2ffc,
    (short)0x2e1b, (short)0x2138, (short)0x5c26, (short)0xc926,
    (short)0x4d2c, (short)0x6dfc, (short)0x5ac4, (short)0x2aed,
    (short)0x5338, (short)0x0d13, (short)0x9d95, (short)0xb3df,
    (short)0x650a, (short)0x7354, (short)0x8baf, (short)0x63de,
    (short)0x766a, (short)0x0abb, (short)0x3c77, (short)0xb2a8,
    (short)0x81c2, (short)0xc92e, (short)0x47ed, (short)0xaee6,
    (short)0x9272, (short)0x2c85, (short)0x1482, (short)0x353b,
    (short)0xa2bf, (short)0xe8a1, (short)0x4cf1, (short)0x0364,
    (short)0xa81a, (short)0x664b, (short)0xbc42, (short)0x3001,
    (short)0xc24b, (short)0x8b70, (short)0xd0f8, (short)0x9791,
    (short)0xc76c, (short)0x51a3, (short)0x0654, (short)0xbe30,
    (short)0xd192, (short)0xe819, (short)0xd6ef, (short)0x5218,
    (short)0xd699, (short)0x0624, (short)0x5565, (short)0xa910,
    (short)0xf40e, (short)0x3585, (short)0x5771, (short)0x202a,
    (short)0x106a, (short)0xa070, (short)0x32bb, (short)0xd1b8,
    (short)0x19a4, (short)0xc116, (short)0xb8d2, (short)0xd0c8,
    (short)0x1e37, (short)0x6c08, (short)0x5141, (short)0xab53,
    (short)0x2748, (short)0x774c, (short)0xdf8e, (short)0xeb99,
    (short)0x34b0, (short)0xbcb5, (short)0xe19b, (short)0x48a8,
    (short)0x391c, (short)0x0cb3, (short)0xc5c9, (short)0x5a63,
    (short)0x4ed8, (short)0xaa4a, (short)0xe341, (short)0x8acb,
    (short)0x5b9c, (short)0xca4f, (short)0x7763, (short)0xe373,
    (short)0x682e, (short)0x6ff3, (short)0xd6b2, (short)0xb8a3,
    (short)0x748f, (short)0x82ee, (short)0x5def, (short)0xb2fc,
    (short)0x78a5, (short)0x636f, (short)0x4317, (short)0x2f60,
    (short)0x84c8, (short)0x7814, (short)0xa1f0, (short)0xab72,
    (short)0x8cc7, (short)0x0208, (short)0x1a64, (short)0x39ec,
    (short)0x90be, (short)0xfffa, (short)0x2363, (short)0x1e28,
    (short)0xa450, (short)0x6ceb, (short)0xde82, (short)0xbde9,
    (short)0xbef9, (short)0xa3f7, (short)0xb2c6, (short)0x7915,
    (short)0xc671, (short)0x78f2, (short)0xe372, (short)0x532b,
    (short)0xca27, (short)0x3ece, (short)0xea26, (short)0x619c,
    (short)0xd186, (short)0xb8c7, (short)0x21c0, (short)0xc207,
    (short)0xeada, (short)0x7dd6, (short)0xcde0, (short)0xeb1e,
    (short)0xf57d, (short)0x4f7f, (short)0xee6e, (short)0xd178,
    (short)0x06f0, (short)0x67aa, (short)0x7217, (short)0x6fba,
    (short)0x0a63, (short)0x7dc5, (short)0xa2c8, (short)0x98a6,
    (short)0x113f, (short)0x9804, (short)0xbef9, (short)0x0dae,
    (short)0x1b71, (short)0x0b35, (short)0x131c, (short)0x471b,
    (short)0x28db, (short)0x77f5, (short)0x2304, (short)0x7d84,
    (short)0x32ca, (short)0xab7b, (short)0x40c7, (short)0x2493,
    (short)0x3c9e, (short)0xbe0a, (short)0x15c9, (short)0xbebc,
    (short)0x431d, (short)0x67c4, (short)0x9c10, (short)0x0d4c,
    (short)0x4cc5, (short)0xd4be, (short)0xcb3e, (short)0x42b6,
    (short)0x597f, (short)0x299c, (short)0xfc65, (short)0x7e2a,
    (short)0x5fcb, (short)0x6fab, (short)0x3ad6, (short)0xfaec,
    (short)0x6c44, (short)0x198c, (short)0x4a47, (short)0x5817
  };
  static private final short[] HINIT = {
    (short)0x6a09, (short)0xe667, (short)0xf3bc, (short)0xc908,
    (short)0xbb67, (short)0xae85, (short)0x84ca, (short)0xa73b,
    (short)0x3c6e, (short)0xf372, (short)0xfe94, (short)0xf82b,
    (short)0xa54f, (short)0xf53a, (short)0x5f1d, (short)0x36f1,
    (short)0x510e, (short)0x527f, (short)0xade6, (short)0x82d1,
    (short)0x9b05, (short)0x688c, (short)0x2b3e, (short)0x6c1f,
    (short)0x1f83, (short)0xd9ab, (short)0xfb41, (short)0xbd6b,
    (short)0x5be0, (short)0xcd19, (short)0x137e, (short)0x2179
  } ;
  private static short[] working;
  private static short[] blk;
  static private final short BLOCK_SIZE = 128;
  static private final short CNT = 0;
  static private final short BLEN = 1;
  static private final short H0 = 2;
  static private final short H1 = 6;
  static private final short H2 = 10;
  static private final short H3 = 14;
  static private final short H4 = 18;
  static private final short H5 = 22;
  static private final short H6 = 26;
  static private final short H7 = 30;
  static private final short BLK = 34;
  protected static void hashBlock() {
    short AN1, AN2, AN3, AN4; short BN1, BN2, BN3, BN4; short CN1, CN2, CN3, CN4; short DN1, DN2, DN3, DN4; short EN1, EN2, EN3, EN4; short FN1, FN2, FN3, FN4; short GN1, GN2, GN3, GN4; short HN1, HN2, HN3, HN4;
    short T1N1, T1N2, T1N3, T1N4; short T2N1, T2N2, T2N3, T2N4; short T3N1, T3N2, T3N3, T3N4; short T4N1, T4N2, T4N3, T4N4; short T5N1, T5N2, T5N3, T5N4; short RN1, RN2, RN3, RN4;
    short adda = (short)0, addb = (short)0;
    short addc, addxl, addxh;
    byte addk;
    short jProc;
    short tmpOff;
    AN1 = working[H0]; AN2 = working[(short)(H0 + 1)]; AN3 = working[(short)(H0 + 2)]; AN4 = working[(short)(H0 + 3)];;
    BN1 = working[H1]; BN2 = working[(short)(H1 + 1)]; BN3 = working[(short)(H1 + 2)]; BN4 = working[(short)(H1 + 3)];;
    CN1 = working[H2]; CN2 = working[(short)(H2 + 1)]; CN3 = working[(short)(H2 + 2)]; CN4 = working[(short)(H2 + 3)];;
    DN1 = working[H3]; DN2 = working[(short)(H3 + 1)]; DN3 = working[(short)(H3 + 2)]; DN4 = working[(short)(H3 + 3)];;
    EN1 = working[H4]; EN2 = working[(short)(H4 + 1)]; EN3 = working[(short)(H4 + 2)]; EN4 = working[(short)(H4 + 3)];;
    FN1 = working[H5]; FN2 = working[(short)(H5 + 1)]; FN3 = working[(short)(H5 + 2)]; FN4 = working[(short)(H5 + 3)];;
    GN1 = working[H6]; GN2 = working[(short)(H6 + 1)]; GN3 = working[(short)(H6 + 2)]; GN4 = working[(short)(H6 + 3)];;
    HN1 = working[H7]; HN2 = working[(short)(H7 + 1)]; HN3 = working[(short)(H7 + 2)]; HN4 = working[(short)(H7 + 3)];;
    for (byte j = 0; j<80; j++) {
      if (j >= 16) {
        tmpOff = (short)(4*(short)((j-2) & 0xF)); T2N1 = blk[tmpOff]; T2N2 = blk[(short)(tmpOff + 1)]; T2N3 = blk[(short)(tmpOff + 2)]; T2N4 = blk[(short)(tmpOff + 3)];;
        T3N1 = (short) ( (T2N4>>>3) & (short)8191 | ((short)(T2N3<<(13))) ); T3N2 = (short) ( (T2N1>>>3) & (short)8191 | ((short)(T2N4<<(13))) ); T3N3 = (short) ( (T2N2>>>3) & (short)8191 | ((short)(T2N1<<(13))) ); T3N4 = (short) ( (T2N3>>>3) & (short)8191 | ((short)(T2N2<<(13))) );; T4N1 = (short) ( (T2N2>>>13) & (short)7 | ((short)(T2N1<<(3))) ); T4N2 = (short) ( (T2N3>>>13) & (short)7 | ((short)(T2N2<<(3))) ); T4N3 = (short) ( (T2N4>>>13) & (short)7 | ((short)(T2N3<<(3))) ); T4N4 = (short) ( (T2N1>>>13) & (short)7 | ((short)(T2N4<<(3))) );; T5N1 = (short) ((T2N1>>>6) & (short)1023); T5N2 = (short) ( (T2N2>>>6) & (short)1023 | ((short)(T2N1<<(10))) ); T5N3 = (short) ( (T2N3>>>6) & (short)1023 | ((short)(T2N2<<(10))) ); T5N4 = (short) ( (T2N4>>>6) & (short)1023 | ((short)(T2N3<<(10))) );; T2N1 = (short)(T3N1 ^ T4N1 ^ T5N1); T2N2 = (short)(T3N2 ^ T4N2 ^ T5N2); T2N3 = (short)(T3N3 ^ T4N3 ^ T5N3); T2N4 = (short)(T3N4 ^ T4N4 ^ T5N4);;
        tmpOff = (short)(4*(short)((j-7) & 0xF)); addb = blk[(short)(tmpOff + 3)]; addxl = (short)((T2N4&0xFF) + (addb&0xFF)); addxh = (short)(((T2N4>>>8)&0xFF) + ((addb>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T2N4 = (short)((addxh<<8) | (addxl&0xFF)); addb = blk[(short)(tmpOff + 2)]; addxl = (short)((T2N3&0xFF) + (addb&0xFF) + addc); addxh = (short)(((T2N3>>>8)&0xFF) + ((addb>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T2N3 = (short)((addxh<<8) | (addxl&0xFF)); addb = blk[(short)(tmpOff + 1)]; addxl = (short)((T2N2&0xFF) + (addb&0xFF) + addc); addxh = (short)(((T2N2>>>8)&0xFF) + ((addb>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T2N2 = (short)((addxh<<8) | (addxl&0xFF)); addb = blk[tmpOff]; addxl = (short)((T2N1&0xFF) + (addb&0xFF) + addc); addxh = (short)(((T2N1>>>8)&0xFF) + ((addb>>>8)&0xFF) + (short)(addxl>>>8)); T2N1 = (short)((addxh<<8) | (addxl&0xFF));;
        tmpOff = (short)(4*(short)((j-15) & 0xF)); T1N1 = blk[tmpOff]; T1N2 = blk[(short)(tmpOff + 1)]; T1N3 = blk[(short)(tmpOff + 2)]; T1N4 = blk[(short)(tmpOff + 3)];;
        T3N1 = (short) ( (T1N1>>>1) & (short)32767 | ((short)(T1N4<<(15))) ); T3N2 = (short) ( (T1N2>>>1) & (short)32767 | ((short)(T1N1<<(15))) ); T3N3 = (short) ( (T1N3>>>1) & (short)32767 | ((short)(T1N2<<(15))) ); T3N4 = (short) ( (T1N4>>>1) & (short)32767 | ((short)(T1N3<<(15))) );; T4N1 = (short) ( (T1N1>>>8) & (short)255 | ((short)(T1N4<<(8))) ); T4N2 = (short) ( (T1N2>>>8) & (short)255 | ((short)(T1N1<<(8))) ); T4N3 = (short) ( (T1N3>>>8) & (short)255 | ((short)(T1N2<<(8))) ); T4N4 = (short) ( (T1N4>>>8) & (short)255 | ((short)(T1N3<<(8))) );; T5N1 = (short) ((T1N1>>>7) & (short)511); T5N2 = (short) ( (T1N2>>>7) & (short)511 | ((short)(T1N1<<(9))) ); T5N3 = (short) ( (T1N3>>>7) & (short)511 | ((short)(T1N2<<(9))) ); T5N4 = (short) ( (T1N4>>>7) & (short)511 | ((short)(T1N3<<(9))) );; T1N1 = (short)(T3N1 ^ T4N1 ^ T5N1); T1N2 = (short)(T3N2 ^ T4N2 ^ T5N2); T1N3 = (short)(T3N3 ^ T4N3 ^ T5N3); T1N4 = (short)(T3N4 ^ T4N4 ^ T5N4);;
        addxl = (short)((T2N4&0xFF) + (T1N4&0xFF)); addxh = (short)(((T2N4>>>8)&0xFF) + ((T1N4>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T2N4 = (short)((addxh<<8) | (addxl&0xFF)); addxl = (short)((T2N3&0xFF) + (T1N3&0xFF) + addc); addxh = (short)(((T2N3>>>8)&0xFF) + ((T1N3>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T2N3 = (short)((addxh<<8) | (addxl&0xFF)); addxl = (short)((T2N2&0xFF) + (T1N2&0xFF) + addc); addxh = (short)(((T2N2>>>8)&0xFF) + ((T1N2>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T2N2 = (short)((addxh<<8) | (addxl&0xFF)); addxl = (short)((T2N1&0xFF) + (T1N1&0xFF) + addc); addxh = (short)(((T2N1>>>8)&0xFF) + ((T1N1>>>8)&0xFF) + (short)(addxl>>>8)); T2N1 = (short)((addxh<<8) | (addxl&0xFF));;
        tmpOff = (short)(4*(short)((j-16) & 0xF)); addb = blk[(short)(tmpOff + 3)]; addxl = (short)((T2N4&0xFF) + (addb&0xFF)); addxh = (short)(((T2N4>>>8)&0xFF) + ((addb>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T2N4 = (short)((addxh<<8) | (addxl&0xFF)); addb = blk[(short)(tmpOff + 2)]; addxl = (short)((T2N3&0xFF) + (addb&0xFF) + addc); addxh = (short)(((T2N3>>>8)&0xFF) + ((addb>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T2N3 = (short)((addxh<<8) | (addxl&0xFF)); addb = blk[(short)(tmpOff + 1)]; addxl = (short)((T2N2&0xFF) + (addb&0xFF) + addc); addxh = (short)(((T2N2>>>8)&0xFF) + ((addb>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T2N2 = (short)((addxh<<8) | (addxl&0xFF)); addb = blk[tmpOff]; addxl = (short)((T2N1&0xFF) + (addb&0xFF) + addc); addxh = (short)(((T2N1>>>8)&0xFF) + ((addb>>>8)&0xFF) + (short)(addxl>>>8)); T2N1 = (short)((addxh<<8) | (addxl&0xFF));;
        tmpOff = (short)(4*(short)(j&0xF)); blk[tmpOff] = T2N1; blk[(short)(tmpOff + 1)] = T2N2; blk[(short)(tmpOff + 2)] = T2N3; blk[(short)(tmpOff + 3)] = T2N4;;
      }
      T1N1 = HN1; T1N2 = HN2; T1N3 = HN3; T1N4 = HN4;;
      RN1 = EN1; RN2 = EN2; RN3 = EN3; RN4 = EN4;;
      T3N1 = (short) ( (RN1>>>14) & (short)3 | ((short)(RN4<<(2))) ); T3N2 = (short) ( (RN2>>>14) & (short)3 | ((short)(RN1<<(2))) ); T3N3 = (short) ( (RN3>>>14) & (short)3 | ((short)(RN2<<(2))) ); T3N4 = (short) ( (RN4>>>14) & (short)3 | ((short)(RN3<<(2))) );; T4N1 = (short) ( (RN4>>>2) & (short)16383 | ((short)(RN3<<(14))) ); T4N2 = (short) ( (RN1>>>2) & (short)16383 | ((short)(RN4<<(14))) ); T4N3 = (short) ( (RN2>>>2) & (short)16383 | ((short)(RN1<<(14))) ); T4N4 = (short) ( (RN3>>>2) & (short)16383 | ((short)(RN2<<(14))) );; T5N1 = (short) ( (RN3>>>9) & (short)127 | ((short)(RN2<<(7))) ); T5N2 = (short) ( (RN4>>>9) & (short)127 | ((short)(RN3<<(7))) ); T5N3 = (short) ( (RN1>>>9) & (short)127 | ((short)(RN4<<(7))) ); T5N4 = (short) ( (RN2>>>9) & (short)127 | ((short)(RN1<<(7))) );; RN1 = (short)(T3N1 ^ T4N1 ^ T5N1); RN2 = (short)(T3N2 ^ T4N2 ^ T5N2); RN3 = (short)(T3N3 ^ T4N3 ^ T5N3); RN4 = (short)(T3N4 ^ T4N4 ^ T5N4);;
      addxl = (short)((T1N4&0xFF) + (RN4&0xFF)); addxh = (short)(((T1N4>>>8)&0xFF) + ((RN4>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T1N4 = (short)((addxh<<8) | (addxl&0xFF)); addxl = (short)((T1N3&0xFF) + (RN3&0xFF) + addc); addxh = (short)(((T1N3>>>8)&0xFF) + ((RN3>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T1N3 = (short)((addxh<<8) | (addxl&0xFF)); addxl = (short)((T1N2&0xFF) + (RN2&0xFF) + addc); addxh = (short)(((T1N2>>>8)&0xFF) + ((RN2>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T1N2 = (short)((addxh<<8) | (addxl&0xFF)); addxl = (short)((T1N1&0xFF) + (RN1&0xFF) + addc); addxh = (short)(((T1N1>>>8)&0xFF) + ((RN1>>>8)&0xFF) + (short)(addxl>>>8)); T1N1 = (short)((addxh<<8) | (addxl&0xFF));;
      RN1 = (short) ( ( (EN1) & (FN1) ) ^ ( (~EN1) & (GN1) ) ); RN2 = (short) ( ( (EN2) & (FN2) ) ^ ( (~EN2) & (GN2) ) ); RN3 = (short) ( ( (EN3) & (FN3) ) ^ ( (~EN3) & (GN3) ) ); RN4 = (short) ( ( (EN4) & (FN4) ) ^ ( (~EN4) & (GN4) ) );;
      addxl = (short)((T1N4&0xFF) + (RN4&0xFF)); addxh = (short)(((T1N4>>>8)&0xFF) + ((RN4>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T1N4 = (short)((addxh<<8) | (addxl&0xFF)); addxl = (short)((T1N3&0xFF) + (RN3&0xFF) + addc); addxh = (short)(((T1N3>>>8)&0xFF) + ((RN3>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T1N3 = (short)((addxh<<8) | (addxl&0xFF)); addxl = (short)((T1N2&0xFF) + (RN2&0xFF) + addc); addxh = (short)(((T1N2>>>8)&0xFF) + ((RN2>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T1N2 = (short)((addxh<<8) | (addxl&0xFF)); addxl = (short)((T1N1&0xFF) + (RN1&0xFF) + addc); addxh = (short)(((T1N1>>>8)&0xFF) + ((RN1>>>8)&0xFF) + (short)(addxl>>>8)); T1N1 = (short)((addxh<<8) | (addxl&0xFF));;
      jProc = (short)(j*4); RN1 = primeSqrt[(short)(jProc )]; RN2 = primeSqrt[(short)(jProc+1)]; RN3 = primeSqrt[(short)(jProc+2)]; RN4 = primeSqrt[(short)(jProc+3)];;
      addxl = (short)((T1N4&0xFF) + (RN4&0xFF)); addxh = (short)(((T1N4>>>8)&0xFF) + ((RN4>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T1N4 = (short)((addxh<<8) | (addxl&0xFF)); addxl = (short)((T1N3&0xFF) + (RN3&0xFF) + addc); addxh = (short)(((T1N3>>>8)&0xFF) + ((RN3>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T1N3 = (short)((addxh<<8) | (addxl&0xFF)); addxl = (short)((T1N2&0xFF) + (RN2&0xFF) + addc); addxh = (short)(((T1N2>>>8)&0xFF) + ((RN2>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T1N2 = (short)((addxh<<8) | (addxl&0xFF)); addxl = (short)((T1N1&0xFF) + (RN1&0xFF) + addc); addxh = (short)(((T1N1>>>8)&0xFF) + ((RN1>>>8)&0xFF) + (short)(addxl>>>8)); T1N1 = (short)((addxh<<8) | (addxl&0xFF));;
      tmpOff = (short)(4*(short)(j&0xF)); addb = blk[(short)(tmpOff + 3)]; addxl = (short)((T1N4&0xFF) + (addb&0xFF)); addxh = (short)(((T1N4>>>8)&0xFF) + ((addb>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T1N4 = (short)((addxh<<8) | (addxl&0xFF)); addb = blk[(short)(tmpOff + 2)]; addxl = (short)((T1N3&0xFF) + (addb&0xFF) + addc); addxh = (short)(((T1N3>>>8)&0xFF) + ((addb>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T1N3 = (short)((addxh<<8) | (addxl&0xFF)); addb = blk[(short)(tmpOff + 1)]; addxl = (short)((T1N2&0xFF) + (addb&0xFF) + addc); addxh = (short)(((T1N2>>>8)&0xFF) + ((addb>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T1N2 = (short)((addxh<<8) | (addxl&0xFF)); addb = blk[tmpOff]; addxl = (short)((T1N1&0xFF) + (addb&0xFF) + addc); addxh = (short)(((T1N1>>>8)&0xFF) + ((addb>>>8)&0xFF) + (short)(addxl>>>8)); T1N1 = (short)((addxh<<8) | (addxl&0xFF));;
      T2N1 = AN1; T2N2 = AN2; T2N3 = AN3; T2N4 = AN4;;
      T3N1 = (short) ( (T2N4>>>12) & (short)15 | ((short)(T2N3<<(4))) ); T3N2 = (short) ( (T2N1>>>12) & (short)15 | ((short)(T2N4<<(4))) ); T3N3 = (short) ( (T2N2>>>12) & (short)15 | ((short)(T2N1<<(4))) ); T3N4 = (short) ( (T2N3>>>12) & (short)15 | ((short)(T2N2<<(4))) );; T4N1 = (short) ( (T2N3>>>2) & (short)16383 | ((short)(T2N2<<(14))) ); T4N2 = (short) ( (T2N4>>>2) & (short)16383 | ((short)(T2N3<<(14))) ); T4N3 = (short) ( (T2N1>>>2) & (short)16383 | ((short)(T2N4<<(14))) ); T4N4 = (short) ( (T2N2>>>2) & (short)16383 | ((short)(T2N1<<(14))) );; T5N1 = (short) ( (T2N3>>>7) & (short)511 | ((short)(T2N2<<(9))) ); T5N2 = (short) ( (T2N4>>>7) & (short)511 | ((short)(T2N3<<(9))) ); T5N3 = (short) ( (T2N1>>>7) & (short)511 | ((short)(T2N4<<(9))) ); T5N4 = (short) ( (T2N2>>>7) & (short)511 | ((short)(T2N1<<(9))) );; T2N1 = (short)(T3N1 ^ T4N1 ^ T5N1); T2N2 = (short)(T3N2 ^ T4N2 ^ T5N2); T2N3 = (short)(T3N3 ^ T4N3 ^ T5N3); T2N4 = (short)(T3N4 ^ T4N4 ^ T5N4);;
      RN1 = (short) ( ( (AN1) & (BN1) ) ^ ( (AN1) & (CN1) ) ^ ( (BN1) & (CN1) ) ); RN2 = (short) ( ( (AN2) & (BN2) ) ^ ( (AN2) & (CN2) ) ^ ( (BN2) & (CN2) ) ); RN3 = (short) ( ( (AN3) & (BN3) ) ^ ( (AN3) & (CN3) ) ^ ( (BN3) & (CN3) ) ); RN4 = (short) ( ( (AN4) & (BN4) ) ^ ( (AN4) & (CN4) ) ^ ( (BN4) & (CN4) ) );;
      addxl = (short)((T2N4&0xFF) + (RN4&0xFF)); addxh = (short)(((T2N4>>>8)&0xFF) + ((RN4>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T2N4 = (short)((addxh<<8) | (addxl&0xFF)); addxl = (short)((T2N3&0xFF) + (RN3&0xFF) + addc); addxh = (short)(((T2N3>>>8)&0xFF) + ((RN3>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T2N3 = (short)((addxh<<8) | (addxl&0xFF)); addxl = (short)((T2N2&0xFF) + (RN2&0xFF) + addc); addxh = (short)(((T2N2>>>8)&0xFF) + ((RN2>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); T2N2 = (short)((addxh<<8) | (addxl&0xFF)); addxl = (short)((T2N1&0xFF) + (RN1&0xFF) + addc); addxh = (short)(((T2N1>>>8)&0xFF) + ((RN1>>>8)&0xFF) + (short)(addxl>>>8)); T2N1 = (short)((addxh<<8) | (addxl&0xFF));;
      HN1 = GN1; HN2 = GN2; HN3 = GN3; HN4 = GN4;;
      GN1 = FN1; GN2 = FN2; GN3 = FN3; GN4 = FN4;;
      FN1 = EN1; FN2 = EN2; FN3 = EN3; FN4 = EN4;;
      EN1 = DN1; EN2 = DN2; EN3 = DN3; EN4 = DN4;;
      DN1 = CN1; DN2 = CN2; DN3 = CN3; DN4 = CN4;;
      CN1 = BN1; CN2 = BN2; CN3 = BN3; CN4 = BN4;;
      BN1 = AN1; BN2 = AN2; BN3 = AN3; BN4 = AN4;;
      AN1 = T1N1; AN2 = T1N2; AN3 = T1N3; AN4 = T1N4;;
      addxl = (short)((AN4&0xFF) + (T2N4&0xFF)); addxh = (short)(((AN4>>>8)&0xFF) + ((T2N4>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); AN4 = (short)((addxh<<8) | (addxl&0xFF)); addxl = (short)((AN3&0xFF) + (T2N3&0xFF) + addc); addxh = (short)(((AN3>>>8)&0xFF) + ((T2N3>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); AN3 = (short)((addxh<<8) | (addxl&0xFF)); addxl = (short)((AN2&0xFF) + (T2N2&0xFF) + addc); addxh = (short)(((AN2>>>8)&0xFF) + ((T2N2>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); AN2 = (short)((addxh<<8) | (addxl&0xFF)); addxl = (short)((AN1&0xFF) + (T2N1&0xFF) + addc); addxh = (short)(((AN1>>>8)&0xFF) + ((T2N1>>>8)&0xFF) + (short)(addxl>>>8)); AN1 = (short)((addxh<<8) | (addxl&0xFF));;
      addxl = (short)((EN4&0xFF) + (T1N4&0xFF)); addxh = (short)(((EN4>>>8)&0xFF) + ((T1N4>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); EN4 = (short)((addxh<<8) | (addxl&0xFF)); addxl = (short)((EN3&0xFF) + (T1N3&0xFF) + addc); addxh = (short)(((EN3>>>8)&0xFF) + ((T1N3>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); EN3 = (short)((addxh<<8) | (addxl&0xFF)); addxl = (short)((EN2&0xFF) + (T1N2&0xFF) + addc); addxh = (short)(((EN2>>>8)&0xFF) + ((T1N2>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); EN2 = (short)((addxh<<8) | (addxl&0xFF)); addxl = (short)((EN1&0xFF) + (T1N1&0xFF) + addc); addxh = (short)(((EN1>>>8)&0xFF) + ((T1N1>>>8)&0xFF) + (short)(addxl>>>8)); EN1 = (short)((addxh<<8) | (addxl&0xFF));;
    }
    adda = working[(short)(H0 + 3)]; addxl = (short)((adda&0xFF) + (AN4&0xFF)); addxh = (short)(((adda>>>8)&0xFF) + ((AN4>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H0 + 3)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[(short)(H0 + 2)]; addxl = (short)((adda&0xFF) + (AN3&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((AN3>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H0 + 2)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[(short)(H0 + 1)]; addxl = (short)((adda&0xFF) + (AN2&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((AN2>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H0 + 1)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[H0]; addxl = (short)((adda&0xFF) + (AN1&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((AN1>>>8)&0xFF) + (short)(addxl>>>8)); working[H0] = (short)((addxh<<8) | (addxl&0xFF));;
    adda = working[(short)(H1 + 3)]; addxl = (short)((adda&0xFF) + (BN4&0xFF)); addxh = (short)(((adda>>>8)&0xFF) + ((BN4>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H1 + 3)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[(short)(H1 + 2)]; addxl = (short)((adda&0xFF) + (BN3&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((BN3>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H1 + 2)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[(short)(H1 + 1)]; addxl = (short)((adda&0xFF) + (BN2&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((BN2>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H1 + 1)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[H1]; addxl = (short)((adda&0xFF) + (BN1&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((BN1>>>8)&0xFF) + (short)(addxl>>>8)); working[H1] = (short)((addxh<<8) | (addxl&0xFF));;
    adda = working[(short)(H2 + 3)]; addxl = (short)((adda&0xFF) + (CN4&0xFF)); addxh = (short)(((adda>>>8)&0xFF) + ((CN4>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H2 + 3)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[(short)(H2 + 2)]; addxl = (short)((adda&0xFF) + (CN3&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((CN3>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H2 + 2)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[(short)(H2 + 1)]; addxl = (short)((adda&0xFF) + (CN2&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((CN2>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H2 + 1)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[H2]; addxl = (short)((adda&0xFF) + (CN1&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((CN1>>>8)&0xFF) + (short)(addxl>>>8)); working[H2] = (short)((addxh<<8) | (addxl&0xFF));;
    adda = working[(short)(H3 + 3)]; addxl = (short)((adda&0xFF) + (DN4&0xFF)); addxh = (short)(((adda>>>8)&0xFF) + ((DN4>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H3 + 3)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[(short)(H3 + 2)]; addxl = (short)((adda&0xFF) + (DN3&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((DN3>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H3 + 2)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[(short)(H3 + 1)]; addxl = (short)((adda&0xFF) + (DN2&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((DN2>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H3 + 1)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[H3]; addxl = (short)((adda&0xFF) + (DN1&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((DN1>>>8)&0xFF) + (short)(addxl>>>8)); working[H3] = (short)((addxh<<8) | (addxl&0xFF));;
    adda = working[(short)(H4 + 3)]; addxl = (short)((adda&0xFF) + (EN4&0xFF)); addxh = (short)(((adda>>>8)&0xFF) + ((EN4>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H4 + 3)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[(short)(H4 + 2)]; addxl = (short)((adda&0xFF) + (EN3&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((EN3>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H4 + 2)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[(short)(H4 + 1)]; addxl = (short)((adda&0xFF) + (EN2&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((EN2>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H4 + 1)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[H4]; addxl = (short)((adda&0xFF) + (EN1&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((EN1>>>8)&0xFF) + (short)(addxl>>>8)); working[H4] = (short)((addxh<<8) | (addxl&0xFF));;
    adda = working[(short)(H5 + 3)]; addxl = (short)((adda&0xFF) + (FN4&0xFF)); addxh = (short)(((adda>>>8)&0xFF) + ((FN4>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H5 + 3)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[(short)(H5 + 2)]; addxl = (short)((adda&0xFF) + (FN3&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((FN3>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H5 + 2)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[(short)(H5 + 1)]; addxl = (short)((adda&0xFF) + (FN2&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((FN2>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H5 + 1)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[H5]; addxl = (short)((adda&0xFF) + (FN1&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((FN1>>>8)&0xFF) + (short)(addxl>>>8)); working[H5] = (short)((addxh<<8) | (addxl&0xFF));;
    adda = working[(short)(H6 + 3)]; addxl = (short)((adda&0xFF) + (GN4&0xFF)); addxh = (short)(((adda>>>8)&0xFF) + ((GN4>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H6 + 3)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[(short)(H6 + 2)]; addxl = (short)((adda&0xFF) + (GN3&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((GN3>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H6 + 2)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[(short)(H6 + 1)]; addxl = (short)((adda&0xFF) + (GN2&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((GN2>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H6 + 1)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[H6]; addxl = (short)((adda&0xFF) + (GN1&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((GN1>>>8)&0xFF) + (short)(addxl>>>8)); working[H6] = (short)((addxh<<8) | (addxl&0xFF));;
    adda = working[(short)(H7 + 3)]; addxl = (short)((adda&0xFF) + (HN4&0xFF)); addxh = (short)(((adda>>>8)&0xFF) + ((HN4>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H7 + 3)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[(short)(H7 + 2)]; addxl = (short)((adda&0xFF) + (HN3&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((HN3>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H7 + 2)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[(short)(H7 + 1)]; addxl = (short)((adda&0xFF) + (HN2&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((HN2>>>8)&0xFF) + (short)(addxl>>>8)); addc = (short)(addxh>>>8); working[(short)(H7 + 1)] = (short)((addxh<<8) | (addxl&0xFF)); adda = working[H7]; addxl = (short)((adda&0xFF) + (HN1&0xFF) + addc); addxh = (short)(((adda>>>8)&0xFF) + ((HN1>>>8)&0xFF) + (short)(addxl>>>8)); working[H7] = (short)((addxh<<8) | (addxl&0xFF));;
  }
}
