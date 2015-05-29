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
import javacard.framework.Util;
public class Ripemd160 {
    public static void hash32(byte[] buffer, short offset, byte[] target, short targetOffset, byte[] scratch, short scratchOffset)
    {
      byte i;
      short H0HIGH = (short)0, H0LOW = (short)0; short H1HIGH = (short)0, H1LOW = (short)0; short H2HIGH = (short)0, H2LOW = (short)0; short H3HIGH = (short)0, H3LOW = (short)0; short H4HIGH = (short)0, H4LOW = (short)0;
      short X0HIGH = (short)0, X0LOW = (short)0; short X1HIGH = (short)0, X1LOW = (short)0; short X2HIGH = (short)0, X2LOW = (short)0; short X3HIGH = (short)0, X3LOW = (short)0; short X4HIGH = (short)0, X4LOW = (short)0; short X5HIGH = (short)0, X5LOW = (short)0; short X6HIGH = (short)0, X6LOW = (short)0; short X7HIGH = (short)0, X7LOW = (short)0; short X8HIGH = (short)0, X8LOW = (short)0; short X9HIGH = (short)0, X9LOW = (short)0; short X10HIGH = (short)0, X10LOW = (short)0; short X11HIGH = (short)0, X11LOW = (short)0; short X12HIGH = (short)0, X12LOW = (short)0; short X13HIGH = (short)0, X13LOW = (short)0; short X14HIGH = (short)0, X14LOW = (short)0; short X15HIGH = (short)0, X15LOW = (short)0;
      short XHIGH = (short)0, XLOW = (short)0;
      short AHIGH = (short)0, ALOW = (short)0; short BHIGH = (short)0, BLOW = (short)0; short CHIGH = (short)0, CLOW = (short)0; short DHIGH = (short)0, DLOW = (short)0; short EHIGH = (short)0, ELOW = (short)0; short ApHIGH = (short)0, ApLOW = (short)0; short BpHIGH = (short)0, BpLOW = (short)0; short CpHIGH = (short)0, CpLOW = (short)0; short DpHIGH = (short)0, DpLOW = (short)0; short EpHIGH = (short)0, EpLOW = (short)0; short THIGH = (short)0, TLOW = (short)0; short sHIGH = (short)0, sLOW = (short)0; short tmpHIGH = (short)0, tmpLOW = (short)0;
      short addX, addY, addLow, addCarry; short rotH, rotL, rotMsk, rotSl, rotSh;
      H0HIGH = (short)0x6745; H0LOW = (short)0x2301;
      H1HIGH = (short)0xEFCD; H1LOW = (short)0xAB89;
      H2HIGH = (short)0x98BA; H2LOW = (short)0xDCFE;
      H3HIGH = (short)0x1032; H3LOW = (short)0x5476;
      H4HIGH = (short)0xC3D2; H4LOW = (short)0xE1F0;
      Util.arrayFillNonAtomic(scratch, scratchOffset, (short)64, (byte)0x00);
      Util.arrayCopyNonAtomic(buffer, offset, scratch, scratchOffset, (short)32);
      scratch[(short)(scratchOffset + 32)] = (byte)0x80;
      scratch[(short)(scratchOffset + 64 - 7)] = (byte)0x01;
      offset = scratchOffset;
      for (i = 0; i < 16; i++) {
        short low = (short)((scratch[offset++] & 0xff) | ((scratch[offset++] & 0xff) << 8));
        short high = (short)((scratch[offset++] & 0xff) | ((scratch[offset++] & 0xff) << 8));
        switch(i) {
            case 0: X0HIGH = (short)high; X0LOW = (short)low; break;
            case 1: X1HIGH = (short)high; X1LOW = (short)low; break;
            case 2: X2HIGH = (short)high; X2LOW = (short)low; break;
            case 3: X3HIGH = (short)high; X3LOW = (short)low; break;
            case 4: X4HIGH = (short)high; X4LOW = (short)low; break;
            case 5: X5HIGH = (short)high; X5LOW = (short)low; break;
            case 6: X6HIGH = (short)high; X6LOW = (short)low; break;
            case 7: X7HIGH = (short)high; X7LOW = (short)low; break;
            case 8: X8HIGH = (short)high; X8LOW = (short)low; break;
            case 9: X9HIGH = (short)high; X9LOW = (short)low; break;
            case 10: X10HIGH = (short)high; X10LOW = (short)low; break;
            case 11: X11HIGH = (short)high; X11LOW = (short)low; break;
            case 12: X12HIGH = (short)high; X12LOW = (short)low; break;
            case 13: X13HIGH = (short)high; X13LOW = (short)low; break;
            case 14: X14HIGH = (short)high; X14LOW = (short)low; break;
            case 15: X15HIGH = (short)high; X15LOW = (short)low; break;
        }
      }
      AHIGH = H0HIGH; ALOW = H0LOW;
      ApHIGH = H0HIGH; ApLOW = H0LOW;
      BHIGH = H1HIGH; BLOW = H1LOW;
      BpHIGH = H1HIGH; BpLOW = H1LOW;
      CHIGH = H2HIGH; CLOW = H2LOW;
      CpHIGH = H2HIGH; CpLOW = H2LOW;
      DHIGH = H3HIGH; DLOW = H3LOW;
      DpHIGH = H3HIGH; DpLOW = H3LOW;
      EHIGH = H4HIGH; ELOW = H4LOW;
      EpHIGH = H4HIGH; EpLOW = H4LOW;
      for (i = 0; i < 80; i++)
        {
          sHIGH = (short)0; sLOW = (short)S[i];
          switch(i >> 4) {
              case 0:
                  THIGH = BHIGH; TLOW = BLOW;
                  THIGH ^= CHIGH; TLOW ^= CLOW;
                  THIGH ^= DHIGH; TLOW ^= DLOW;
                  addX = TLOW; addY = ALOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += AHIGH;
                  switch(i) { case 0 : XLOW = X0LOW; XHIGH = X0HIGH; break; case 1 : XLOW = X1LOW; XHIGH = X1HIGH; break; case 2 : XLOW = X2LOW; XHIGH = X2HIGH; break; case 3 : XLOW = X3LOW; XHIGH = X3HIGH; break; case 4 : XLOW = X4LOW; XHIGH = X4HIGH; break; case 5 : XLOW = X5LOW; XHIGH = X5HIGH; break; case 6 : XLOW = X6LOW; XHIGH = X6HIGH; break; case 7 : XLOW = X7LOW; XHIGH = X7HIGH; break; case 8 : XLOW = X8LOW; XHIGH = X8HIGH; break; case 9 : XLOW = X9LOW; XHIGH = X9HIGH; break; case 10 : XLOW = X10LOW; XHIGH = X10HIGH; break; case 11 : XLOW = X11LOW; XHIGH = X11HIGH; break; case 12 : XLOW = X12LOW; XHIGH = X12HIGH; break; case 13 : XLOW = X13LOW; XHIGH = X13HIGH; break; case 14 : XLOW = X14LOW; XHIGH = X14HIGH; break; case 15 : XLOW = X15LOW; XHIGH = X15HIGH; break; };
                  addX = TLOW; addY = XLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += XHIGH;
                  break;
              case 1:
                  THIGH = BHIGH; TLOW = BLOW;
                  THIGH &= CHIGH; TLOW &= CLOW;
                  tmpHIGH = BHIGH; tmpLOW = BLOW;
                  tmpHIGH = (short)(~tmpHIGH); tmpLOW = (short)(~tmpLOW);
                  tmpHIGH &= DHIGH; tmpLOW &= DLOW;
                  THIGH |= tmpHIGH; TLOW |= tmpLOW;
                  addX = TLOW; addY = ALOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += AHIGH;
                  switch(R[i]) { case 0 : XLOW = X0LOW; XHIGH = X0HIGH; break; case 1 : XLOW = X1LOW; XHIGH = X1HIGH; break; case 2 : XLOW = X2LOW; XHIGH = X2HIGH; break; case 3 : XLOW = X3LOW; XHIGH = X3HIGH; break; case 4 : XLOW = X4LOW; XHIGH = X4HIGH; break; case 5 : XLOW = X5LOW; XHIGH = X5HIGH; break; case 6 : XLOW = X6LOW; XHIGH = X6HIGH; break; case 7 : XLOW = X7LOW; XHIGH = X7HIGH; break; case 8 : XLOW = X8LOW; XHIGH = X8HIGH; break; case 9 : XLOW = X9LOW; XHIGH = X9HIGH; break; case 10 : XLOW = X10LOW; XHIGH = X10HIGH; break; case 11 : XLOW = X11LOW; XHIGH = X11HIGH; break; case 12 : XLOW = X12LOW; XHIGH = X12HIGH; break; case 13 : XLOW = X13LOW; XHIGH = X13HIGH; break; case 14 : XLOW = X14LOW; XHIGH = X14HIGH; break; case 15 : XLOW = X15LOW; XHIGH = X15HIGH; break; };
                  addX = TLOW; addY = XLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += XHIGH;
                  addX = TLOW; addY = (short)0x7999; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += (short)0x5A82;
                  break;
              case 2:
                  THIGH = CHIGH; TLOW = CLOW;
                  THIGH = (short)(~THIGH); TLOW = (short)(~TLOW);
                  THIGH |= BHIGH; TLOW |= BLOW;
                  THIGH ^= DHIGH; TLOW ^= DLOW;
                  addX = TLOW; addY = ALOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += AHIGH;
                  switch(R[i]) { case 0 : XLOW = X0LOW; XHIGH = X0HIGH; break; case 1 : XLOW = X1LOW; XHIGH = X1HIGH; break; case 2 : XLOW = X2LOW; XHIGH = X2HIGH; break; case 3 : XLOW = X3LOW; XHIGH = X3HIGH; break; case 4 : XLOW = X4LOW; XHIGH = X4HIGH; break; case 5 : XLOW = X5LOW; XHIGH = X5HIGH; break; case 6 : XLOW = X6LOW; XHIGH = X6HIGH; break; case 7 : XLOW = X7LOW; XHIGH = X7HIGH; break; case 8 : XLOW = X8LOW; XHIGH = X8HIGH; break; case 9 : XLOW = X9LOW; XHIGH = X9HIGH; break; case 10 : XLOW = X10LOW; XHIGH = X10HIGH; break; case 11 : XLOW = X11LOW; XHIGH = X11HIGH; break; case 12 : XLOW = X12LOW; XHIGH = X12HIGH; break; case 13 : XLOW = X13LOW; XHIGH = X13HIGH; break; case 14 : XLOW = X14LOW; XHIGH = X14HIGH; break; case 15 : XLOW = X15LOW; XHIGH = X15HIGH; break; };
                  addX = TLOW; addY = XLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += XHIGH;
                  addX = TLOW; addY = (short)0xEBA1; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += (short)0x6ED9;
                  break;
              case 3:
                  THIGH = BHIGH; TLOW = BLOW;
                  THIGH &= DHIGH; TLOW &= DLOW;
                  tmpHIGH = DHIGH; tmpLOW = DLOW;
                  tmpHIGH = (short)(~tmpHIGH); tmpLOW = (short)(~tmpLOW);
                  tmpHIGH &= CHIGH; tmpLOW &= CLOW;
                  THIGH |= tmpHIGH; TLOW |= tmpLOW;
                  addX = TLOW; addY = ALOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += AHIGH;
                  switch(R[i]) { case 0 : XLOW = X0LOW; XHIGH = X0HIGH; break; case 1 : XLOW = X1LOW; XHIGH = X1HIGH; break; case 2 : XLOW = X2LOW; XHIGH = X2HIGH; break; case 3 : XLOW = X3LOW; XHIGH = X3HIGH; break; case 4 : XLOW = X4LOW; XHIGH = X4HIGH; break; case 5 : XLOW = X5LOW; XHIGH = X5HIGH; break; case 6 : XLOW = X6LOW; XHIGH = X6HIGH; break; case 7 : XLOW = X7LOW; XHIGH = X7HIGH; break; case 8 : XLOW = X8LOW; XHIGH = X8HIGH; break; case 9 : XLOW = X9LOW; XHIGH = X9HIGH; break; case 10 : XLOW = X10LOW; XHIGH = X10HIGH; break; case 11 : XLOW = X11LOW; XHIGH = X11HIGH; break; case 12 : XLOW = X12LOW; XHIGH = X12HIGH; break; case 13 : XLOW = X13LOW; XHIGH = X13HIGH; break; case 14 : XLOW = X14LOW; XHIGH = X14HIGH; break; case 15 : XLOW = X15LOW; XHIGH = X15HIGH; break; };
                  addX = TLOW; addY = XLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += XHIGH;
                  addX = TLOW; addY = (short)0xBCDC; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += (short)0x8F1B;
                  break;
              case 4:
                  THIGH = DHIGH; TLOW = DLOW;
                  THIGH = (short)(~THIGH); TLOW = (short)(~TLOW);
                  THIGH |= CHIGH; TLOW |= CLOW;
                  THIGH ^= BHIGH; TLOW ^= BLOW;
                  addX = TLOW; addY = ALOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += AHIGH;
                  switch(R[i]) { case 0 : XLOW = X0LOW; XHIGH = X0HIGH; break; case 1 : XLOW = X1LOW; XHIGH = X1HIGH; break; case 2 : XLOW = X2LOW; XHIGH = X2HIGH; break; case 3 : XLOW = X3LOW; XHIGH = X3HIGH; break; case 4 : XLOW = X4LOW; XHIGH = X4HIGH; break; case 5 : XLOW = X5LOW; XHIGH = X5HIGH; break; case 6 : XLOW = X6LOW; XHIGH = X6HIGH; break; case 7 : XLOW = X7LOW; XHIGH = X7HIGH; break; case 8 : XLOW = X8LOW; XHIGH = X8HIGH; break; case 9 : XLOW = X9LOW; XHIGH = X9HIGH; break; case 10 : XLOW = X10LOW; XHIGH = X10HIGH; break; case 11 : XLOW = X11LOW; XHIGH = X11HIGH; break; case 12 : XLOW = X12LOW; XHIGH = X12HIGH; break; case 13 : XLOW = X13LOW; XHIGH = X13HIGH; break; case 14 : XLOW = X14LOW; XHIGH = X14HIGH; break; case 15 : XLOW = X15LOW; XHIGH = X15HIGH; break; };
                  addX = TLOW; addY = XLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += XHIGH;
                  addX = TLOW; addY = (short)0xFD4E; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += (short)0xA953;
                  break;
          }
          AHIGH = EHIGH; ALOW = ELOW;
          EHIGH = DHIGH; ELOW = DLOW;
          DHIGH = CHIGH; DLOW = CLOW;
          rotMsk = mask[(short)10]; rotH = DHIGH; rotL = DLOW; rotSh = (short) (rotMsk & ((short) (rotH >>> ((short)(16-(short)10))))); rotSl = (short) (rotMsk & ((short) (rotL >>> ((short)(16-(short)10))))); DHIGH = (short) ((rotH<<(short)(short)10) | rotSl); DLOW = (short) ((rotL<<(short)(short)10) | rotSh);
          CHIGH = BHIGH; CLOW = BLOW;
          BHIGH = THIGH; BLOW = TLOW;
          rotMsk = mask[sLOW]; rotH = BHIGH; rotL = BLOW; rotSh = (short) (rotMsk & ((short) (rotH >>> ((short)(16-sLOW))))); rotSl = (short) (rotMsk & ((short) (rotL >>> ((short)(16-sLOW))))); BHIGH = (short) ((rotH<<(short)sLOW) | rotSl); BLOW = (short) ((rotL<<(short)sLOW) | rotSh);
          addX = BLOW; addY = ALOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); BHIGH += addCarry; BLOW = addLow; BHIGH += AHIGH;
          sHIGH = (short)0; sLOW = (short)Sp[i];
          switch(i >> 4) {
              case 0:
                  THIGH = DpHIGH; TLOW = DpLOW;
                  THIGH = (short)(~THIGH); TLOW = (short)(~TLOW);
                  THIGH |= CpHIGH; TLOW |= CpLOW;
                  THIGH ^= BpHIGH; TLOW ^= BpLOW;
                  addX = TLOW; addY = ApLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += ApHIGH;
                  switch(Rp[i]) { case 0 : XLOW = X0LOW; XHIGH = X0HIGH; break; case 1 : XLOW = X1LOW; XHIGH = X1HIGH; break; case 2 : XLOW = X2LOW; XHIGH = X2HIGH; break; case 3 : XLOW = X3LOW; XHIGH = X3HIGH; break; case 4 : XLOW = X4LOW; XHIGH = X4HIGH; break; case 5 : XLOW = X5LOW; XHIGH = X5HIGH; break; case 6 : XLOW = X6LOW; XHIGH = X6HIGH; break; case 7 : XLOW = X7LOW; XHIGH = X7HIGH; break; case 8 : XLOW = X8LOW; XHIGH = X8HIGH; break; case 9 : XLOW = X9LOW; XHIGH = X9HIGH; break; case 10 : XLOW = X10LOW; XHIGH = X10HIGH; break; case 11 : XLOW = X11LOW; XHIGH = X11HIGH; break; case 12 : XLOW = X12LOW; XHIGH = X12HIGH; break; case 13 : XLOW = X13LOW; XHIGH = X13HIGH; break; case 14 : XLOW = X14LOW; XHIGH = X14HIGH; break; case 15 : XLOW = X15LOW; XHIGH = X15HIGH; break; };
                  addX = TLOW; addY = XLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += XHIGH;
                  addX = TLOW; addY = (short)0x8BE6; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += (short)0x50A2;
                  break;
              case 1:
                  THIGH = BpHIGH; TLOW = BpLOW;
                  THIGH &= DpHIGH; TLOW &= DpLOW;
                  tmpHIGH = DpHIGH; tmpLOW = DpLOW;
                  tmpHIGH = (short)(~tmpHIGH); tmpLOW = (short)(~tmpLOW);
                  tmpHIGH &= CpHIGH; tmpLOW &= CpLOW;
                  THIGH |= tmpHIGH; TLOW |= tmpLOW;
                  addX = TLOW; addY = ApLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += ApHIGH;
                  switch(Rp[i]) { case 0 : XLOW = X0LOW; XHIGH = X0HIGH; break; case 1 : XLOW = X1LOW; XHIGH = X1HIGH; break; case 2 : XLOW = X2LOW; XHIGH = X2HIGH; break; case 3 : XLOW = X3LOW; XHIGH = X3HIGH; break; case 4 : XLOW = X4LOW; XHIGH = X4HIGH; break; case 5 : XLOW = X5LOW; XHIGH = X5HIGH; break; case 6 : XLOW = X6LOW; XHIGH = X6HIGH; break; case 7 : XLOW = X7LOW; XHIGH = X7HIGH; break; case 8 : XLOW = X8LOW; XHIGH = X8HIGH; break; case 9 : XLOW = X9LOW; XHIGH = X9HIGH; break; case 10 : XLOW = X10LOW; XHIGH = X10HIGH; break; case 11 : XLOW = X11LOW; XHIGH = X11HIGH; break; case 12 : XLOW = X12LOW; XHIGH = X12HIGH; break; case 13 : XLOW = X13LOW; XHIGH = X13HIGH; break; case 14 : XLOW = X14LOW; XHIGH = X14HIGH; break; case 15 : XLOW = X15LOW; XHIGH = X15HIGH; break; };
                  addX = TLOW; addY = XLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += XHIGH;
                  addX = TLOW; addY = (short)0xD124; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += (short)0x5C4D;
                  break;
              case 2:
                  THIGH = CpHIGH; TLOW = CpLOW;
                  THIGH = (short)(~THIGH); TLOW = (short)(~TLOW);
                  THIGH |= BpHIGH; TLOW |= BpLOW;
                  THIGH ^= DpHIGH; TLOW ^= DpLOW;
                  addX = TLOW; addY = ApLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += ApHIGH;
                  switch(Rp[i]) { case 0 : XLOW = X0LOW; XHIGH = X0HIGH; break; case 1 : XLOW = X1LOW; XHIGH = X1HIGH; break; case 2 : XLOW = X2LOW; XHIGH = X2HIGH; break; case 3 : XLOW = X3LOW; XHIGH = X3HIGH; break; case 4 : XLOW = X4LOW; XHIGH = X4HIGH; break; case 5 : XLOW = X5LOW; XHIGH = X5HIGH; break; case 6 : XLOW = X6LOW; XHIGH = X6HIGH; break; case 7 : XLOW = X7LOW; XHIGH = X7HIGH; break; case 8 : XLOW = X8LOW; XHIGH = X8HIGH; break; case 9 : XLOW = X9LOW; XHIGH = X9HIGH; break; case 10 : XLOW = X10LOW; XHIGH = X10HIGH; break; case 11 : XLOW = X11LOW; XHIGH = X11HIGH; break; case 12 : XLOW = X12LOW; XHIGH = X12HIGH; break; case 13 : XLOW = X13LOW; XHIGH = X13HIGH; break; case 14 : XLOW = X14LOW; XHIGH = X14HIGH; break; case 15 : XLOW = X15LOW; XHIGH = X15HIGH; break; };
                  addX = TLOW; addY = XLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += XHIGH;
                  addX = TLOW; addY = (short)0x3EF3; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += (short)0x6D70;
                  break;
              case 3:
                  THIGH = BpHIGH; TLOW = BpLOW;
                  THIGH &= CpHIGH; TLOW &= CpLOW;
                  tmpHIGH = BpHIGH; tmpLOW = BpLOW;
                  tmpHIGH = (short)(~tmpHIGH); tmpLOW = (short)(~tmpLOW);
                  tmpHIGH &= DpHIGH; tmpLOW &= DpLOW;
                  THIGH |= tmpHIGH; TLOW |= tmpLOW;
                  addX = TLOW; addY = ApLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += ApHIGH;
                  switch(Rp[i]) { case 0 : XLOW = X0LOW; XHIGH = X0HIGH; break; case 1 : XLOW = X1LOW; XHIGH = X1HIGH; break; case 2 : XLOW = X2LOW; XHIGH = X2HIGH; break; case 3 : XLOW = X3LOW; XHIGH = X3HIGH; break; case 4 : XLOW = X4LOW; XHIGH = X4HIGH; break; case 5 : XLOW = X5LOW; XHIGH = X5HIGH; break; case 6 : XLOW = X6LOW; XHIGH = X6HIGH; break; case 7 : XLOW = X7LOW; XHIGH = X7HIGH; break; case 8 : XLOW = X8LOW; XHIGH = X8HIGH; break; case 9 : XLOW = X9LOW; XHIGH = X9HIGH; break; case 10 : XLOW = X10LOW; XHIGH = X10HIGH; break; case 11 : XLOW = X11LOW; XHIGH = X11HIGH; break; case 12 : XLOW = X12LOW; XHIGH = X12HIGH; break; case 13 : XLOW = X13LOW; XHIGH = X13HIGH; break; case 14 : XLOW = X14LOW; XHIGH = X14HIGH; break; case 15 : XLOW = X15LOW; XHIGH = X15HIGH; break; };
                  addX = TLOW; addY = XLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += XHIGH;
                  addX = TLOW; addY = (short)0x76E9; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += (short)0x7A6D;
                  break;
              case 4:
                  THIGH = BpHIGH; TLOW = BpLOW;
                  THIGH ^= CpHIGH; TLOW ^= CpLOW;
                  THIGH ^= DpHIGH; TLOW ^= DpLOW;
                  addX = TLOW; addY = ApLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += ApHIGH;
                  switch(Rp[i]) { case 0 : XLOW = X0LOW; XHIGH = X0HIGH; break; case 1 : XLOW = X1LOW; XHIGH = X1HIGH; break; case 2 : XLOW = X2LOW; XHIGH = X2HIGH; break; case 3 : XLOW = X3LOW; XHIGH = X3HIGH; break; case 4 : XLOW = X4LOW; XHIGH = X4HIGH; break; case 5 : XLOW = X5LOW; XHIGH = X5HIGH; break; case 6 : XLOW = X6LOW; XHIGH = X6HIGH; break; case 7 : XLOW = X7LOW; XHIGH = X7HIGH; break; case 8 : XLOW = X8LOW; XHIGH = X8HIGH; break; case 9 : XLOW = X9LOW; XHIGH = X9HIGH; break; case 10 : XLOW = X10LOW; XHIGH = X10HIGH; break; case 11 : XLOW = X11LOW; XHIGH = X11HIGH; break; case 12 : XLOW = X12LOW; XHIGH = X12HIGH; break; case 13 : XLOW = X13LOW; XHIGH = X13HIGH; break; case 14 : XLOW = X14LOW; XHIGH = X14HIGH; break; case 15 : XLOW = X15LOW; XHIGH = X15HIGH; break; };
                  addX = TLOW; addY = XLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += XHIGH;
                  break;
          }
          ApHIGH = EpHIGH; ApLOW = EpLOW;
          EpHIGH = DpHIGH; EpLOW = DpLOW;
          DpHIGH = CpHIGH; DpLOW = CpLOW;
          rotMsk = mask[(short)10]; rotH = DpHIGH; rotL = DpLOW; rotSh = (short) (rotMsk & ((short) (rotH >>> ((short)(16-(short)10))))); rotSl = (short) (rotMsk & ((short) (rotL >>> ((short)(16-(short)10))))); DpHIGH = (short) ((rotH<<(short)(short)10) | rotSl); DpLOW = (short) ((rotL<<(short)(short)10) | rotSh);
          CpHIGH = BpHIGH; CpLOW = BpLOW;
          BpHIGH = THIGH; BpLOW = TLOW;
          rotMsk = mask[sLOW]; rotH = BpHIGH; rotL = BpLOW; rotSh = (short) (rotMsk & ((short) (rotH >>> ((short)(16-sLOW))))); rotSl = (short) (rotMsk & ((short) (rotL >>> ((short)(16-sLOW))))); BpHIGH = (short) ((rotH<<(short)sLOW) | rotSl); BpLOW = (short) ((rotL<<(short)sLOW) | rotSh);
          addX = BpLOW; addY = ApLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); BpHIGH += addCarry; BpLOW = addLow; BpHIGH += ApHIGH;
      }
      THIGH = H1HIGH; TLOW = H1LOW;
      addX = TLOW; addY = CLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += CHIGH;
      addX = TLOW; addY = DpLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); THIGH += addCarry; TLOW = addLow; THIGH += DpHIGH;
      H1HIGH = H2HIGH; H1LOW = H2LOW;
      addX = H1LOW; addY = DLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); H1HIGH += addCarry; H1LOW = addLow; H1HIGH += DHIGH;
      addX = H1LOW; addY = EpLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); H1HIGH += addCarry; H1LOW = addLow; H1HIGH += EpHIGH;
      H2HIGH = H3HIGH; H2LOW = H3LOW;
      addX = H2LOW; addY = ELOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); H2HIGH += addCarry; H2LOW = addLow; H2HIGH += EHIGH;
      addX = H2LOW; addY = ApLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); H2HIGH += addCarry; H2LOW = addLow; H2HIGH += ApHIGH;
      H3HIGH = H4HIGH; H3LOW = H4LOW;
      addX = H3LOW; addY = ALOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); H3HIGH += addCarry; H3LOW = addLow; H3HIGH += AHIGH;
      addX = H3LOW; addY = BpLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); H3HIGH += addCarry; H3LOW = addLow; H3HIGH += BpHIGH;
      H4HIGH = H0HIGH; H4LOW = H0LOW;
      addX = H4LOW; addY = BLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); H4HIGH += addCarry; H4LOW = addLow; H4HIGH += BHIGH;
      addX = H4LOW; addY = CpLOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); H4HIGH += addCarry; H4LOW = addLow; H4HIGH += CpHIGH;
      H0HIGH = THIGH; H0LOW = TLOW;
      target[targetOffset++] = (byte)(H0LOW); target[targetOffset++] = (byte)(H0LOW >>> 8); target[targetOffset++] = (byte)(H0HIGH); target[targetOffset++] = (byte)(H0HIGH >>> 8);
      target[targetOffset++] = (byte)(H1LOW); target[targetOffset++] = (byte)(H1LOW >>> 8); target[targetOffset++] = (byte)(H1HIGH); target[targetOffset++] = (byte)(H1HIGH >>> 8);
      target[targetOffset++] = (byte)(H2LOW); target[targetOffset++] = (byte)(H2LOW >>> 8); target[targetOffset++] = (byte)(H2HIGH); target[targetOffset++] = (byte)(H2HIGH >>> 8);
      target[targetOffset++] = (byte)(H3LOW); target[targetOffset++] = (byte)(H3LOW >>> 8); target[targetOffset++] = (byte)(H3HIGH); target[targetOffset++] = (byte)(H3HIGH >>> 8);
      target[targetOffset++] = (byte)(H4LOW); target[targetOffset++] = (byte)(H4LOW >>> 8); target[targetOffset++] = (byte)(H4HIGH); target[targetOffset++] = (byte)(H4HIGH >>> 8);
    }
    private static final short[] R = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13 };
    private static final short[] Rp = {
         5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
         6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
         8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11 };
    private static final short[] S = {
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
         7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
         9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6 };
    private static final short[] Sp = {
         8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
         9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
         9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
         8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11 };
    private static final short[] mask = {
        (short)0x0000, (short)0x0001, (short)0x0003, (short)0x0007,
        (short)0x000F, (short)0x001F, (short)0x003F, (short)0x007F,
        (short)0x00FF, (short)0x01FF, (short)0x03FF, (short)0x07FF,
        (short)0x0FFF, (short)0x1FFF, (short)0x3FFF, (short)0x7FFF,
    };
}
