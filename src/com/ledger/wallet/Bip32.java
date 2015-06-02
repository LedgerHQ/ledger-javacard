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

import javacard.framework.Util;
import javacard.security.Signature;

public class Bip32 {
	
	protected static final short OFFSET_DERIVATION_INDEX = (short)64;
	
	private static final byte BITCOIN_SEED[] = {
		'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd'
	};		
	
	private static final short OFFSET_TMP = (short)100;	
	private static final short OFFSET_BLOCK = (short)127;
	    
    // seed : scratch, offset 0 -> result in masterDerived 
	// depending on the implementation, if a native transient HMAC is used, the key size might be fixed
	// on the first call
	// if that's the case, power cycle / deselect between initial seed derivation and all other key derivations
	public static void deriveSeed(byte seedLength) {
		if (Crypto.signatureHmac != null) {
			Crypto.keyHmac.setKey(BITCOIN_SEED, (short)0, (short)BITCOIN_SEED.length);
			if ((LedgerWalletApplet.proprietaryAPI != null) && (LedgerWalletApplet.proprietaryAPI.hasHmacSHA512())) {
				LedgerWalletApplet.proprietaryAPI.hmacSHA512(Crypto.keyHmac, LedgerWalletApplet.scratch256, (short)0, seedLength, LedgerWalletApplet.masterDerived, (short)0);
			}
			else {
				Crypto.signatureHmac.init(Crypto.keyHmac, Signature.MODE_SIGN);
				Crypto.signatureHmac.sign(LedgerWalletApplet.scratch256, (short)0, seedLength, LedgerWalletApplet.masterDerived, (short)0);
			}
		}
		else {
			HmacSha512.hmac(BITCOIN_SEED, (short)0, (short)BITCOIN_SEED.length, LedgerWalletApplet.scratch256, (short)0, seedLength, LedgerWalletApplet.masterDerived, (short)0, LedgerWalletApplet.scratch256, (short)64);
		}
	}
	
	// scratch255 : 0-64 : key + chain / 64-67 : derivation index / 100-165 : tmp
	// apduBuffer : block (128, starting at 127)
	// result : scratch255 0-64
	public static boolean derive(byte[] apduBuffer) {
		boolean isZero = true;
		byte i;
		if ((LedgerWalletApplet.scratch256[OFFSET_DERIVATION_INDEX] & (byte)0x80) == 0) {
			if (LedgerWalletApplet.proprietaryAPI != null) {
				LedgerWalletApplet.proprietaryAPI.getUncompressedPublicPoint(LedgerWalletApplet.scratch256, (short)0, LedgerWalletApplet.scratch256, OFFSET_TMP);				
			}
			else {				
				if (!Bip32Cache.copyLastPublic(LedgerWalletApplet.scratch256, OFFSET_TMP)) {
					return false;
				}
			}
			AddressUtils.compressPublicKey(LedgerWalletApplet.scratch256, OFFSET_TMP);
		}
		else {
			LedgerWalletApplet.scratch256[OFFSET_TMP] = 0;
			Util.arrayCopyNonAtomic(LedgerWalletApplet.scratch256, (short)0, LedgerWalletApplet.scratch256, (short)(OFFSET_TMP + 1), (short)32);
		}
		Util.arrayCopyNonAtomic(LedgerWalletApplet.scratch256, OFFSET_DERIVATION_INDEX, LedgerWalletApplet.scratch256, (short)(OFFSET_TMP + 33), (short)4);
		if (Crypto.signatureHmac != null) {
			Crypto.keyHmac.setKey(LedgerWalletApplet.scratch256, (short)32, (short)32);
			if ((LedgerWalletApplet.proprietaryAPI != null) && (LedgerWalletApplet.proprietaryAPI.hasHmacSHA512())) {
				LedgerWalletApplet.proprietaryAPI.hmacSHA512(Crypto.keyHmac, LedgerWalletApplet.scratch256, OFFSET_TMP, (short)37, LedgerWalletApplet.scratch256, OFFSET_TMP);
			}
			else {
				Crypto.signatureHmac.init(Crypto.keyHmac, Signature.MODE_SIGN);
				Crypto.signatureHmac.sign(LedgerWalletApplet.scratch256, OFFSET_TMP, (short)37, LedgerWalletApplet.scratch256, OFFSET_TMP);
			}
		}
		else {
			HmacSha512.hmac(LedgerWalletApplet.scratch256, (short)32, (short)32, LedgerWalletApplet.scratch256, OFFSET_TMP, (short)37, LedgerWalletApplet.scratch256, OFFSET_TMP, apduBuffer, OFFSET_BLOCK);
		}
		if (MathMod256.ucmp(LedgerWalletApplet.scratch256, OFFSET_TMP, Secp256k1.SECP256K1_R, (short)0) >= 0) {
			return false;
		}
		MathMod256.addm(LedgerWalletApplet.scratch256, (short)0, LedgerWalletApplet.scratch256, OFFSET_TMP, LedgerWalletApplet.scratch256, (short)0, Secp256k1.SECP256K1_R, (short)0);
		for (i=0; i<(byte)32; i++) {
			if (LedgerWalletApplet.scratch256[i] != 0) {
				isZero = false;
				break;
			}
		}
		if (isZero) {
			return false;
		}
		Util.arrayCopyNonAtomic(LedgerWalletApplet.scratch256, (short)(OFFSET_TMP + 32), LedgerWalletApplet.scratch256, (short)32, (short)32);		
		return true;
	}

}
