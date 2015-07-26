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

package com.ledger.wallet.test;

import com.licel.jcardsim.bouncycastle.crypto.engines.DESedeEngine;
import com.licel.jcardsim.bouncycastle.crypto.BufferedBlockCipher;
import com.licel.jcardsim.bouncycastle.crypto.modes.CBCBlockCipher;
import com.licel.jcardsim.bouncycastle.crypto.params.KeyParameter;

public class KeycardHelper {

	private static final int KEYCARD_SIZE = (byte)0x50;

	private byte[] keycard;

	public KeycardHelper(byte[] key) {
		BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(new DESedeEngine()));
		cipher.init(true, new KeyParameter(key));
		keycard = new byte[KEYCARD_SIZE];
		byte[] tmp = new byte[KEYCARD_SIZE];
		for (int i=0; i<KEYCARD_SIZE; i++) {
			tmp[i] = (byte)i;
		}
		int processed = cipher.processBytes(tmp, 0, KEYCARD_SIZE, keycard, 0);
		try {
			cipher.doFinal(keycard, processed);
		}
		catch(Exception e) {			
		}
		for (int i=0; i<KEYCARD_SIZE; i++) {
			keycard[i] = (byte)(((keycard[i] >> 4) & 0x0f) ^ (keycard[i] & 0x0f));			
		}

	}

	public byte[] getPIN(String address, byte[] indexes) {
		byte[] result = new byte[indexes.length];
		byte[] addressBin = address.getBytes();
		for (int i=0; i<indexes.length; i++) {
			short addressCode = (short)((short)(addressBin[indexes[i]] & 0xff) - 0x30);
			result[i] = keycard[addressCode];
			System.out.println("Checker index " + indexes[i] + " addressCode " + addressCode + " result " + result[i]);
		}
		return result;
	}

	public byte[] getKeycard() {
		return keycard;
	}

}
