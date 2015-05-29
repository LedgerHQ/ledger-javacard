package com.ledger.wallet;

public class AddressUtils {
	
	public static void compressPublicKey(byte[] buffer, short offset) {
		buffer[offset] = ((buffer[(short)(offset + 64)] & 1) != 0 ? (byte)0x03 : (byte)0x02);
	}

}
