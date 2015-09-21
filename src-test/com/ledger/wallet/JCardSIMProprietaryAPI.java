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

import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.Key;
import javacard.security.Signature;

public class JCardSIMProprietaryAPI implements ProprietaryAPI {
	
	private Signature signature;
	private KeyAgreement keyAgreement;
	private ECPrivateKey privateKey;
	private byte ecAlgorithm;
	
	
	public JCardSIMProprietaryAPI() {
		try {
			keyAgreement = com.licel.jcardsim.extensions.security.KeyAgreement.getInstance(com.licel.jcardsim.extensions.security.KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
			signature = com.licel.jcardsim.extensions.security.Signature.getInstance(com.licel.jcardsim.extensions.security.Signature.ALG_ECDSA_SHA_256_RFC6979, false);
		}
		catch(Exception e) {			
		}
    	try {
    		privateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_EC_FP_256, false);
    		ecAlgorithm = KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT;
    	}
    	catch(Exception e) {
    		try {
    			privateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET, KeyBuilder.LENGTH_EC_FP_256, false);
    			ecAlgorithm = KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET;
    		}
    		catch(Exception e1) {
    			try {
    				privateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
    				ecAlgorithm = KeyBuilder.TYPE_EC_FP_PRIVATE;        				
    			}
    			catch(Exception e2) {        				
    			}
    		}    			
    	}
    	if ((privateKey != null) && (ecAlgorithm == KeyBuilder.TYPE_EC_FP_PRIVATE)) {
    		Secp256k1.setCommonCurveParameters(privateKey);
    	}		
	}

	@Override
	public boolean getUncompressedPublicPoint(byte[] privateKey,
			short privateKeyOffset, byte[] publicPoint, short publicPointOffset) {
		if ((privateKey != null) && (keyAgreement != null)) {
			try {
				if (ecAlgorithm != KeyBuilder.TYPE_EC_FP_PRIVATE) {
					Secp256k1.setCommonCurveParameters(this.privateKey);
				}
				this.privateKey.setS(privateKey, privateKeyOffset, (short)32);
				keyAgreement.init(this.privateKey);
				keyAgreement.generateSecret(Secp256k1.SECP256K1_G, (short)0, (short)Secp256k1.SECP256K1_G.length, publicPoint, publicPointOffset);
				return true;
			}
			catch(Exception e) {
				return false;
			}
		}
		else {		
			return false;
		}
	}

	@Override
	public boolean hasHmacSHA512() {
		return false;
	}


	@Override
	public void hmacSHA512(Key key, byte[] in, short inBuffer, short inLength, byte[] out, short outOffset) {
	}

	@Override
	public boolean hasDeterministicECDSASHA256() {
		return true;
	}	

	@Override
	public void signDeterministicECDSASHA256(Key key, byte[] in, short inBuffer, short inLength, byte[] out, short outOffset) {		
        signature.init(key, Signature.MODE_SIGN);
        signature.sign(in, inBuffer, inLength, out, outOffset);				
	}
}
