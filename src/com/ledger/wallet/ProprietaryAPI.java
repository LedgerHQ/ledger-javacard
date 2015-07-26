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

import javacard.security.Key;

/**
 * Implements proprietary features not present in the Java Card API or optimizations
 * @author BTChip
 *
 */
public interface ProprietaryAPI {
	
	/**
	 * Get the uncompressed public key
	 * @param privateKey buffer containing the private key
	 * @param privateKeyOffset offset to the private key in the buffer
	 * @param publicPoint buffer that will contain the uncompressed public key (65 bytes)
	 * @param publicPointOffset offset to the uncompressed public key in the buffer
	 * @return true if ok, false if an error occurred
	 */
	public boolean getUncompressedPublicPoint(byte[] privateKey, short privateKeyOffset, byte[] publicPoint, short publicPointOffset);
	/**
	 * Check if there is an optimized support for HMAC SHA512
	 * @return true if it's present, otherwise false
	 */
	public boolean hasHmacSHA512();
	/**
	 * Perform an optimized HMAC SHA512 operation
	 * @param key HMAC key object provisioned with the HMAC key
	 * @param in buffer containing the data to HMAC
	 * @param inBuffer offset to the data
	 * @param inLength length of the data
	 * @param out buffer that will contain the HMAC SHA512 result
	 * @param outOffset offset to the result
	 */
	public void hmacSHA512(Key key, byte[] in, short inBuffer, short inLength, byte[] out, short outOffset);
	/**
	 * Check if deterministic ECDSA SHA-256 signature is supported
	 * @return true if it's present, otherwise false
	 */
	public boolean hasDeterministicECDSASHA256();
	/**
	 * Perform a deterministic ECDSA SHA-256 signature
	 * Non malleability is not guaranteed and should be checked by the host
	 * (see https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#low-s-values-in-signatures)
	 * @param key Private ECC key object provisioned with the signature key
	 * @param in buffer containing the data to hash and sign
	 * @param inBuffer offset to the data
	 * @param inLength length of the data
	 * @param out buffer that will contain the signature
	 * @param outOffset offset to the signature
	 */	
	public void signDeterministicECDSASHA256(Key key, byte[] in, short inBuffer, short inLength, byte[] out, short outOffset);

}
