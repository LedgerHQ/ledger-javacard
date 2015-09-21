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

import java.math.BigInteger;
import java.util.Arrays;
import junit.framework.TestCase;
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.licel.jcardsim.utils.ByteUtil;
import com.licel.jcardsim.bouncycastle.asn1.ASN1Sequence;
import com.licel.jcardsim.bouncycastle.asn1.ASN1EncodableVector;
import com.licel.jcardsim.bouncycastle.asn1.ASN1Primitive;
import com.licel.jcardsim.bouncycastle.asn1.DERInteger;
import com.licel.jcardsim.bouncycastle.asn1.DERSequence;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import com.ledger.wallet.LedgerWalletApplet;
import com.btchip.BTChipDongle;
import com.btchip.BTChipConstants;
import com.btchip.BTChipException;


public abstract class AbstractTest extends TestCase {

	private static final BigInteger HALF_ORDER = new BigInteger(ByteUtil.byteArray("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"));
	private static final BigInteger ORDER = new BigInteger(1, ByteUtil.byteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"));

	public static final AID LOAD_FILE_AID = AIDUtil.create("FF4C4547522E57414C543031");	
	public static final byte[] INSTANCE_AID_DATA = ByteUtil.byteArray("FF4C4547522E57414C5430312E493031");
	public static final AID INSTANCE_AID = AIDUtil.create(INSTANCE_AID_DATA);

	public static final int TESTNET_VERSION = 111;
	public static final int TESTNET_P2SH_VERSION = 196;
	public static final byte[] DEFAULT_PIN = "1234".getBytes();
	// release afford clump fury license speak hungry remain crouch exile basic choose bar client own clip like armor forum fossil energy eight seven sausage
	public static final byte[] DEFAULT_SEED = ByteUtil.byteArray("d3c9b5146da60ebb8216ced62ecfc3a7dd3c7dc98f41a35e841cd5a659f0991bb7562be0d1138b2a5df2512004c8374162a2970d2a1277001f6614172e44f033");
	public static final byte DEFAULT_KEYCARD_ADDRESS_SIZE = (byte)4;	
	public static final byte[] DEFAULT_KEYCARD = ByteUtil.byteArray("f27c395759a14d3aec2135188d670d8e");

	protected Simulator simulator;

	protected Simulator prepareSimulator() {
		byte[] parameters = new byte[INSTANCE_AID_DATA.length + 3];
		parameters[0] = (byte)INSTANCE_AID_DATA.length;
		System.arraycopy(INSTANCE_AID_DATA, 0, parameters, 1, INSTANCE_AID_DATA.length);
		Simulator tmpSimulator = new Simulator();
		tmpSimulator.installApplet(LOAD_FILE_AID, LedgerWalletApplet.class, parameters, (short)0, (byte)parameters.length);
		return tmpSimulator;
	}

	protected BTChipDongle getDongle(boolean debug) throws BTChipException {
		this.simulator = prepareSimulator();
		assertTrue(simulator.selectApplet(INSTANCE_AID));		
		JCardSIMTransport transport = new JCardSIMTransport(simulator, debug);
		BTChipDongle dongle = new BTChipDongle(transport);
		dongle.setKeycardSeed(DEFAULT_KEYCARD_ADDRESS_SIZE, DEFAULT_KEYCARD);		
		return dongle;
	}

	protected BTChipDongle getDongle() throws BTChipException {
		return getDongle(false);
	}	

	protected BTChipDongle prepareDongleRestoreTestnet(boolean debug) throws BTChipException {
		BTChipDongle dongle = getDongle(debug);
		dongle.setup(
			new BTChipDongle.OperationMode[] { BTChipDongle.OperationMode.WALLET },
			new BTChipDongle.Feature[] { BTChipDongle.Feature.RFC6979, BTChipDongle.Feature.NO_2FA_P2SH},
			TESTNET_VERSION,
			TESTNET_P2SH_VERSION,
			DEFAULT_PIN,
			null,
			BTChipConstants.QWERTY_KEYMAP,
			DEFAULT_SEED,
			null);
		return dongle;
	}

	protected void reset() throws BTChipException {
		simulator.reset();
		assertTrue(simulator.selectApplet(INSTANCE_AID));		
	}

	protected byte[] canonicalizeSignature(byte[] signature) throws BTChipException {
		try {
			ASN1Sequence seq = (ASN1Sequence)ASN1Primitive.fromByteArray(signature);
			BigInteger r = ((DERInteger)seq.getObjectAt(0)).getValue();
			BigInteger s = ((DERInteger)seq.getObjectAt(1)).getValue();
			if (s.compareTo(HALF_ORDER) > 0) {
				s = ORDER.subtract(s);
			}
			else {
				return signature;
			}
 			ASN1EncodableVector v = new ASN1EncodableVector();
  			v.add(new DERInteger(r));
  			v.add(new DERInteger(s)); 
  			return new DERSequence(v).getEncoded("DER");			
		}
		catch(Exception e) {
			throw new BTChipException("Error canonicalizing signature", e);
		}
	}
}
