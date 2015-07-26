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

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import junit.framework.TestCase;
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.licel.jcardsim.utils.ByteUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import com.ledger.wallet.LedgerWalletApplet;
import com.btchip.BTChipDongle;
import com.btchip.BTChipConstants;
import com.btchip.BTChipException;
import com.btchip.BitcoinTransaction;

public class TestTransaction extends AbstractTest {

	// fcabbad3a52ba1274c9a5e41f15df84cc79d1116499a2284025df0ff3737160d	
	public static final byte[] TXIN_1 = ByteUtil.byteArray("01000000011ce6fa2f5f4d49355821803039fcce4e3e3f7d0b448244222d98e38041637c73000000006a47304402202301a4e34c2e482624b89152ded4fe7624c4d0ff8627c5b8d03049812fd4559f0220531e00d2b004a3dcd0f4e8e57649ee6cddd269bb6c23972182b38c11d4cf910f012103f6e22ad16597a679f53b47f02a2473e0f4ed1c2c1dfe5b9c9115d54b94c37c41ffffffff022fc8a900000000001976a914bb42f9f29403fe18be77d5c71e1a7b11fb7933f988ace0930400000000001976a91442e73e3c17fadf8d5547d5ed07897cf7385302ef88ac00000000");
	// 2da2361a2034615bd7788dd608f72ac2262f2ee0b764be2e301729be81d3cfa4
	public static final byte[] TXOUT_1 = ByteUtil.byteArray("01000000010d163737fff05d0284229a4916119dc74cf85df1415e9a4c27a12ba5d3baabfc010000006b483045022100f2008bfb170266905f7de00390fa4bce4ad1bba4694a4a4bff8e57b90abdcc9b02202bf77725e58d59f52d848897ef9fb5769c39a5a434725b06e2b7642a7d55a63d01210372fd24bfbaa0017c61a56706f26782507a94233a65d83694aaab3ed5fefad0caffffffff01222b0400000000001976a914e585fe65b9beb6937fbd1d0b386966451417978d88ac00000000");
	private static final String TXOUT_1_ADDRESS = "n2SZZ2n1dgnCEJYEJ6TDfKvt9tnRF7LNxf";

	// 482cb7d6377332684c53fc7ce1ef8dffeb5666dae97a0053b640524a8db67f5c
	public static final byte[] TXIN_2_1 = ByteUtil.byteArray("01000000019a3882d438d24e3ad7fe98180a952c2e8fea8acd86172d967b43659385b39bfd010000006b48304502210091b7b32d220102d9d5bd385d3fd6b957fdb902daca4fe398e0688b157860379a02202f2f148d9d0424c741bfb3dc89a6e3d32beb026153332cb72864d7d55d47220f0121024d1b2529fe22c463844e9c88f6b7ccb8f7fa6601862d58c5eb6dbad62beee0aaffffffff024f316101000000001976a914a7896ab8c92668021db756cba95795ec9c9bbe7088ac801a0600000000001976a91464d521453272dbd156fcf7844385748198dda27b88ac00000000");
	// d26f11f27e5bfeca12e157b0e9f7c97b0a0f163a29e79ec406ba123f2174a871
	public static final byte[] TXIN_2_2 = ByteUtil.byteArray("01000000022ce66cbc0f14cd91c4967fa7a3acb1214d32b9da0ed3fb9e862b7733b7791de6000000006b483045022100e614f109e23f78ae27abaa5188d325a8a5cdc8a9724d11a42b5362f7a1c4181d02204518d7a9e96b9e3ddce99a2ec80d2ad05ff04221f20332479d7c800ecceb10b80121026f2f5cf851d6cb1df93dc33df5d306ae1a1cd4f3dca1b9c34b8f3864db20c280ffffffffb8801068b6bbd0d157898211699d47c9de12a71c42e4863fabc06d8786f10ca6000000006b483045022100935d3f81f7c814b2e34203e821f682a6de61fae03b229d4f6631edd2c08487e302202d0740a90b9120b0fa344b8f581fc003033a50ccb66f3a7ace7c3fe5b5e4b9c60121021f5ccdbf1254e2f10052bdf0374554e7abc7e3214e951279cb1ff799c79ae709ffffffff02e0930400000000001976a91464d521453272dbd156fcf7844385748198dda27b88ac2b6d0300000000001976a914d4dd045ef4e98a28264301b463c57dd3106f565788ac00000000");
	// b3b45c8768ca708f87696d08be6f17cb1199a603870287bb59ab8ca9903086c2
	public static final byte[] TXOUT_2 = ByteUtil.byteArray("01000000025c7fb68d4a5240b653007ae9da6656ebff8defe17cfc534c68327337d6b72c48010000006a47304402205a5df97d31199317b6c26bac71942101236c5ab49b6ea19566fe775a5003c88e02207b976e7e19800fe3c26fb4e6e57015d3c395383e90b0b95082e2055d12c0a1b50121035ff80a17dbc573406c653718fb16c7400c43d6d07886ed37da0a0c30ade31179ffffffff71a874213f12ba06c49ee7293a160f0a7bc9f7e9b057e112cafe5b7ef2116fd2000000006a47304402200d50aa47541f30dcc47370916560114f0fe4b437f6e58c89af91254e970f8c1802202673babd4a920e72644294b53a4eebf293d771555f6d953109340bb5435473470121035ff80a17dbc573406c653718fb16c7400c43d6d07886ed37da0a0c30ade31179ffffffff0282a40200000000001976a914538abe38a9744c03dcc8122b787d976ab9f7a90c88ac20a10700000000001976a914643a30d6e2a664b11bee6f07471658d58f91ad4288ac00000000");
	public static final String TXOUT_2_ADDRESS = "mpeuaQLpsGey3UbQ1xupe5FEwRMfCNMLh5";

	// 7764aef5620cbe5fb4d95377c668e365affc43fa1878d881175ca00d82193ff1
	public static final byte[] TXIN_3 = ByteUtil.byteArray("01000000016c9bd18d376d47995edbc623e4d57dfa6677e52ee72f3ff620a00b26d1372d81010000006a473044022025a3832dc0fbfbc7432146238339c35a39707cc7c5c2e5267e089976550b480702205734a02fb2b9490e365fd5d05e6367c2f0b032a8d43ee6eaf256570b21c571f90121024be65fee9e15a9d264516abe811286b0cf5107d72a2155f07978cae7af7f141bffffffff02801a06000000000017a914296d13ce7f304a815307cac4b2bb5830d5b019a2874bad2f00000000001976a91430a40bb2280255f92bea4f65c2ff9c408cfe906788ac00000000");
	// 2dd0a8212e873222be1eb83da020cb3febd3cd12a0449af85e4b16b1614b8621
	public static final byte[] TXOUT_3 = ByteUtil.byteArray("0100000001f13f19820da05c1781d87818fa43fcaf65e368c67753d9b45fbe0c62f5ae647700000000da0048304502210094e6ba564ee8dfda62fa97053142b9a71605b7d81a1badb3a3944cb1cb1540db02207bbace366553c76d9d33bdb4332a7daf8ba503ac0fe01437ca9d1f5069a10aa60147304402203d8c3803c4289e05a48350e5c107b591fc8e2f35504ccb25c7a3e0a22272c2f40220238454e6e70f355e66963e70feaafc8230637e10efc750310336353e347aaf170147522102a3cf97be30a15eede7165963e710207f989ec9d7cb717b44e03b6912b80ad7b22103a23b107c301f7bd4870453dda3dd86758693629690702832d3fae22cdd4df3cf52aeffffffff02905f01000000000017a91479b277f534a02f50fc7891d831460dd87c3aa4b187e0930400000000001976a9143b3c2312df153aeac34f19944fec0b5f2ec4e5d088ac00000000");
	public static final byte[] TXIN_3_REDEEM_SCRIPT = ByteUtil.byteArray("522102a3cf97be30a15eede7165963e710207f989ec9d7cb717b44e03b6912b80ad7b22103a23b107c301f7bd4870453dda3dd86758693629690702832d3fae22cdd4df3cf52ae");

	public static String EXPECTED_ADDRESS_1 = "n4CYzppnrJViRcUrezwcSdwwGERAcHScQZ";
	public static byte[] EXPECTED_PUBLIC_KEY_1 = ByteUtil.byteArray("04a44e52606aaafa575c3d9c2d09819ce885ab4066bb7d1e8d61acae24986ab4579b9fb5742b49fa3dcf508242ba31f01ee889072159cd6aff27048d7ba4e9e3f0");
	public static byte[] EXPECTED_CHAINCODE_1 = ByteUtil.byteArray("80ecfe04ceeabc5745b0eeeb5b5f36d0f40119e18c865cf8d5a407bcb6e8b88c");

	public void testTX1ContactlessSticky() throws BTChipException {
		KeycardHelper keycardHelper = new KeycardHelper(DEFAULT_KEYCARD);
		BTChipDongle dongle = prepareDongleRestoreTestnet(true);
		simulator.changeProtocol("T=CL,TYPE_A,T1");
		dongle.verifyPin(DEFAULT_PIN);
		BitcoinTransaction txin_1 = new BitcoinTransaction(new ByteArrayInputStream(TXIN_1));
		BitcoinTransaction txout_1 = new BitcoinTransaction(new ByteArrayInputStream(TXOUT_1));
		BTChipDongle.BTChipInput input1 = dongle.getTrustedInput(txin_1, 1);
		dongle.startUntrustedTransaction(
			true, 
			0, 
			new BTChipDongle.BTChipInput[] { input1 }, 
			txin_1.getOutputs().get(1).getScript());
		BTChipDongle.BTChipOutput output = dongle.finalizeInputFull(txout_1.serializeOutputs());		
		assertEquals(output.getUserConfirmation(), BTChipDongle.UserConfirmation.KEYCARD);		
		// Keycard validation is done while still in the field
		byte[] keycardIndexes = ((BTChipDongle.BTChipOutputKeycard)output).getKeycardIndexes();
		assertEquals(keycardIndexes.length, DEFAULT_KEYCARD_ADDRESS_SIZE);
		byte[] pin = keycardHelper.getPIN(TXOUT_1_ADDRESS, keycardIndexes);
		byte[] signature = dongle.untrustedHashSign("44'/0'/0'/0/0", pin);
		signature = canonicalizeSignature(signature);
		byte[] originalSignature = Arrays.copyOfRange(txout_1.getInputs().get(0).getScript(), 1, 1 + signature.length);		
		assertTrue(Arrays.equals(signature, originalSignature));
	}

	public void testTX1ContactlessNoPIN() throws BTChipException {
		KeycardHelper keycardHelper = new KeycardHelper(DEFAULT_KEYCARD);
		BTChipDongle dongle = prepareDongleRestoreTestnet(true);
		simulator.changeProtocol("T=CL,TYPE_A,T1");
		BitcoinTransaction txin_1 = new BitcoinTransaction(new ByteArrayInputStream(TXIN_1));
		BitcoinTransaction txout_1 = new BitcoinTransaction(new ByteArrayInputStream(TXOUT_1));
		BTChipDongle.BTChipInput input1 = dongle.getTrustedInput(txin_1, 1);
		try {
			dongle.startUntrustedTransaction(
				true, 
				0, 
				new BTChipDongle.BTChipInput[] { input1 }, 
				txin_1.getOutputs().get(1).getScript());
			fail();
		}
		catch(BTChipException e) {
			assertEquals(e.getSW(), ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}		
	}

	public void testTX1ContactlessUntrustedInput() throws BTChipException {
		KeycardHelper keycardHelper = new KeycardHelper(DEFAULT_KEYCARD);
		BTChipDongle dongle = prepareDongleRestoreTestnet(true);
		simulator.changeProtocol("T=CL,TYPE_A,T1");
		dongle.verifyPin(DEFAULT_PIN);
		BitcoinTransaction txin_1 = new BitcoinTransaction(new ByteArrayInputStream(TXIN_1));
		BitcoinTransaction txout_1 = new BitcoinTransaction(new ByteArrayInputStream(TXOUT_1));
		BTChipDongle.BTChipInput input1 = dongle.getTrustedInput(txin_1, 1);
		byte[] prevout = Arrays.copyOfRange(input1.getValue(), 4, 4 + 36);
		input1 = new BTChipDongle.BTChipInput(prevout, false);
		try {
			dongle.startUntrustedTransaction(
				true, 
				0, 
				new BTChipDongle.BTChipInput[] { input1 }, 
				txin_1.getOutputs().get(1).getScript());
			fail();
		}
		catch(BTChipException e) {
			assertEquals(e.getSW(), ISO7816.SW_WRONG_DATA);
		}		
	}

	public void testTX1ContactlessDisconnect() throws BTChipException {
		KeycardHelper keycardHelper = new KeycardHelper(DEFAULT_KEYCARD);
		BTChipDongle dongle = prepareDongleRestoreTestnet(true);
		simulator.changeProtocol("T=CL,TYPE_A,T1");
		dongle.verifyPin(DEFAULT_PIN);
		BitcoinTransaction txin_1 = new BitcoinTransaction(new ByteArrayInputStream(TXIN_1));
		BitcoinTransaction txout_1 = new BitcoinTransaction(new ByteArrayInputStream(TXOUT_1));
		BTChipDongle.BTChipInput input1 = dongle.getTrustedInput(txin_1, 1);
		dongle.startUntrustedTransaction(
			true, 
			0, 
			new BTChipDongle.BTChipInput[] { input1 }, 
			txin_1.getOutputs().get(1).getScript());
		BTChipDongle.BTChipOutput output = dongle.finalizeInputFull(txout_1.serializeOutputs());		
		assertEquals(output.getUserConfirmation(), BTChipDongle.UserConfirmation.KEYCARD);		
		reset();
		// Card is removed from the field
		byte[] keycardIndexes = ((BTChipDongle.BTChipOutputKeycard)output).getKeycardIndexes();
		assertEquals(keycardIndexes.length, DEFAULT_KEYCARD_ADDRESS_SIZE);
		byte[] pin = keycardHelper.getPIN(TXOUT_1_ADDRESS, keycardIndexes);
		byte[] signature = null;
		try {
			dongle.untrustedHashSign("44'/0'/0'/0/0", pin);
			fail();
		}
		catch(BTChipException e) {
			assertEquals(e.getSW(), ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
	}

	public void testTX1ContactlessDisconnectReconnect() throws BTChipException {
		KeycardHelper keycardHelper = new KeycardHelper(DEFAULT_KEYCARD);
		BTChipDongle dongle = prepareDongleRestoreTestnet(true);
		simulator.changeProtocol("T=CL,TYPE_A,T1");
		dongle.verifyPin(DEFAULT_PIN);
		BitcoinTransaction txin_1 = new BitcoinTransaction(new ByteArrayInputStream(TXIN_1));
		BitcoinTransaction txout_1 = new BitcoinTransaction(new ByteArrayInputStream(TXOUT_1));
		BTChipDongle.BTChipInput input1 = dongle.getTrustedInput(txin_1, 1);
		dongle.startUntrustedTransaction(
			true, 
			0, 
			new BTChipDongle.BTChipInput[] { input1 }, 
			txin_1.getOutputs().get(1).getScript());
		BTChipDongle.BTChipOutput output = dongle.finalizeInputFull(txout_1.serializeOutputs());		
		assertEquals(output.getUserConfirmation(), BTChipDongle.UserConfirmation.KEYCARD);		
		reset();
		// Card is removed from the field
		byte[] keycardIndexes = ((BTChipDongle.BTChipOutputKeycard)output).getKeycardIndexes();
		assertEquals(keycardIndexes.length, DEFAULT_KEYCARD_ADDRESS_SIZE);
		byte[] pin = keycardHelper.getPIN(TXOUT_1_ADDRESS, keycardIndexes);
		// Reinitialize the transient parser
		dongle.startUntrustedTransaction(
			false, 
			0, 
			new BTChipDongle.BTChipInput[] { input1 }, 
			txin_1.getOutputs().get(1).getScript());
		dongle.finalizeInputFull(txout_1.serializeOutputs());		
		byte[] signature = dongle.untrustedHashSign("44'/0'/0'/0/0", pin);
		signature = canonicalizeSignature(signature);
		byte[] originalSignature = Arrays.copyOfRange(txout_1.getInputs().get(0).getScript(), 1, 1 + signature.length);		
		assertTrue(Arrays.equals(signature, originalSignature));
	}

	public void testTX1ContactlessDisconnectReconnectFakeOutputAmount() throws BTChipException {
		KeycardHelper keycardHelper = new KeycardHelper(DEFAULT_KEYCARD);
		BTChipDongle dongle = prepareDongleRestoreTestnet(true);
		simulator.changeProtocol("T=CL,TYPE_A,T1");
		dongle.verifyPin(DEFAULT_PIN);
		BitcoinTransaction txin_1 = new BitcoinTransaction(new ByteArrayInputStream(TXIN_1));
		BitcoinTransaction txout_1 = new BitcoinTransaction(new ByteArrayInputStream(TXOUT_1));
		BTChipDongle.BTChipInput input1 = dongle.getTrustedInput(txin_1, 1);
		dongle.startUntrustedTransaction(
			true, 
			0, 
			new BTChipDongle.BTChipInput[] { input1 }, 
			txin_1.getOutputs().get(1).getScript());
		BTChipDongle.BTChipOutput output = dongle.finalizeInputFull(txout_1.serializeOutputs());		
		assertEquals(output.getUserConfirmation(), BTChipDongle.UserConfirmation.KEYCARD);		
		reset();
		// Card is removed from the field
		byte[] keycardIndexes = ((BTChipDongle.BTChipOutputKeycard)output).getKeycardIndexes();
		assertEquals(keycardIndexes.length, DEFAULT_KEYCARD_ADDRESS_SIZE);
		byte[] pin = keycardHelper.getPIN(TXOUT_1_ADDRESS, keycardIndexes);
		// Reinitialize the transient parser
		dongle.startUntrustedTransaction(
			false, 
			0, 
			new BTChipDongle.BTChipInput[] { input1 }, 
			txin_1.getOutputs().get(1).getScript());
		byte[] fullOutput = txout_1.serializeOutputs();
		fullOutput[4]++;
		try {
			dongle.finalizeInputFull(fullOutput);		
			fail();
		}
		catch(BTChipException e) {
			assertEquals(e.getSW(), ISO7816.SW_WRONG_DATA);
		}		
	}

	public void testTX1ContactlessDisconnectReconnectFakeOutputDestination() throws BTChipException {
		KeycardHelper keycardHelper = new KeycardHelper(DEFAULT_KEYCARD);
		BTChipDongle dongle = prepareDongleRestoreTestnet(true);
		simulator.changeProtocol("T=CL,TYPE_A,T1");
		dongle.verifyPin(DEFAULT_PIN);
		BitcoinTransaction txin_1 = new BitcoinTransaction(new ByteArrayInputStream(TXIN_1));
		BitcoinTransaction txout_1 = new BitcoinTransaction(new ByteArrayInputStream(TXOUT_1));
		BTChipDongle.BTChipInput input1 = dongle.getTrustedInput(txin_1, 1);
		dongle.startUntrustedTransaction(
			true, 
			0, 
			new BTChipDongle.BTChipInput[] { input1 }, 
			txin_1.getOutputs().get(1).getScript());
		BTChipDongle.BTChipOutput output = dongle.finalizeInputFull(txout_1.serializeOutputs());		
		assertEquals(output.getUserConfirmation(), BTChipDongle.UserConfirmation.KEYCARD);		
		reset();
		// Card is removed from the field
		byte[] keycardIndexes = ((BTChipDongle.BTChipOutputKeycard)output).getKeycardIndexes();
		assertEquals(keycardIndexes.length, DEFAULT_KEYCARD_ADDRESS_SIZE);
		byte[] pin = keycardHelper.getPIN(TXOUT_1_ADDRESS, keycardIndexes);
		// Reinitialize the transient parser
		dongle.startUntrustedTransaction(
			false, 
			0, 
			new BTChipDongle.BTChipInput[] { input1 }, 
			txin_1.getOutputs().get(1).getScript());
		byte[] fullOutput = txout_1.serializeOutputs();
		fullOutput[fullOutput.length - 5] ^= (byte)0x42;
		try {
			dongle.finalizeInputFull(fullOutput);		
			fail();
		}
		catch(BTChipException e) {
			assertEquals(e.getSW(), ISO7816.SW_WRONG_DATA);
		}		
	}

	public void testTX2ContactlessSticky() throws BTChipException {
		KeycardHelper keycardHelper = new KeycardHelper(DEFAULT_KEYCARD);
		BTChipDongle dongle = prepareDongleRestoreTestnet(true);
		simulator.changeProtocol("T=CL,TYPE_A,T1");
		dongle.verifyPin(DEFAULT_PIN);
		BitcoinTransaction txin_1 = new BitcoinTransaction(new ByteArrayInputStream(TXIN_2_1));
		BitcoinTransaction txin_2 = new BitcoinTransaction(new ByteArrayInputStream(TXIN_2_2));
		BitcoinTransaction txout_1 = new BitcoinTransaction(new ByteArrayInputStream(TXOUT_2));
		BTChipDongle.BTChipInput input1 = dongle.getTrustedInput(txin_1, 1);
		BTChipDongle.BTChipInput input2 = dongle.getTrustedInput(txin_2, 0);
		dongle.startUntrustedTransaction(
			true, 
			0, 
			new BTChipDongle.BTChipInput[] { input1, input2 }, 
			txin_1.getOutputs().get(1).getScript());
		BTChipDongle.BTChipOutput output = dongle.finalizeInputFull(txout_1.serializeOutputs(), "44'/0'/0'/1/0");		
		assertEquals(output.getUserConfirmation(), BTChipDongle.UserConfirmation.KEYCARD);		
		// Keycard validation is done while still in the field
		byte[] keycardIndexes = ((BTChipDongle.BTChipOutputKeycard)output).getKeycardIndexes();
		assertEquals(keycardIndexes.length, DEFAULT_KEYCARD_ADDRESS_SIZE);
		byte[] pin = keycardHelper.getPIN(TXOUT_2_ADDRESS, keycardIndexes);
		byte[] signature = dongle.untrustedHashSign("44'/0'/0'/0/1", pin);
		signature = canonicalizeSignature(signature);
		byte[] originalSignature = Arrays.copyOfRange(txout_1.getInputs().get(0).getScript(), 1, 1 + signature.length);				
		assertTrue(Arrays.equals(signature, originalSignature));
		// Process second input
		dongle.startUntrustedTransaction(
			false, 
			1, 
			new BTChipDongle.BTChipInput[] { input1, input2 }, 
			txin_2.getOutputs().get(0).getScript());
		dongle.finalizeInputFull(txout_1.serializeOutputs(), "44'/0'/0'/1/0");
		signature = dongle.untrustedHashSign("44'/0'/0'/0/1", pin);
		signature = canonicalizeSignature(signature);
		originalSignature = Arrays.copyOfRange(txout_1.getInputs().get(1).getScript(), 1, 1 + signature.length);				
		assertTrue(Arrays.equals(signature, originalSignature));
	}

	public void testTX2ContactlessDisconnect() throws BTChipException {
		KeycardHelper keycardHelper = new KeycardHelper(DEFAULT_KEYCARD);
		BTChipDongle dongle = prepareDongleRestoreTestnet(true);
		simulator.changeProtocol("T=CL,TYPE_A,T1");
		dongle.verifyPin(DEFAULT_PIN);
		BitcoinTransaction txin_1 = new BitcoinTransaction(new ByteArrayInputStream(TXIN_2_1));
		BitcoinTransaction txin_2 = new BitcoinTransaction(new ByteArrayInputStream(TXIN_2_2));
		BitcoinTransaction txout_1 = new BitcoinTransaction(new ByteArrayInputStream(TXOUT_2));
		BTChipDongle.BTChipInput input1 = dongle.getTrustedInput(txin_1, 1);
		BTChipDongle.BTChipInput input2 = dongle.getTrustedInput(txin_2, 0);
		dongle.startUntrustedTransaction(
			true, 
			0, 
			new BTChipDongle.BTChipInput[] { input1, input2 }, 
			txin_1.getOutputs().get(1).getScript());
		BTChipDongle.BTChipOutput output = dongle.finalizeInputFull(txout_1.serializeOutputs(), "44'/0'/0'/1/0");		
		assertEquals(output.getUserConfirmation(), BTChipDongle.UserConfirmation.KEYCARD);		
		byte[] keycardIndexes = ((BTChipDongle.BTChipOutputKeycard)output).getKeycardIndexes();
		assertEquals(keycardIndexes.length, DEFAULT_KEYCARD_ADDRESS_SIZE);
		reset();
		// Card is removed from the field		
		byte[] pin = keycardHelper.getPIN(TXOUT_2_ADDRESS, keycardIndexes);
		try {
			dongle.untrustedHashSign("44'/0'/0'/0/1", pin);
			fail();
		}
		catch(BTChipException e) {
			assertEquals(e.getSW(), ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
	}

	public void testTX2ContactlessDisconnectReconnect() throws BTChipException {
		KeycardHelper keycardHelper = new KeycardHelper(DEFAULT_KEYCARD);
		BTChipDongle dongle = prepareDongleRestoreTestnet(true);
		simulator.changeProtocol("T=CL,TYPE_A,T1");
		dongle.verifyPin(DEFAULT_PIN);
		BitcoinTransaction txin_1 = new BitcoinTransaction(new ByteArrayInputStream(TXIN_2_1));
		BitcoinTransaction txin_2 = new BitcoinTransaction(new ByteArrayInputStream(TXIN_2_2));
		BitcoinTransaction txout_1 = new BitcoinTransaction(new ByteArrayInputStream(TXOUT_2));
		BTChipDongle.BTChipInput input1 = dongle.getTrustedInput(txin_1, 1);
		BTChipDongle.BTChipInput input2 = dongle.getTrustedInput(txin_2, 0);
		dongle.startUntrustedTransaction(
			true, 
			0, 
			new BTChipDongle.BTChipInput[] { input1, input2 }, 
			txin_1.getOutputs().get(1).getScript());
		BTChipDongle.BTChipOutput output = dongle.finalizeInputFull(txout_1.serializeOutputs(), "44'/0'/0'/1/0");		
		assertEquals(output.getUserConfirmation(), BTChipDongle.UserConfirmation.KEYCARD);		
		// Keycard validation is done while still in the field
		byte[] keycardIndexes = ((BTChipDongle.BTChipOutputKeycard)output).getKeycardIndexes();
		assertEquals(keycardIndexes.length, DEFAULT_KEYCARD_ADDRESS_SIZE);
		reset();
		// Card is removed from the field		
		// Reinitialize the transient parser
		dongle.startUntrustedTransaction(
			false, 
			0, 
			new BTChipDongle.BTChipInput[] { input1, input2 }, 
			txin_1.getOutputs().get(1).getScript());
		dongle.finalizeInputFull(txout_1.serializeOutputs(), "44'/0'/0'/1/0");						
		byte[] pin = keycardHelper.getPIN(TXOUT_2_ADDRESS, keycardIndexes);
		byte[] signature = dongle.untrustedHashSign("44'/0'/0'/0/1", pin);
		signature = canonicalizeSignature(signature);
		byte[] originalSignature = Arrays.copyOfRange(txout_1.getInputs().get(0).getScript(), 1, 1 + signature.length);				
		assertTrue(Arrays.equals(signature, originalSignature));
		// Process second input
		dongle.startUntrustedTransaction(
			false, 
			1, 
			new BTChipDongle.BTChipInput[] { input1, input2 }, 
			txin_2.getOutputs().get(0).getScript());
		dongle.finalizeInputFull(txout_1.serializeOutputs(), "44'/0'/0'/1/0");
		signature = dongle.untrustedHashSign("44'/0'/0'/0/1", pin);
		signature = canonicalizeSignature(signature);
		originalSignature = Arrays.copyOfRange(txout_1.getInputs().get(1).getScript(), 1, 1 + signature.length);				
		assertTrue(Arrays.equals(signature, originalSignature));
	}

	public void testTX2ContactlessDisconnectReconnectSwap() throws BTChipException {
		KeycardHelper keycardHelper = new KeycardHelper(DEFAULT_KEYCARD);
		BTChipDongle dongle = prepareDongleRestoreTestnet(true);
		simulator.changeProtocol("T=CL,TYPE_A,T1");
		dongle.verifyPin(DEFAULT_PIN);
		BitcoinTransaction txin_1 = new BitcoinTransaction(new ByteArrayInputStream(TXIN_2_1));
		BitcoinTransaction txin_2 = new BitcoinTransaction(new ByteArrayInputStream(TXIN_2_2));
		BitcoinTransaction txout_1 = new BitcoinTransaction(new ByteArrayInputStream(TXOUT_2));
		BTChipDongle.BTChipInput input1 = dongle.getTrustedInput(txin_1, 1);
		BTChipDongle.BTChipInput input2 = dongle.getTrustedInput(txin_2, 0);
		dongle.startUntrustedTransaction(
			true, 
			0, 
			new BTChipDongle.BTChipInput[] { input1, input2 }, 
			txin_1.getOutputs().get(1).getScript());
		BTChipDongle.BTChipOutput output = dongle.finalizeInputFull(txout_1.serializeOutputs(), "44'/0'/0'/1/0");		
		assertEquals(output.getUserConfirmation(), BTChipDongle.UserConfirmation.KEYCARD);		
		// Keycard validation is done while still in the field
		byte[] keycardIndexes = ((BTChipDongle.BTChipOutputKeycard)output).getKeycardIndexes();
		assertEquals(keycardIndexes.length, DEFAULT_KEYCARD_ADDRESS_SIZE);
		reset();
		// Card is removed from the field		
		// Reinitialize the transient parser
		dongle.startUntrustedTransaction(
			false, 
			0, 
			new BTChipDongle.BTChipInput[] { input2, input1 }, 
			txin_2.getOutputs().get(0).getScript());
		try {
			dongle.finalizeInputFull(txout_1.serializeOutputs(), "44'/0'/0'/1/0");						
			fail();
		}
		catch(BTChipException e) {
			assertEquals(e.getSW(), ISO7816.SW_WRONG_DATA);
		}				
	}

	public void testTX2ContactlessNoChange() throws BTChipException {
		KeycardHelper keycardHelper = new KeycardHelper(DEFAULT_KEYCARD);
		BTChipDongle dongle = prepareDongleRestoreTestnet(true);
		simulator.changeProtocol("T=CL,TYPE_A,T1");
		dongle.verifyPin(DEFAULT_PIN);
		BitcoinTransaction txin_1 = new BitcoinTransaction(new ByteArrayInputStream(TXIN_2_1));
		BitcoinTransaction txin_2 = new BitcoinTransaction(new ByteArrayInputStream(TXIN_2_2));
		BitcoinTransaction txout_1 = new BitcoinTransaction(new ByteArrayInputStream(TXOUT_2));
		BTChipDongle.BTChipInput input1 = dongle.getTrustedInput(txin_1, 1);
		BTChipDongle.BTChipInput input2 = dongle.getTrustedInput(txin_2, 0);
		dongle.startUntrustedTransaction(
			true, 
			0, 
			new BTChipDongle.BTChipInput[] { input1, input2 }, 
			txin_1.getOutputs().get(1).getScript());
		try {
			dongle.finalizeInputFull(txout_1.serializeOutputs());		
			fail();
		}
		catch(BTChipException e) {
			assertEquals(e.getSW(), ISO7816.SW_WRONG_DATA);
		}				
	}

	public void testTX2ContactlessWrongChange() throws BTChipException {
		KeycardHelper keycardHelper = new KeycardHelper(DEFAULT_KEYCARD);
		BTChipDongle dongle = prepareDongleRestoreTestnet(true);
		simulator.changeProtocol("T=CL,TYPE_A,T1");
		dongle.verifyPin(DEFAULT_PIN);
		BitcoinTransaction txin_1 = new BitcoinTransaction(new ByteArrayInputStream(TXIN_2_1));
		BitcoinTransaction txin_2 = new BitcoinTransaction(new ByteArrayInputStream(TXIN_2_2));
		BitcoinTransaction txout_1 = new BitcoinTransaction(new ByteArrayInputStream(TXOUT_2));
		BTChipDongle.BTChipInput input1 = dongle.getTrustedInput(txin_1, 1);
		BTChipDongle.BTChipInput input2 = dongle.getTrustedInput(txin_2, 0);
		dongle.startUntrustedTransaction(
			true, 
			0, 
			new BTChipDongle.BTChipInput[] { input1, input2 }, 
			txin_1.getOutputs().get(1).getScript());
		try {
			dongle.finalizeInputFull(txout_1.serializeOutputs(), "44'/0'/0'/1/1");		
			fail();
		}
		catch(BTChipException e) {
			assertEquals(e.getSW(), ISO7816.SW_WRONG_DATA);
		}				
	}

	public void testTX3Contactless() throws BTChipException {
		KeycardHelper keycardHelper = new KeycardHelper(DEFAULT_KEYCARD);
		BTChipDongle dongle = prepareDongleRestoreTestnet(true);
		simulator.changeProtocol("T=CL,TYPE_A,T1");
		dongle.verifyPin(DEFAULT_PIN);
		BitcoinTransaction txin_1 = new BitcoinTransaction(new ByteArrayInputStream(TXIN_3));
		BitcoinTransaction txout_1 = new BitcoinTransaction(new ByteArrayInputStream(TXOUT_3));		
		BTChipDongle.BTChipInput input1 = dongle.getTrustedInput(txin_1, 0);
		byte[] prevout = Arrays.copyOfRange(input1.getValue(), 4, 4 + 36);
		input1 = new BTChipDongle.BTChipInput(prevout, false);
		dongle.startUntrustedTransaction(
			true, 
			0, 
			new BTChipDongle.BTChipInput[] { input1 }, 
			TXIN_3_REDEEM_SCRIPT);
		BTChipDongle.BTChipOutput output = dongle.finalizeInputFull(txout_1.serializeOutputs());		
		assertEquals(output.getUserConfirmation(), BTChipDongle.UserConfirmation.NONE);		
		byte[] signature = dongle.untrustedHashSign("45'/2147483647/0/0", new byte[0]);
		signature = canonicalizeSignature(signature);
		byte[] originalSignature = Arrays.copyOfRange(txout_1.getInputs().get(0).getScript(), 2, 2 + signature.length);				
		assertTrue(Arrays.equals(signature, originalSignature));
	}
}
