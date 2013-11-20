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

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Applet simulating an NFC Forum Type 4 tag for the second factor validation
 * @author BTChip
 *
 */
public class BTChipNFCForumApplet extends Applet {
    
    public BTChipNFCForumApplet() {
        scratch = JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_DESELECT);
        FILE_DATA = new byte[500];
        // Header initialization
        short offset = 0;
        offset += (short)2;       
        FILE_DATA[offset++] = (byte)0xC1; // beginning of well known record, short record bit not set
        FILE_DATA[offset++] = (byte)0x01;
        FILE_DATA[offset++] = (byte)0x00; // start of 4 bytes length
        FILE_DATA[offset++] = (byte)0x00;
        offset += (short)2;
        Util.arrayCopyNonAtomic(LANG, (short)0, FILE_DATA, offset, (short)LANG.length);                        
        BTChipPocApplet.writeIdleText();   
    }
    
    public static void writeHeader(short textSize) {
        short offset = (short)0;
        Util.setShort(FILE_DATA, offset, (short)(textSize + 1 + 5 + 4 + 2 + 1)); // prefix with size of full record
        offset += (short)(2 + 4);
        Util.setShort(FILE_DATA, offset, (short)(textSize + 1 + 5)); // size of text record payload
    }
    
    @Override
    public boolean select() { // only grant access on the contactless interface
       return (BTChipPocApplet.isContactless());      
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_CLA] != NFCFORUM_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        switch(buffer[ISO7816.OFFSET_INS]) {
            case INS_SELECT: {
                apdu.setIncomingAndReceive();
                short selectedFile = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
                switch(selectedFile) {
                    case EF_CONTAINER:
                        scratch[OFFSET_SELECTED_FILE] = SELECTED_FILE_CONTAINER;
                        break;
                    case EF_NDEF:
                        scratch[OFFSET_SELECTED_FILE] = SELECTED_FILE_NDEF;
                        break;
                    default:
                        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                }
            }
            break;
            
            case INS_READ: {
                short offset = Util.makeShort(buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]);
                if (scratch[OFFSET_SELECTED_FILE] == SELECTED_FILE_NONE) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
                byte[] fileData = null;
                switch(scratch[OFFSET_SELECTED_FILE]) {
                    case SELECTED_FILE_CONTAINER:
                        fileData = CONTAINER_DATA;
                        break;
                    case SELECTED_FILE_NDEF:
                        fileData = FILE_DATA;
                        break;
                }
                if (offset >= (short)fileData.length) {
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                }
                short sizeRead = (short)(buffer[ISO7816.OFFSET_LC] & 0xff);
                short blockLength = (((short)(offset + sizeRead) > (short)fileData.length) ? (short)(fileData.length - offset) : sizeRead);
                Util.arrayCopyNonAtomic(fileData, offset, buffer, (short)0, blockLength);
                apdu.setOutgoingAndSend((short)0, blockLength);
            }
            break;
                
        }       
    }
    
    public static void install (byte bArray[], short bOffset, byte bLength) throws ISOException {
        new BTChipNFCForumApplet().register(bArray, (short)(bOffset + 1), bArray[bOffset]);
    }
    
    public static final byte OFFSET_TEXT = (byte)15;
    
    private static final byte NFCFORUM_CLA = (byte)0x00;
    private static final byte INS_SELECT = (byte)0xA4;
    private static final byte INS_READ = (byte)0xB0;
    
    private static final short EF_CONTAINER = (short)0xE103;
    private static final short EF_NDEF = (short)0xE104;
    
    private static final byte SELECTED_FILE_NONE = (byte)0x00;
    private static final byte SELECTED_FILE_CONTAINER = (byte)0x01;
    private static final byte SELECTED_FILE_NDEF = (byte)0x02;
    
    private static final byte OFFSET_SELECTED_FILE = (byte)0x00;
    
    private static final byte CONTAINER_DATA[] = { 
        (byte)0x00, (byte)0x0F, // length
        (byte)0x20, // mapping version 2.0
        (byte)0x00, (byte)0xFF, // max R-APDU data size
        (byte)0x00, (byte)0xFF, // max C-APDU data size
        (byte)0x04, (byte)0x06, // NDEF File Control TL
           (byte)0xE1, (byte)0x04, // EF_NDEF
           (byte)0x01, (byte)0xF4, // Max NDEF size (update with FILE_DATA size)
           (byte)0x00,             // Read always
           (byte)0xFF              // Write never
    };
    
    private static final byte LANG[] = {
        (byte)'T', (byte)0x05, (byte)'e', (byte)'n', (byte)'-', (byte)'U', (byte)'S' // en-US text record
    };
        
    public static byte FILE_DATA[];
    
    private static byte scratch[];
    
}
