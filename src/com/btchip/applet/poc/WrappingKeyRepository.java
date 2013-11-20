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

// REMOVE DEBUGGING VALUE

package com.btchip.applet.poc;

import javacard.framework.JCSystem;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

/**
 * Management of internal wrapping keys
 * @author BTChip
 *
 */
public class WrappingKeyRepository {
    
    public static class WrappingKey {
        
        protected WrappingKey(byte id, byte role, Key key) {
            this.id = id;
            this.role = role;
            this.key = key;
            if (wrappingKeyList == null) {
                wrappingKeyList = this;
            }
            else {
                wrappingKeyList.next = this;
            }
        }
        
        public boolean match(byte id, byte role) {
            boolean match1 = (this.id == id);
            boolean match2 = (this.role == role);
            return (match1 && match2);
        }
        
        public void initCipher(boolean encrypt) {
            Crypto.blobEncryptDecrypt.init(key, (encrypt ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT), IV_ZERO, (short)0, (short)IV_ZERO.length);
        }
        
        public Key getKey() {
            return key;
        }
        
        public WrappingKey getNext() {
            return next;
        }
        
        private static final byte[] IV_ZERO = { 0, 0, 0, 0, 0, 0, 0, 0 };
        
        private byte id;
        private byte role;
        private Key key;
        private WrappingKey next;        
    }
        
    public static WrappingKey add(byte id, byte role, byte[] value, short valueOffset) {
        DESKey newKey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
        newKey.setKey(value, valueOffset);
        return new WrappingKey(id, role, newKey);
    }
    
    public static WrappingKey find(byte id, byte role) {
        WrappingKey current = wrappingKeyList;
        while (current != null) {
            if (current.match(id, role)) {
                return current;
            }
            current = current.getNext();
        }
        return null;
    }
    
    public static final byte ROLE_PRIVATE_KEY_ENCRYPTION = (byte)0x20;
    public static final byte ROLE_CONTEXT_EXCHANGE_ENCRYPTION = (byte)0x21;
    public static final byte ROLE_AUTHORIZED_ADDRESS_ENCRYPTION = (byte)0x22;
    public static final byte ROLE_TRUSTED_INPUT_ENCRYPTION = (byte)0x23;
    public static final byte ROLE_TRANSACTION_AUTHORIZATION_SIGNATURE = (byte)0x24;
    public static final byte ROLE_TRUSTED_SECURE_CHANNEL = (byte)0x25;
    public static final byte ROLE_PRIVATE_KEY_SIGNATURE = (byte)0x26;
    public static final byte ROLE_MODE_SIGNATURE = (byte)0x27;
    public static final byte ROLE_PRIVATE_KEY_DIVERSIFICATION = (byte)0x28;
    
    private static WrappingKey wrappingKeyList = null;
}
