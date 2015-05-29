# Replace with the path to your Java Card Development Kit
JCENV=/media/truecrypt1/standards/JC/JavaCardKit-3_0_2/
mkdir -p build/classes build/applet build/src/com/ledger/wallet 2>/dev/null
cp src/com/ledger/wallet/*.java build/src/com/ledger/wallet
cpp -P src/com/ledger/wallet/Ripemd160.javap > build/src/com/ledger/wallet/Ripemd160.java
cpp -P src/com/ledger/wallet/SHA512.javap > build/src/com/ledger/wallet/SHA512.java
javac -g -classpath $JCENV/lib/api_classic.jar -sourcepath build/src -d build/classes build/src/com/ledger/wallet/*.java 
java -classpath "$JCENV/lib/*" com.sun.javacard.converter.Main -exportpath "$JCENV/api_export_files" -useproxyclass -out CAP -classdir build/classes -d build/applet -applet 0xFF:0x4C:0x45:0x47:0x52:0x2E:0x57:0x41:0x4C:0x54:0x30:0x31:0x2E:0x49:0x30:0x31 com.ledger.wallet.LedgerWalletApplet -applet 0xFF:0x4C:0x45:0x47:0x52:0x2E:0x57:0x41:0x4C:0x54:0x30:0x31:0x2E:0x49:0x30:0x32 com.ledger.wallet.LWNFCForumApplet com.ledger.wallet 0xFF:0x4C:0x45:0x47:0x52:0x2E:0x57:0x41:0x4C:0x54:0x30:0x31 1.0
cp build/applet/com/ledger/wallet/javacard/wallet.cap build/Ledger-wallet.cap 2>/dev/null
rm -rf build/applet
rm -rf build/classes
rm -rf build/src

