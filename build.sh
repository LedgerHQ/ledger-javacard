JCENV=/media/truecrypt1/standards/JC/JavaCardKit-3_0_2/
mkdir -p build/classes build/applet 2>/dev/null
javac -g -classpath $JCENV/lib/api_classic.jar -sourcepath src -d build/classes src/com/btchip/applet/poc/*.java 
java -classpath "$JCENV/lib/*" com.sun.javacard.converter.Main -exportpath "$JCENV/api_export_files" -useproxyclass -out CAP -classdir build/classes -d build/applet -applet 0xFF:0x42:0x54:0x43:0x48:0x49:0x50:0x01 com.btchip.applet.poc.BTChipPocApplet -applet 0xFF:0x42:0x54:0x43:0x48:0x49:0x50:0x02 com.btchip.applet.poc.BTChipNFCForumApplet com.btchip.applet.poc 0xFF:0x42:0x54:0x43:0x48:0x49:0x50 1.0
cp build/applet/com/btchip/applet/poc/javacard/poc.cap build/BTChip.cap 2>/dev/null
rm -rf build/applet
rm -rf build/classes

