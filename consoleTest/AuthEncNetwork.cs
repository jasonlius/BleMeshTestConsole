using System;
namespace consoleTest
{
    public class AuthEncNetwork
    {
        public byte[] EncDst = new byte[2];
        public byte[] EncTransportPdu;
        public byte[] NetMIC = new byte[4];

        public String toString()
        {
            return "EncDst=" + Utility.BytesToHexString(EncDst) + " EncTransportPdu=" + Utility.BytesToHexString(EncTransportPdu) + "NetMic=" + Utility.BytesToHexString(NetMIC);
        }
    }
}
