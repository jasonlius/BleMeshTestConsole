using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace consoleTest
{
    public class BluetoothMesh
    {
        private static BluetoothMesh mesh;
        private int seqNumber;

        private readonly byte[] netKey = Utility.HexToBytes("7dd7364cd842ad18c17c2b820c84c3d6");
        private readonly byte[] appKey = Utility.HexToBytes("63964771734fbd76e3b40519d1d94a48");
        private byte[] ivIndex = Utility.HexToBytes("12345677");

        private byte[] encryptionKey = { };
        private byte[] privacyKey = { };
        private byte[] networkID = { };
        private byte sar = 0;
        private byte msgType = 0;

        // network PDU fields
        private byte ivi = 0;
        private byte nid = 0;
        private byte ctl = 0;
        private byte ttl = 0x03;
        private byte[] seq = Utility.HexToBytes("07080a");
        private byte[] src = { 0x12, 0x34 };
        private byte seg = 0;
        private byte akf = 1; // means application key is in use
        private byte aid = 0;
        private byte[] opcode = { 0x00, 0x00 };
        private byte[] opparams = { };

        private BluetoothMesh()
        {
            K2KeyMaterial k2KeyMaterial = Crypto.K2(netKey, new byte[] { 0x00 });
            encryptionKey = k2KeyMaterial.EncryptionKey;
            privacyKey = k2KeyMaterial.PrivacyKey;
            nid = k2KeyMaterial.NID[0];
            Console.WriteLine("encryptionKey is : {0}\n " +
               "privacyKey is : {1} \n" +
               "nid is {2} \n", Utility.BytesToHexString(encryptionKey),
               Utility.BytesToHexString(privacyKey), nid.ToString("X"));
            networkID = Crypto.K3(netKey);
            Console.WriteLine("networkID is : " + Utility.BytesToHexString(networkID));
            aid = Crypto.K4(appKey);
            Console.WriteLine("AID is : " + aid.ToString("X"));
            ivi = Utility.GetLeastSignificantBit(ivIndex[3]);
            Console.WriteLine("IVI is : " + ivi.ToString("X"));

        }

        public static BluetoothMesh GetInstanace()
        {
            if (mesh == null)
                mesh = new BluetoothMesh();
            return mesh;
        }

        //to formulate proxy Mesh PDUs and submit it by GATT bearer.
        public byte[] SendGenericOnOffSetUnack(byte[] dst, byte onoff)
        {
            byte[] accessPayload;
            byte[] opcode = Utility.HexToBytes("8203");
            try
            {
                //derive access payload.
                MemoryStream ms = new MemoryStream();
                ms.Write(opcode, 0, opcode.Length);
                ms.WriteByte(onoff);
                ms.WriteByte((byte)1);
                accessPayload = Utility.HexToBytes("d50a0048656c6c6f");
                Console.WriteLine("accessPayload : " + Utility.BytesToHexString(accessPayload));
                byte[] networkPdu = deriveNetworkPdu(accessPayload, dst);
                Console.WriteLine("network pdu is " + Utility.BytesToHexString(networkPdu));
                byte[] proxyPdus = finaliseProxyPdu(networkPdu);
                Console.WriteLine("proxy PDUs is " + Utility.BytesToHexString(proxyPdus));
                return proxyPdus;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.StackTrace.ToString());
                Console.WriteLine(ex.ToString());
                return new byte[] { 00 };
            }

        }

        // to get TransMIC and Encryption Paylaod using AES-CCM algorithm. 
        public EncAccessPayloadTransMic meshAuthEncAccessPayload(byte[] key, byte[] nonce, byte[] payload)
        {
            Console.WriteLine("meshAuthEncAccessPayload: key = " + Utility.BytesToHexString(key) + " nonce = " + Utility.BytesToHexString(nonce) + " payload = " + Utility.BytesToHexString(payload));
            EncAccessPayloadTransMic result = new EncAccessPayloadTransMic();
            byte[] Ciphertext = Crypto.Get_AES_CCM(key, nonce, payload);
            Console.WriteLine("meshAuthEncAccessPayload: ciphertext=" + Utility.BytesToHexString(Ciphertext));
            byte[] encAccessPayload = new byte[Ciphertext.Length - 4];
            Array.Copy(Ciphertext, 0, encAccessPayload, 0, Ciphertext.Length - 4);
            byte[] transportMic = new byte[4];
            Array.Copy(Ciphertext, Ciphertext.Length - 4, transportMic, 0, 4);
            result.EncAccessPayload = encAccessPayload;
            Console.WriteLine("EncAccessPayload is " + Utility.BytesToHexString(encAccessPayload));
            result.TransMic = transportMic;
            return result;
        }

        //derive uppper transport layer PDU
        private EncAccessPayloadTransMic deriveSecureUpperTransportPdu(byte[] accessPayload, byte[] dst)
        {
            EncAccessPayloadTransMic UpperTransportPdu;
            //derive Application Nonce
            MemoryStream ms = new MemoryStream();
            ms.Write(Utility.HexToBytes("0100"), 0, Utility.HexToBytes("0100").Length);
            ms.Write(seq, 0, seq.Length);
            ms.Write(src, 0, src.Length);
            ms.Write(dst, 0, dst.Length);
            ms.Write(ivIndex, 0, ivIndex.Length);
            byte[] appNonce = ms.ToArray();
            Console.WriteLine("deriveSecureUpperTransportPdu : appNonce= " + Utility.BytesToHexString(appNonce));
            UpperTransportPdu = meshAuthEncAccessPayload(appKey, appNonce, accessPayload);
            return UpperTransportPdu;
        }

        //derive lower transport PDUs
        private byte[] deriveLowerTransportPdu(EncAccessPayloadTransMic upperTransportPdu)
        {
            byte[] lowerTransportPdu = new byte[upperTransportPdu.GetLength() + 1];
            //to formulate a byte using operator << and |
            // seg=0 (1 bit), akf=1 (1 bit), aid (6 bits) already derived from k4
            byte ltpdu1 = (byte)((seg << 7) | (akf << 6) | aid);
            lowerTransportPdu[0] = ltpdu1;
            Array.Copy(upperTransportPdu.GetUpperTransportPdu(), 0, lowerTransportPdu, 1, upperTransportPdu.GetLength());
            return lowerTransportPdu;
        }

        // to get NetMIC, Encryption TransportPDU,Encryption Key using AES-CCM algorithm. 
        private AuthEncNetwork meshAuthEncNetwork(byte[] encryptionKey, byte[] nonce, byte[] dst, byte[] transportPdu)
        {
            AuthEncNetwork result = new AuthEncNetwork();
            MemoryStream ms = new MemoryStream();
            ms.Write(dst, 0, dst.Length);
            ms.Write(transportPdu, 0, transportPdu.Length);
            byte[] dstPlusTransportPdu = ms.ToArray();
            byte[] cipherText = Crypto.Get_AES_CCM(encryptionKey, nonce, dstPlusTransportPdu);
            int len = cipherText.Length;
            result.EncDst[0] = cipherText[0];
            result.EncDst[1] = cipherText[1];
            byte[] etp = new byte[len - 6];
            Array.Copy(cipherText, 2, etp, 0, len - 6);
            result.EncTransportPdu = etp;
            byte[] netMic = new byte[4];
            Array.Copy(cipherText, len - 4, netMic, 0, 4);
            result.NetMIC = netMic;
            return result;
        }

        //formulate network layer Nonce value to derive Decrption lowerTransportPdu,Decrption dst and NetMic
        private AuthEncNetwork deriveSecureNetworkLayer(byte[] lowerTransportPdu, byte[] dst)
        {
            byte ctl_ttl = (byte)(ctl | ttl);
            MemoryStream ms = new MemoryStream();
            ms.WriteByte(0);
            ms.WriteByte(ctl_ttl);
            ms.Write(seq, 0, seq.Length);
            ms.Write(src, 0, src.Length);
            ms.WriteByte(0);
            ms.WriteByte(0);
            ms.Write(ivIndex, 0, ivIndex.Length);
            byte[] netNonce = ms.ToArray();
            Console.WriteLine("derivesNetWorkPdu: NetNonce=" + Utility.BytesToHexString(netNonce));
            AuthEncNetwork authEncNetwork = meshAuthEncNetwork(encryptionKey, netNonce, dst, lowerTransportPdu);
            return authEncNetwork;
        }

        private byte[] finaliseNetworkPdu(byte ivi, byte nid, byte[] obfuscated_ctl_ttl_seq_src, byte[] encDst, byte[] encTransportPdu, byte[] netmic)
        {
            MemoryStream ms = new MemoryStream();
            byte npdu1 = (byte)((ivi << 7) | nid);
            ms.WriteByte(npdu1);
            ms.Write(obfuscated_ctl_ttl_seq_src, 0, obfuscated_ctl_ttl_seq_src.Length);
            ms.Write(encDst, 0, encDst.Length);
            ms.Write(encTransportPdu, 0, encTransportPdu.Length);
            ms.Write(netmic, 0, netmic.Length);
            ms.Flush();
            return ms.ToArray();
        }

        //to derive NetworkPdu
        private byte[] deriveNetworkPdu(byte[] accessPayload, byte[] dst)
        {
            Console.WriteLine("accessPayload : " + Utility.BytesToHexString(accessPayload));

            // upper transport PDU
            EncAccessPayloadTransMic UpperTransportPdu = deriveSecureUpperTransportPdu(accessPayload, dst);
            Console.WriteLine("upper transport pdu is " + Utility.BytesToHexString(UpperTransportPdu.GetUpperTransportPdu()));

            // derive lower transport PDU
            byte[] LowerTransportPdu = deriveLowerTransportPdu(UpperTransportPdu);
            Console.WriteLine("LowerTransportPdu is " + Utility.BytesToHexString(LowerTransportPdu));

            // encrypt network PDU
            AuthEncNetwork authEncNetwork = deriveSecureNetworkLayer(LowerTransportPdu, dst);
            Console.WriteLine("AuthEncNetwork is " + Utility.BytesToHexString(authEncNetwork.EncTransportPdu));

            // Obfuscate
            byte[] obfuscated_ctl_ttl_seq_src = Crypto.obfuscate(authEncNetwork.EncDst, authEncNetwork.EncTransportPdu, authEncNetwork.NetMIC, ctl, ttl, seq, src, ivIndex, privacyKey);
            Console.WriteLine("obfuscated_ctl_ttl_seq_src is " + Utility.BytesToHexString(obfuscated_ctl_ttl_seq_src));
            Console.WriteLine("netMic is " + Utility.BytesToHexString(authEncNetwork.NetMIC));

            // Finalise 
            byte[] networkPdu = finaliseNetworkPdu(ivi, nid, obfuscated_ctl_ttl_seq_src, authEncNetwork.EncDst, authEncNetwork.EncTransportPdu, authEncNetwork.NetMIC);
            return networkPdu;
        }

        //formulate final Proxy mesh network PDUs using Network PDU.
        private byte[] finaliseProxyPdu(byte[] networkPdu)
        {
            MemoryStream ms = new MemoryStream();
            byte sm = (byte)((sar << 6) | msgType);
            ms.WriteByte(sm);
            ms.Write(networkPdu, 0, networkPdu.Length);
            return ms.ToArray();
        }

    }
}
