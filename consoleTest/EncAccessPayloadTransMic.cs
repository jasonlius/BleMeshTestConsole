using System;
namespace consoleTest
{
    public class EncAccessPayloadTransMic
    {
        public byte[] EncAccessPayload { get; set; }
        public byte[] TransMic = new byte[4];

        public byte[] GetUpperTransportPdu()
        {
            byte[] upperTransportPdu = new byte[EncAccessPayload.Length + 4];
            Array.Copy(EncAccessPayload, 0, upperTransportPdu, 0, EncAccessPayload.Length);
            Array.Copy(TransMic, 0, upperTransportPdu, EncAccessPayload.Length, 4);
            return upperTransportPdu;
        }

        public int GetLength()
        {
            return EncAccessPayload.Length + 4;
        }

        public string ToString()
        {
            return "EncAccessPayload=" + Utility.BytesToHexString(EncAccessPayload) + " TransMIC=" + Utility.BytesToHexString(TransMic);
        }
    }
}
