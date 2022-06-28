using System;
using System.Numerics;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using consoleTest;
using Org.BouncyCastle.Crypto.Modes;
using System.IO;

namespace consoleTest
{
    public static class Crypto
    {
        private static readonly byte[] ZERO = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        private static readonly byte[] ZERO_5 = { 0, 0, 0, 0, 0 };
        private static byte[] k2_salt;
        private static byte[] k3_salt;
        private static byte[] k4_salt;
        //will be used in K2 calculation
        private static readonly byte[] id64 = { 0x69, 0x64, 0x36, 0x34 };
        //will be used in K3 calculation
        private static readonly byte[] id64_01 = { 0x69, 0x64, 0x36, 0x34, 0x01 };
        private static readonly byte[] id6 = { 0x69, 0x64, 0x36 };
        //will be used in K4 calculation
        private static readonly byte[] id6_01 = { 0x69, 0x64, 0x36, 0x01 };
        private static BigInteger TWO_POW_64 = BigInteger.Pow(2, 64);
        private static BigInteger BIGINT_64 = BigInteger.Parse( "40",System.Globalization.NumberStyles.HexNumber);

        //initialize a set of salt_value which can be used later. 
        static Crypto()
        {
            byte[] k2_plain = { 0x73, 0x6d, 0x6b, 0x32 };
            k2_salt = s1(k2_plain); // "smk2"
            byte[] k3_plain = Utility.HexToBytes("736d6b33") ;
            k3_salt = s1(k3_plain); // "smk3"
            byte[] k4_plain = { 0x73, 0x6d, 0x6b, 0x34 };
            k4_salt = s1(k4_plain); // "smk4"
        }
        //todo Cmac 算法用库实现
        public static byte[] GetAesCmac(byte[] key, byte[] message)
        {
            byte[] cmac_bytes = new byte[16];
            ICipherParameters cipherParameters = new KeyParameter(key);
            IBlockCipher blockCipher = new AesEngine();
            CMac mac = new CMac(blockCipher);
            mac.Init(cipherParameters);
            foreach (var b in message)
            {
                mac.Update(b);
            }
            mac.DoFinal(cmac_bytes, 0);
            return cmac_bytes;
        }

        //caculate the value of salt which K2 function will be used.
        public static byte[] s1(byte[] M)
        {
            byte[] cmac =AesCmac.GetAesCmac(ZERO, M);
            return cmac;
        }

        //to implement K2 network key material derivation function
        public static K2KeyMaterial K2(byte[] N, byte[] P)
        {
            Console.WriteLine("N: " + Utility.BytesToHexString(N));
            K2KeyMaterial k2KeyMaterial = new K2KeyMaterial();

            // T = AES-CMACsalt (N)
            byte[] T =AesCmac.GetAesCmac(k2_salt, N);
            byte[] T0 = { };

            //  T1 = AES-CMACt (T0 || P || 0x01)
            byte[] M1 = new byte[P.Length + 1];
            Array.Copy(P, 0, M1, 0, P.Length);
            M1[P.Length] = 0x01;
            byte[] T1 =AesCmac.GetAesCmac(T, M1);

            // T2 = AES-CMACt (T1 || P || 0x02)
            byte[] M2 = new byte[T1.Length + P.Length + 1];
            Array.Copy(T1, 0, M2, 0, T1.Length);
            Array.Copy(P, 0, M2, T1.Length, P.Length);
            M2[M2.Length - 1] = 0x02;
            byte[] T2 =AesCmac.GetAesCmac(T, M2);
            // T3 = AES-CMACt (T2 || P || 0x03)
            byte[] M3 = new byte[T2.Length + P.Length + 1];
            Array.Copy(T2, 0, M3, 0, T2.Length);
            Array.Copy(P, 0, M3, T2.Length, P.Length);
            M3[M3.Length - 1] = 0x03;
            byte[] T3 =AesCmac.GetAesCmac(T, M3);

            byte[] T123 = Utility.ByteCombine(Utility.ByteCombine(T1, T2), T3);
            BigInteger TWO_POW_263 = BigInteger.Pow(2, 263);
            BigInteger T123_BIGINT =BigInteger.Parse("0"+Utility.BytesToHexString(T123), System.Globalization.NumberStyles.HexNumber);
            BigInteger modval;
            BigInteger val = BigInteger.DivRem(T123_BIGINT, TWO_POW_263, out modval);

            //X means HEX
            String K2_hex = modval.ToString("X");
            k2KeyMaterial.NID = Utility.HexToBytes(K2_hex.Substring(0, 2));
            k2KeyMaterial.EncryptionKey = Utility.HexToBytes(K2_hex.Substring(2, 32));
            k2KeyMaterial.PrivacyKey = Utility.HexToBytes(K2_hex.Substring(34, 32));
            return k2KeyMaterial;
        }
        public static byte[] K3(byte[] N)
        {
            Console.WriteLine("N: " + Utility.BytesToHexString(N));
            // T = AES-CMACsalt (N)
            byte[] T =AesCmac.GetAesCmac(k3_salt, N);
            // k3(N) = AES-CMACt ( “id64” || 0x01 ) mod 2^64
            byte[] k3_cmac =AesCmac.GetAesCmac(T, id64_01);
            BigInteger k3_cmac_bigint =BigInteger.Parse("0"+Utility.BytesToHexString(k3_cmac),System.Globalization.NumberStyles.HexNumber);
            BigInteger k3_modval = BigInteger.Remainder(k3_cmac_bigint, TWO_POW_64);
            string k3_modval_hex = k3_modval.ToString("X");

            return Utility.HexToBytes(k3_modval_hex);
        }

        public static byte K4(byte[] N)
        {
            byte[] T = AesCmac.GetAesCmac(k4_salt, N);
            byte[] k4_cmac =AesCmac.GetAesCmac(T, id6_01);
            BigInteger k4_cmac_bigint =BigInteger.Parse("0"+Utility.BytesToHexString(k4_cmac), System.Globalization.NumberStyles.HexNumber);
            BigInteger k4_modval = BigInteger.Remainder(k4_cmac_bigint,  BIGINT_64);
            string k4_modval_hex = k4_modval.ToString("X");
            return Utility.HexToBytes(k4_modval_hex)[0];
        }

        /// <summary>
        /// Get the AES CCM algorithm
        /// </summary>
        /// <param name="key"></param>
        /// <param name="nonce"></param>
        /// <param name="plainText"></param>
        /// <returns></returns>
        public static byte[] Get_AES_CCM(byte[] key, byte[] nonce, byte[] plainText)
        {
            byte[] encryptedBytes = new byte[plainText.Length + 4];
            CcmBlockCipher ccmBlockCipher = new CcmBlockCipher(new AesEngine());
            AeadParameters aeadParameters = new AeadParameters(new KeyParameter(key), 32, nonce);
            ccmBlockCipher.Init(true, aeadParameters);
            ccmBlockCipher.ProcessBytes(plainText, 0, plainText.Length, encryptedBytes, plainText.Length);
            try
            {
                ccmBlockCipher.DoFinal(encryptedBytes, 0);
                return encryptedBytes;
            }
            catch (InvalidCipherTextException e)
            {
                Console.WriteLine("Error performing AES-CCM encryption: " + e.ToString());
                return null;
            }
        }

        private static byte[] privacyRandom(byte[] encDst, byte[] encTransportPdu, byte[] netmic)
        {
            MemoryStream ms = new MemoryStream();
            ms.Write(encDst, 0, encDst.Length);
            ms.Write(encTransportPdu, 0, encTransportPdu.Length);
            ms.Write(netmic, 0, netmic.Length);
            byte[] pr = ms.ToArray();
            byte[] pr07 = new byte[7];
            Array.Copy(pr, 0, pr07, 0, 7);
            return pr07;
        }

        /// <summary>
        /// e is AES-EBC unauthenticated encrptiom.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="plaintext"></param>
        /// <returns></returns>
        private static byte[] e(byte[] key, byte[] plaintext)
        {
            byte[] encrypted = new byte[plaintext.Length];
            ICipherParameters cipher_params = new KeyParameter(key);
            AesLightEngine engine = new AesLightEngine();
            engine.Init(true, cipher_params);
            engine.ProcessBlock(plaintext, 0, encrypted, 0);
            return encrypted;
        }

        public static byte[] obfuscate(byte[] encDst, byte[] encTransportPdu, byte[] netmic, byte ctl, byte ttl, byte[] seq, byte[] src, byte[] ivIndex, byte[] privacyKey)
        {
            // 1. Create Privacy Random
            byte[] PrivacyRandom = privacyRandom(encDst, encTransportPdu, netmic);
            Console.WriteLine("privacy_random= " + Utility.BytesToHexString(PrivacyRandom).ToLower());
            Console.WriteLine("Zero_5= " + Utility.BytesToHexString(ZERO_5).ToLower());
            Console.WriteLine("iv_index= " + Utility.BytesToHexString(ivIndex).ToLower());
            Console.WriteLine("privacy_key= " + Utility.BytesToHexString(privacyKey).ToLower());

            // 2. Calculate PECB
            MemoryStream ms = new MemoryStream();
            ms.Write(ZERO_5, 0, ZERO_5.Length);
            ms.Write(ivIndex, 0, ivIndex.Length);
            ms.Write(PrivacyRandom, 0, PrivacyRandom.Length);
            ms.Flush();
            byte[] pecbInput = ms.ToArray();
            Console.WriteLine("pecb_input= " + Utility.BytesToHexString(pecbInput).ToLower());
            byte[] pecb = e(privacyKey, pecbInput);
            byte[] pecb05 = new byte[6];
            Array.Copy(pecb, 0, pecb05, 0, 6);
            Console.WriteLine("PECB= " + Utility.BytesToHexString(pecb).ToLower());

            // 3. Obfuscate
            byte ctl_ttl = (byte)(ctl | ttl);
            ms = new MemoryStream();
            ms.WriteByte(ctl_ttl);
            ms.Write(seq, 0, seq.Length);
            ms.Write(src, 0, src.Length);
            ms.Flush();
            byte[] ctl_ttl_seq_src = ms.ToArray();
            Console.WriteLine("ctl_ttl_seq_src= " + Utility.BytesToHexString(ctl_ttl_seq_src).ToLower());
            byte[] obf = Utility.xorU8Arrays(ctl_ttl_seq_src, pecb05);
            return obf;
        }
    }
}
