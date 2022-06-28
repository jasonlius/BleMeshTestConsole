using System;
using System.IO;
using System.Text;
using System.Numerics;
namespace consoleTest
{
    public class Utility
    {
        public static byte[] HexToBytes(String hexString)
        {
            try
            {
                Console.WriteLine("HexString is {0}", hexString);
                if (string.IsNullOrEmpty(hexString))
                {
                    Console.WriteLine($"error! hex string is empty: {hexString}.");
                    return new byte[0];
                }
                else if (hexString.Length > 2)
                {
                    string heHeader = hexString.Substring(0, 2);

                    if (heHeader == "0x")
                    {
                        hexString = hexString.Substring(2, hexString.Length - 2);
                    }
                }

                if (hexString.Length % 2 == 1)
                {
                    hexString = "0" + hexString;
                }
                // 将16进制秘钥转成字节数组
                byte[] bytes = new byte[hexString.Length / 2];
                for (var x = 0; x < bytes.Length; x++)
                {
                    var i = Convert.ToInt32(hexString.Substring(x * 2, 2), 16);
                    bytes[x] = (byte)i;
                }
                return bytes;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Message: {ex.Message}.");
                Console.WriteLine($"StackTrace: \r\n{ex.StackTrace}.");
                return new byte[0];
            }
        }

        // To combine two byte Array to one.
        public static byte[] ByteCombine(byte[] first, byte[] second)
        {
            byte[] bytes = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, bytes, 0, first.Length);
            Buffer.BlockCopy(second, 0, bytes, first.Length, second.Length);
            return bytes;
        }

        /// <summary>
        /// to convert ByteArray into HexString .
        /// </summary>
        /// <param name="bytes">byte Array</param>
        /// <returns></returns>
        public static string BytesToHexString(byte[] bytes)
        {
            StringBuilder sb = new StringBuilder(bytes.Length * 3);
            foreach (byte b in bytes)
            {
                sb.Append(Convert.ToString(b, 16).PadLeft(2, '0'));
            }
            return sb.ToString().ToUpper();
        }

        /// <summary>
        /// used to calculate the least significant bit（LSB）.
        /// </summary>
        /// <param name="number"></param>
        /// <returns></returns>
        public static byte GetLeastSignificantBit(byte number)
        {
            return (byte)(number & 1);
        }

        /// <summary>
        /// xor both array A and array B
        /// </summary>
        /// <param name="arrayA"></param>
        /// <param name="arrayB"></param>
        /// <returns></returns>
        public static byte[] xorU8Arrays(byte[] arrayA, byte[] arrayB)
        {
            byte[] result = new byte[arrayA.Length];
            for (int i = 0; i < arrayA.Length; i++)
            {
                result[i] = (byte)(arrayA[i] ^ arrayB[i]);
            }
            return result;
        }
    }
}
