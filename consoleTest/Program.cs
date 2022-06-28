using System;
using System.Diagnostics;
using System.Numerics;
using System.IO;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;

namespace consoleTest
{
    class MainProgram
    {
        public static void Main()
        {
          BluetoothMesh bluetoothMesh =  BluetoothMesh.GetInstanace();
          bluetoothMesh.SendGenericOnOffSetUnack(Utility.HexToBytes("c105"),  (byte)1); 
        }

    }
}

