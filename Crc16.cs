// modified from http://www.sanity-free.org/134/standard_crc_16_in_csharp.html

using System;
using System.IO;
using System.Linq;

namespace WfcPatcher
{
    public class Crc16
    {
        private readonly ushort[] table = new ushort[256];

        public Crc16(ushort polynomial = 0xA001)
        {
            for (ushort i = 0; i < table.Length; ++i)
            {
                ushort value = 0;
                ushort temp = i;
                for (byte j = 0; j < 8; ++j)
                {
                    if (((value ^ temp) & 0x0001) != 0)
                    {
                        value = (ushort) ((value >> 1) ^ polynomial);
                    }
                    else
                    {
                        value >>= 1;
                    }
                    temp >>= 1;
                }
                table[i] = value;
            }
        }

        public ushort ComputeChecksum(byte[] bytes)
        {
            ushort crc = 0;
// ReSharper disable once AccessToModifiedClosure
            foreach (var index in bytes.Select(t => (byte) (crc ^ t)))
            {
                crc = (ushort) ((crc >> 8) ^ table[index]);
            }
            return crc;
        }

        public ushort ComputeChecksum(Stream stream, int length, ushort init = 0)
        {
            ushort crc = init;
            for (int i = 0; i < length; ++i)
            {
                var index = (byte) ((crc ^ stream.ReadByte()) & 0xFF);
                crc = (ushort) ((crc >> 8) ^ table[index]);
            }
            return crc;
        }

        public byte[] ComputeChecksumBytes(byte[] bytes)
        {
            ushort crc = ComputeChecksum(bytes);
            return BitConverter.GetBytes(crc);
        }
    }
}