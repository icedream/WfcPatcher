using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace WfcPatcher
{
    public static class Util
    {
        #region SwapEndian

        public static Int16 SwapEndian(this Int16 x)
        {
            return (Int16) SwapEndian((UInt16) x);
        }

        public static UInt16 SwapEndian(this UInt16 x)
        {
            return (UInt16)
                ((x << 8) |
                 (x >> 8));
        }

        public static Int32 SwapEndian(this Int32 x)
        {
            return (Int32) SwapEndian((UInt32) x);
        }

        public static UInt32 SwapEndian(this UInt32 x)
        {
            return (x << 24) |
                   ((x << 8) & 0x00FF0000) |
                   ((x >> 8) & 0x0000FF00) |
                   (x >> 24);
        }

        public static Int64 SwapEndian(this Int64 x)
        {
            return (Int64) SwapEndian((UInt64) x);
        }

        public static UInt64 SwapEndian(this UInt64 x)
        {
            return (x << 56) |
                   ((x << 40) & 0x00FF000000000000) |
                   ((x << 24) & 0x0000FF0000000000) |
                   ((x << 8) & 0x000000FF00000000) |
                   ((x >> 8) & 0x00000000FF000000) |
                   ((x >> 24) & 0x0000000000FF0000) |
                   ((x >> 40) & 0x000000000000FF00) |
                   (x >> 56);
        }

        #endregion

        #region HexUtils

        public static byte ParseDecOrHexToByte(string s)
        {
            s = s.Trim();

            if (!s.StartsWith("0x")) return Byte.Parse(s);
            s = s.Substring(2);
            return Byte.Parse(s, NumberStyles.HexNumber);
        }

        public static byte[] HexStringToByteArray(string hex)
        {
            if (hex.Length%2 == 1)
                throw new Exception("The binary key cannot have an odd number of digits");

            var arr = new byte[hex.Length >> 1];

            for (int i = 0; i < hex.Length >> 1; ++i)
            {
                arr[i] = (byte) ((GetHexVal(hex[i << 1]) << 4) + (GetHexVal(hex[(i << 1) + 1])));
            }

            return arr;
        }

        public static int GetHexVal(char hex)
        {
            int val = hex;
            //For uppercase A-F letters:
            //return val - (val < 58 ? 48 : 55);
            //For lowercase a-f letters:
            //return val - (val < 58 ? 48 : 87);
            //Or the two combined, but a bit slower:
            return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
        }

        #endregion

        #region NumberUtils

        public static uint ToUInt24(byte[] file, int pointer)
        {
            var b = file.Skip(pointer).Take(3).ToArray();

            return (uint) (b[2] << 16 | b[1] << 8 | b[0]);
        }

        public static byte[] GetBytesForUInt24(uint number)
        {
            return new[]
            {
                (byte) (number & 0xFF),
                (byte) ((number >> 8) & 0xFF),
                (byte) ((number >> 16) & 0xFF)
            };
        }

        /// <summary>
        ///     converts a 32-bit int that's actually a byte representation of a float
        ///     to an actual float for use in calculations or whatever
        /// </summary>
        public static float UIntToFloat(uint integer)
        {
            byte[] b = BitConverter.GetBytes(integer);
            float f = BitConverter.ToSingle(b, 0);
            return f;
        }

        public static int Align(this int number, int alignment)
        {
            return (int) Align((uint) number, (uint) alignment);
        }

        public static uint Align(this uint number, uint alignment)
        {
            uint diff = number % alignment;
            if (diff == 0)
            {
                return number;
            }
            return (number + (alignment - diff));
        }

        #endregion

        #region TextUtils

        private static Encoding _shiftJISEncoding;

        public static Encoding ShiftJISEncoding
        {
            get { return _shiftJISEncoding ?? (_shiftJISEncoding = Encoding.GetEncoding(932)); }
        }

        public static String GetTextShiftJis(byte[] file, int pointer)
        {
            if (pointer == -1) return null;

            try
            {
                int i = pointer;
                while (file[i] != 0x00)
                {
                    i++;
                }
                string text = ShiftJISEncoding.GetString(file, pointer, i - pointer);
                return text;
            }
            catch (Exception)
            {
                return null;
            }
        }

        public static String GetTextAscii(byte[] file, int pointer)
        {
            if (pointer == -1) return null;

            try
            {
                int i = pointer;
                while (file[i] != 0x00)
                {
                    i++;
                }
                string text = Encoding.ASCII.GetString(file, pointer, i - pointer);
                return text;
            }
            catch (Exception)
            {
                return null;
            }
        }

        public static String GetTextUnicode(byte[] file, int pointer, int maxByteLength)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < maxByteLength; i += 2)
            {
                ushort ch = BitConverter.ToUInt16(file, pointer + i);
                if (ch == 0 || ch == 0xFFFF)
                {
                    break;
                }
                sb.Append((char) ch);
            }
            return sb.ToString();
        }

        public static String GetTextUTF8(byte[] file, int pointer)
        {
            int tmp;
            return GetTextUTF8(file, pointer, out tmp);
        }

        public static String GetTextUTF8(byte[] file, int pointer, out int nullLocation)
        {
            if (pointer == -1)
            {
                nullLocation = -1;
                return null;
            }

            try
            {
                int i = pointer;
                while (file[i] != 0x00)
                {
                    i++;
                }
                string text = Encoding.UTF8.GetString(file, pointer, i - pointer);
                nullLocation = i;
                return text;
            }
            catch (Exception)
            {
                nullLocation = -1;
                return null;
            }
        }

        public static String TrimNull(this String s)
        {
            int n = s.IndexOf('\0', 0);
            return n >= 0 ? s.Substring(0, n) : s;
        }

        public static byte[] StringToBytesShiftJis(String s)
        {
            //byte[] bytes = ShiftJISEncoding.GetBytes(s);
            //return bytes.TakeWhile(subject => subject != 0x00).ToArray();
            return ShiftJISEncoding.GetBytes(s);
        }

        public static byte[] StringToBytesUTF16(String s)
        {
            return Encoding.Unicode.GetBytes(s);
        }

        public static string XmlEscape(string s)
        {
            s = s.Replace("&", "&amp;");
            s = s.Replace("\"", "&quot;");
            s = s.Replace("'", "&apos;");
            s = s.Replace("<", "&lt;");
            s = s.Replace(">", "&gt;");
            return s;
        }

        #endregion

        #region TimeUtils

        public static DateTime UnixTimeToDateTime(ulong unixTime)
        {
            return new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).AddSeconds(unixTime).ToLocalTime();
        }

        public static ulong DateTimeToUnixTime(DateTime time)
        {
            return (ulong) (time - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).ToLocalTime()).TotalSeconds;
        }

        public static DateTime PS3TimeToDateTime(ulong ps3Time)
        {
            return new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).AddMilliseconds((double)ps3Time/1000).ToLocalTime();
        }

        #endregion

        #region ProgramUtils

        public static bool RunProgram(String prog, String args, bool displayCommandLine, bool displayOutput,
            bool useShell = false)
        {
            if (displayCommandLine)
            {
                Console.WriteLine(@"{0} {1}", prog, args);
            }

            // Use ProcessStartInfo class
            var startInfo = new ProcessStartInfo
            {
                CreateNoWindow = false,
                UseShellExecute = useShell,
                FileName = prog,
                WindowStyle = ProcessWindowStyle.Hidden,
                Arguments = args,
                RedirectStandardOutput = !useShell,
                RedirectStandardError = !useShell
            };
            //startInfo.RedirectStandardInput = !useShell;
            //startInfo.UserName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;

            using (var exeProcess = Process.Start(startInfo))
            {
                if (exeProcess == null)
                    return false;

                exeProcess.WaitForExit();
                if (useShell)
                {
                    return exeProcess.ExitCode == 0;
                }

                string output = exeProcess.StandardOutput.ReadToEnd();
                string err = exeProcess.StandardError.ReadToEnd();
                int exitCode = exeProcess.ExitCode;

                if (exitCode != 0)
                {
                    Console.WriteLine("{0} returned nonzero: {1}", prog, output);
                    throw new Exception(output);
                    //return false;
                }

                if (!displayOutput)
                    return true;

                Console.WriteLine(output);
                Console.WriteLine(err);

                return true;
            }
        }

        #endregion

        #region ArrayUtils

        public static void CopyByteArrayPart(IList<byte> from, int locationFrom, IList<byte> to, int locationTo,
            int count)
        {
            for (int i = 0; i < count; i++)
            {
                to[locationTo + i] = from[locationFrom + i];
            }
        }

        public static void FillNull(IList<byte> array, int location, int count)
        {
            for (int i = 0; i < count; ++i)
            {
                array[location + i] = 0x00;
            }
        }

        public static bool IsByteArrayPartEqual(IList<byte> array1, int location1, IList<byte> array2, int location2,
            int count)
        {
            for (int i = 0; i < count; ++i)
            {
                if (array1[i + location1] != array2[i + location2])
                {
                    return false;
                }
            }
            return true;
        }

        #endregion

        #region StreamUtils

        public static uint ReadUInt32(this Stream s)
        {
            int b1 = s.ReadByte();
            int b2 = s.ReadByte();
            int b3 = s.ReadByte();
            int b4 = s.ReadByte();

            return (uint) (b4 << 24 | b3 << 16 | b2 << 8 | b1);
        }

        public static uint PeekUInt32(this Stream s)
        {
            long pos = s.Position;
            uint retval = s.ReadUInt32();
            s.Position = pos;
            return retval;
        }

        public static uint ReadUInt24(this Stream s)
        {
            int b1 = s.ReadByte();
            int b2 = s.ReadByte();
            int b3 = s.ReadByte();

            return (uint) (b3 << 16 | b2 << 8 | b1);
        }

        public static uint PeekUInt24(this Stream s)
        {
            long pos = s.Position;
            uint retval = s.ReadUInt24();
            s.Position = pos;
            return retval;
        }

        public static ushort ReadUInt16(this Stream s)
        {
            int b1 = s.ReadByte();
            int b2 = s.ReadByte();

            return (ushort) (b2 << 8 | b1);
        }

        public static ushort PeekUInt16(this Stream s)
        {
            long pos = s.Position;
            ushort retval = s.ReadUInt16();
            s.Position = pos;
            return retval;
        }

        public static string ReadAsciiNullterm(this Stream s)
        {
            var sb = new StringBuilder();
            int b = s.ReadByte();
            while (b != 0 && b != -1)
            {
                sb.Append((char) (b));
                b = s.ReadByte();
            }
            return sb.ToString();
        }

        public static string ReadAscii(this Stream s, int count)
        {
            var sb = new StringBuilder(count);
            int b;
            for (int i = 0; i < count; ++i)
            {
                b = s.ReadByte();
                sb.Append((char) (b));
            }
            return sb.ToString();
        }

        public static string ReadUTF16Nullterm(this Stream s)
        {
            var sb = new StringBuilder();
            var b = new byte[2];
            int b0 = s.ReadByte();
            int b1 = s.ReadByte();
            while (!(b0 == 0 && b1 == 0) && b1 != -1)
            {
                b[0] = (byte) b0;
                b[1] = (byte) b1;
                sb.Append(Encoding.Unicode.GetString(b, 0, 2));
                b0 = s.ReadByte();
                b1 = s.ReadByte();
            }
            return sb.ToString();
        }

        #endregion

        public static string GuessFileExtension(Stream s)
        {
            uint magic32 = s.PeekUInt32();
            //uint magic24 = s.PeekUInt24();
            uint magic16 = s.PeekUInt16();

            switch (magic32)
            {
                case 0x46464952:
                    return ".wav";
                case 0x474E5089:
                    return ".png";
                case 0x5367674F:
                    return ".ogg";
            }

            switch (magic16)
            {
                case 0x4D42:
                    return ".bmp";
            }

            return "";
        }
    }
}