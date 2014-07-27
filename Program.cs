using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.Remoting.Messaging;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using WfcPatcher.Properties;

namespace WfcPatcher
{
    internal class Program
    {
        private static Dictionary<string, string> _replaceDictionary;

        private static void Main(string[] args)
        {
            _replaceDictionary = CompileReplaceDictionary();

            foreach (var s in args)
            {
#if DEBUG
#else
				try {
#endif
                string newFilename = PatchFile(s);
                Console.WriteLine("Patched to " + newFilename + "!");
#if DEBUG
#else
				} catch ( Exception ex ) {
					Console.WriteLine( "Failed patching " + s );
					Console.WriteLine( ex.ToString() );
					Console.WriteLine();
				}
#endif
            }
        }

        private static string PatchFile(string filename)
        {
            Console.WriteLine("Reading and copying " + filename + "...");
            var ndsSrc = new FileStream(filename, FileMode.Open);
            string newFilename =
                Path.Combine(Path.GetDirectoryName(filename), Path.GetFileNameWithoutExtension(filename)) +
                " (DreamWfc)" + Path.GetExtension(filename);
            var nds = new FileStream(newFilename, FileMode.Create);
            Util.CopyStream(ndsSrc, nds, (int) ndsSrc.Length);
            ndsSrc.Close();

            // http://dsibrew.org/wiki/DSi_Cartridge_Header

            // arm
            Console.WriteLine("Patching ARM Executables...");
            nds.Position = 0x20;
            uint arm9offset = nds.ReadUInt32();
            uint arm9entry = nds.ReadUInt32();
            uint arm9load = nds.ReadUInt32();
            uint arm9size = nds.ReadUInt32();
            uint arm7offset = nds.ReadUInt32();
            uint arm7entry = nds.ReadUInt32();
            uint arm7load = nds.ReadUInt32();
            uint arm7size = nds.ReadUInt32();

            PatchArm9(nds, arm9offset, arm9size);
            PatchArm7(nds, arm7offset, arm7size);

            // overlays
            Console.WriteLine("Patching overlays...");
            nds.Position = 0x50;
            uint arm9overlayoff = nds.ReadUInt32();
            uint arm9overlaylen = nds.ReadUInt32();
            uint arm7overlayoff = nds.ReadUInt32();
            uint arm7overlaylen = nds.ReadUInt32();

            PatchOverlay(nds, arm9overlayoff, arm9overlaylen);
            PatchOverlay(nds, arm7overlayoff, arm7overlaylen);

            Console.WriteLine();

            nds.Close();

            return newFilename;
        }

        private static void PatchArm9(FileStream nds, uint pos, uint len)
        {
            nds.Position = pos;
            var data = new byte[len];
            nds.Read(data, 0, (int) len);

            // decompress size info: http://www.crackerscrap.com/docs/dsromstructure.html
            // TODO: Is there a better way to figure out if an ARM9 is compressed?

            nds.Position = nds.Position - 8;
            uint compressedSize = nds.ReadUInt24();
            nds.ReadByte();
            uint additionalCompressedSize = nds.ReadUInt32();
            uint decompressedSize = additionalCompressedSize + len;

            bool compressed = false;
            byte[] decData = data;

#if DEBUG
            Console.WriteLine("ARM9 old dec size: 0x{0:X6}", decompressedSize);
            Console.WriteLine("ARM9 old cmp size: 0x{0:X6}", compressedSize);
            Console.WriteLine("ARM9 old filesize: 0x{0:X6}", len);
            Console.WriteLine("ARM9 old diff:     0x{0:X6}", additionalCompressedSize);
#endif

            var blz = new blz();
            // if this condition isn't true then it can't be blz-compressed so don't even try
            if (data.Length == compressedSize + 0x4000 || data.Length == compressedSize + 0x4004)
            {
                try
                {
                    blz.arm9 = 1;
                    byte[] maybeDecData = blz.BLZ_Decode(data);

                    if (maybeDecData.Length == decompressedSize)
                    {
                        compressed = true;
                        decData = maybeDecData;
                    }
                }
                catch (Exception)
                {
                    compressed = false;
                }
            }

            var decDataUnmodified = (byte[]) decData.Clone();
            if (ReplaceInData(decData, 0x00, true))
            {
                if (compressed)
                {
                    Console.WriteLine("Replacing and recompressing ARM9...");
                    data = blz.BLZ_Encode(decData, 0);

                    var newCompressedSize = (uint) data.Length;
                    if (newCompressedSize > len)
                    {
                        // new ARM is actually bigger, redo without the additional nullterm replacement
                        decData = decDataUnmodified;
                        ReplaceInData(decData, 0x00, false);
                        data = blz.BLZ_Encode(decData, 0);
                        newCompressedSize = (uint) data.Length;
                    }

                    if (newCompressedSize != len)
                    {
                        // new ARM is (still) different, attempt to find the metadata in the ARM9 secure area and replace that
                        byte[] newCmpSizeBytes = BitConverter.GetBytes(newCompressedSize);
                        for (int i = 0; i < 0x4000; i += 4)
                        {
                            uint maybeSize = BitConverter.ToUInt32(data, i);
                            if (maybeSize == len + 0x02000000)
                            {
                                data[i + 0] = newCmpSizeBytes[0];
                                data[i + 1] = newCmpSizeBytes[1];
                                data[i + 2] = newCmpSizeBytes[2];
                                data[i + 3] = (byte) (newCmpSizeBytes[3] + 0x02);
                                break;
                            }
                        }
                    }
#if DEBUG
                    var newDecompressedSize = (uint) decData.Length;
                    uint newAdditionalCompressedSize = newDecompressedSize - newCompressedSize;
                    Console.WriteLine("ARM9 new dec size: 0x{0:X6}", newDecompressedSize);
                    Console.WriteLine("ARM9 new cmp size: 0x{0:X6}", newCompressedSize);
                    Console.WriteLine("ARM9 new diff:     0x{0:X6}", newAdditionalCompressedSize);
#endif
                }
                else
                {
                    Console.WriteLine("Replacing ARM9...");
                    data = decData;
                }

                nds.Position = pos;
                nds.Write(data, 0, data.Length);

                int newSize = data.Length;
                int diff = (int) len - newSize;

                // copy back footer
                if (diff > 0)
                {
                    var footer = new List<byte>();
                    nds.Position = pos + len;
                    if (nds.PeekUInt32() == 0xDEC00621)
                    {
                        for (int j = 0; j < 12; ++j)
                        {
                            footer.Add((byte) nds.ReadByte());
                        }

                        nds.Position = pos + newSize;
                        nds.Write(footer.ToArray(), 0, footer.Count);
                    }

                    // padding
                    for (int j = 0; j < diff; ++j)
                    {
                        nds.WriteByte(0xFF);
                    }
                }

                // write new size
                byte[] newSizeBytes = BitConverter.GetBytes(newSize);
                nds.Position = 0x2C;
                nds.Write(newSizeBytes, 0, 4);

                // recalculate checksums
                nds.Position = pos;
                ushort secureChecksum = new Crc16().ComputeChecksum(nds, 0x4000, 0xFFFF);
                nds.Position = 0x6C;
                nds.Write(BitConverter.GetBytes(secureChecksum), 0, 2);

                nds.Position = 0;
                ushort headerChecksum = new Crc16().ComputeChecksum(nds, 0x15E, 0xFFFF);
                nds.Write(BitConverter.GetBytes(headerChecksum), 0, 2);
            }
        }

        private static void PatchArm7(FileStream nds, uint pos, uint len)
        {
            nds.Position = pos;
            var data = new byte[len];
            nds.Read(data, 0, (int) len);

            if (ReplaceInData(data))
            {
                Console.WriteLine("Replacing ARM7...");
                nds.Position = pos;
                nds.Write(data, 0, data.Length);
            }
        }

        private static void PatchOverlay(FileStream nds, uint pos, uint len)
        {
            // http://sourceforge.net/p/devkitpro/ndstool/ci/master/tree/source/ndsextract.cpp
            // http://sourceforge.net/p/devkitpro/ndstool/ci/master/tree/source/overlay.h
            // header compression info from http://gbatemp.net/threads/recompressing-an-overlay-file.329576/

            nds.Position = 0x048;
            uint fatOffset = nds.ReadUInt32();

            for (uint i = 0; i < len; i += 0x20)
            {
                nds.Position = pos + i;
                uint id = nds.ReadUInt32();
                uint ramAddr = nds.ReadUInt32();
                uint ramSize = nds.ReadUInt32();
                uint bssSize = nds.ReadUInt32();
                uint sinitInit = nds.ReadUInt32();
                uint sinitInitEnd = nds.ReadUInt32();
                uint fileId = nds.ReadUInt32();
                uint compressedSize = nds.ReadUInt24();
                var compressedBitmask = (byte) nds.ReadByte();

                nds.Position = fatOffset + 8*id;
                uint overlayPositionStart = nds.ReadUInt32();
                uint overlayPositionEnd = nds.ReadUInt32();
                uint overlaySize = overlayPositionEnd - overlayPositionStart;

                if (overlaySize == 0)
                {
                    continue;
                }

                nds.Position = overlayPositionStart;
                var data = new byte[overlaySize];
                nds.Read(data, 0, (int) overlaySize);

                var blz = new blz();
                byte[] decData;

                bool compressed = (compressedBitmask & 0x01) == 0x01;
                if (compressed)
                {
                    decData = blz.BLZ_Decode(data);
                }
                else
                {
                    decData = data;
                }


                if (ReplaceInData(decData))
                {
                    int newOverlaySize;
                    int diff;

                    // if something was replaced, put it back into the ROM
                    if (compressed)
                    {
                        Console.WriteLine("Replacing and recompressing overlay " + id + "...");

                        uint newCompressedSize = 0;
                        data = blz.BLZ_Encode(decData, 0);
                        newCompressedSize = (uint) data.Length;

                        newOverlaySize = data.Length;
                        diff = (int) overlaySize - newOverlaySize;

                        if (diff < 0)
                        {
                            Console.WriteLine("Patched file is {0} bytes bigger than original, trying to remove debug strings...", Math.Abs(diff));
                            var decNData = RemoveDebugStrings(decData);

                            if (decNData.Length != decData.Length)
                            {
                                data = blz.BLZ_Encode(decData, 0);
                                newCompressedSize = (uint) data.Length;

                                newOverlaySize = data.Length;
                                diff = (int)overlaySize - newOverlaySize;

                                if (diff < 0)
                                {
                                    Console.Error.WriteLine("WARNING: Patched overlay is {0} bytes too big, this renders the ROM unplayable most probably.", Math.Abs(diff));
                                }
                                else
                                {
                                    Console.WriteLine("Recovery successful.");
                                }
                            }
                            else
                            {
                                Console.Error.WriteLine("WARNING: Patched overlay is {0} bytes too big and debug string removal not possible, this renders the ROM unplayable most probably.", Math.Abs(diff));
                            }
                        }

                        // replace compressed size, if it was used before
                        if (compressedSize == overlaySize)
                        {
                            byte[] newCompressedSizeBytes = BitConverter.GetBytes(newCompressedSize);
                            nds.Position = pos + i + 0x1C;
                            nds.Write(newCompressedSizeBytes, 0, 3);
                        }
                    }
                    else
                    {
                        Console.WriteLine("Replacing overlay " + id + "...");

                        data = decData;
                    }

                    newOverlaySize = data.Length;
                    diff = (int) overlaySize - newOverlaySize;

                    nds.Position = overlayPositionStart;
                    nds.Write(data, 0, data.Length);

                    overlayPositionEnd = (uint) nds.Position;

                    // padding
                    for (int j = 0; j < diff; ++j)
                    {
                        nds.WriteByte(0xFF);
                    }

                    // new file end offset
                    byte[] newPosEndData = BitConverter.GetBytes(overlayPositionEnd);
                    nds.Position = fatOffset + 8*id + 4;
                    nds.Write(newPosEndData, 0, 4);
                }
            }
        }

        private static byte[] RemoveDebugStrings(byte[] data)
        {
            string[] debugStrings =
            {
                "recv buffer size",
                "send buffer size",
                "unknown connect mode"
            };

            foreach (var s in debugStrings)
            {
                byte[] searchBytes = Encoding.ASCII.GetBytes(s);
                var results = data.Locate(searchBytes);

                foreach (var result in results)
                {
                    for (int i = 0; i < searchBytes.Length; ++i)
                    {
                        data[result + i] = 0x20;
                    }
                }
            }

            return data;
        }

        private static bool ReplaceInData(byte[] data, byte paddingByte = 0x00,
            bool writeAdditionalBytePostString = false)
        {
            bool replacedData;

            // Replace certificate

            var certResults = data.Locate(Encoding.ASCII.GetBytes("US,"));
            foreach (var certResult in certResults)
            {
                var info = Util.GetTextAscii(data, certResult);
#if DEBUG
                Console.WriteLine("Found certificate: {0}", info);
#endif

                // We only want to replace the NoA certificate, nothing else here
                if (info != "US, Washington, Nintendo of America Inc, NOA, Nintendo CA, ca@noa.nintendo.com")
                    continue;

                Console.WriteLine("Patching NoA certificate...");

                var originalInfoLength = info.Length;

                /*
                    var osubj = info;
                    var omodulus = data.Skip(certResult + info.Length + 2).Take(128).ToArray();
                    var oexponent = data.Skip(certResult + info.Length + 1 + omodulus.Length).Take(3).ToArray();
                     */

                var pos = certResult + info.Length + 2;

                var cert = new X509Certificate2(Resources.patched_nas);

                var certSubjInfo =
                    Regex.Matches(cert.Subject, @"[\s]?([A-z]+)=([^,]+)[/,]*")
                        .Cast<Match>()
                        .Select(x => new KeyValuePair<string, string>(x.Groups[1].Value, x.Groups[2].Value))
                        .ToDictionary(x => x.Key, x => x.Value);

                var key = cert.PublicKey.Key as RSACryptoServiceProvider;
                if (key == null)
                {
                    Console.Error.WriteLine("Something is wrong with the certificate!");
                    return false;
                }

                var parameters = key.ExportParameters(false);
#if DEBUG
                HexDisplay(data, certResult, originalInfoLength + 2 + 148, "OLD cert data", p =>
                {
                    if (p < originalInfoLength)
                        return ConsoleColor.Blue;
                    if (p >= originalInfoLength + 2 && p < originalInfoLength + 2 + parameters.Modulus.Length)
                        return ConsoleColor.Green;
                    if (p >= originalInfoLength + 2 + parameters.Modulus.Length && p < originalInfoLength + 2 + parameters.Modulus.Length + parameters.Exponent.Length)
                        return ConsoleColor.Red;
                    return ConsoleColor.DarkGray;
                });
#endif
                parameters.Modulus.CopyTo(data, pos);
                parameters.Exponent.CopyTo(data, pos += parameters.Modulus.Length);

                var infoSplit = info.Split(new[] {", "}, StringSplitOptions.None);
                infoSplit[0] = certSubjInfo.ContainsKey("C") ? certSubjInfo["C"] : infoSplit[0];
                infoSplit[1] = certSubjInfo.ContainsKey("ST")
                    ? certSubjInfo["ST"]
                    : certSubjInfo.ContainsKey("S")
                        ? certSubjInfo["S"]
                        : infoSplit[1];
                infoSplit[2] = certSubjInfo.ContainsKey("O") ? certSubjInfo["O"] : infoSplit[2];
                infoSplit[3] = certSubjInfo.ContainsKey("OU") ? certSubjInfo["OU"] : infoSplit[3];
                infoSplit[4] = certSubjInfo.ContainsKey("CN") ? certSubjInfo["CN"] : infoSplit[4];
                infoSplit[5] = certSubjInfo.ContainsKey("E")
                    ? certSubjInfo["E"]
                    : certSubjInfo.ContainsKey("Email")
                        ? certSubjInfo["Email"]
                        : certSubjInfo.ContainsKey("emailAddress")
                            ? certSubjInfo["emailAddress"]
                            : infoSplit[5];
                info = string.Join(", ", infoSplit);
                if (info.Length > originalInfoLength)
                {
                    Console.Error.WriteLine("WARNING: New certificate subject is longer than original one, trimming!");
                    info = info.Substring(0, originalInfoLength);
                }
                Encoding.ASCII.GetBytes(info + "\x00" + new string('\x00', originalInfoLength - info.Length))
                    .CopyTo(data, certResult);

                // TODO: Patch SSL certificate metadata
                //Console.WriteLine(BitConverter.ToString(data, pos += parameters.Exponent.Length, 20));

#if DEBUG
                HexDisplay(data, certResult, originalInfoLength + 2 + 148, "NEW cert data", p =>
                    {
                        if (p < originalInfoLength)
                            return ConsoleColor.Blue;
                        if (p >= originalInfoLength + 2 && p < originalInfoLength + 2 + parameters.Modulus.Length)
                            return ConsoleColor.Green;
                        if (p >= originalInfoLength + 2 + parameters.Modulus.Length && p < originalInfoLength + 2 + parameters.Modulus.Length + parameters.Exponent.Length)
                            return ConsoleColor.Red;
                        return ConsoleColor.DarkGray;
                    });
#endif

                replacedData = true;
            }

            // Replace strings
            replacedData = ReplaceString(data, _replaceDictionary);

            return replacedData;
        }

        private static Dictionary<string, string> CompileReplaceDictionary()
        {
            var repDict = new Dictionary<string, string>();
            var queries = Settings.Default.PatchSubstrings;

            foreach (var q in queries)
            {
                if (q.Length < 1)
                {
                    throw new Exception(
                        "Invalid substring patch line found: Missing first character (acting as delimiter)");
                }

                var delimiter = q[0];
                var qsplit = q.Split(delimiter);
                if (qsplit.Length != 4) // delimiter type delimiter originalString delimiter patchString
                    throw new Exception(
                        "Invalid substring patch line found: Bad syntax. Syntax is \"delimiter type originalstring type newstring\". Example: \"|type|original|patched\".");
                var query = new
                {
                    Type = qsplit[1],
                    OriginalSubstring = qsplit[2],
                    NewSubstring = qsplit[3]
                };

                switch (query.Type)
                {
                    case "normal":
                        repDict.Add(query.OriginalSubstring, query.NewSubstring);
                        break;
                    case "message":
                        repDict.Add(query.OriginalSubstring, query.NewSubstring);

                        var originalWords = query.OriginalSubstring.Split(' ');
                        var newWords = query.NewSubstring.Split(' ');
                        for (var i = 1; i < Math.Max(originalWords.Length, newWords.Length); i++)
                        {
                            var originalBefore = string.Join(" ", originalWords.Take(Math.Min(i, originalWords.Length)));
                            var originalAfterSkip = Math.Min(i, originalWords.Length);
                            var originalAfter = string.Join(" ",
                                originalWords.Skip(originalAfterSkip).Take(originalWords.Length - originalAfterSkip));

                            var newBefore = string.Empty;
                            var newAfter = string.Empty;
                            var j = 0;
                            do
                            {
                                j++;
                                var tempNewBefore = string.Join(" ", newWords.Take(Math.Min(j, newWords.Length)));
                                if (tempNewBefore.Length > originalBefore.Length)
                                    break;
                                newBefore = tempNewBefore;
                                var newAfterSkip = Math.Min(j, newWords.Length);
                                newAfter = string.Join(" ",
                                    newWords.Skip(newAfterSkip).Take(newWords.Length - newAfterSkip));
                            } while (j < newWords.Length);

                            repDict.Add(string.Format("{0}\n{1}", originalBefore, originalAfter),
                                string.Format("{0}\n{1}", newBefore, newAfter));
                        }
                        break;
                    default:
                        throw new Exception(
                            "Invalid substring patch line found: Invalid type. Allowed types are \"message\" (will take line breaks into account) and \"normal\" (plain replace).");
                }
            }

            return repDict;
        }

        private static bool ReplaceString(byte[] data, Dictionary<string, string> replacements)
        {
            bool replaced = false;

            var encs = new[]
            {
                Encoding.UTF8,
                Encoding.ASCII,
                Encoding.Unicode
            };

            foreach (var enc in encs)
            {
                var encCharSize = Equals(enc, Encoding.Unicode) ? 2 : 1;

                foreach (var oresult in replacements.Keys
                    .Select(enc.GetBytes)
                    .SelectMany(data.Locate)
                    .Distinct())
                {
                    var result = oresult;

                    // Seek to actual beginning of the string
                    while (true)
                    {
                        var cs = new char[16];
                        enc.GetChars(data, result, enc.GetMaxByteCount(1), cs, 0);
                        var c = cs.First();
                        if (!IsPrintable(c))
                            break;
                        result -= encCharSize;
                    }
                    result += encCharSize; // actual beginning of string

                    // Decode string
                    string originalString;
                    if (Equals(enc, Encoding.UTF8))
                        originalString = Util.GetTextUTF8(data, result);
                    else if (Equals(enc, Encoding.Unicode))
                        originalString = Util.GetTextUnicode(data, result, data.Length - result);
                    else
                        originalString = Util.GetTextAscii(data, result);

                    // Do not replace strings which may be internal condition references
                    if (originalString == "https://" || originalString == "http://")
                        continue;

                    // Produce a proper terminator later on
                    originalString += '\0';

                    var replacementString = replacements.Aggregate(originalString,
                        (current, i) => current.Replace(i.Key, i.Value));

                    // Did something change?
                    if (replacementString == originalString)
                        continue;

                    var originalBytes = enc.GetBytes(originalString);

#if DEBUG
                    HexDisplay(data, result, originalBytes.Length, string.Format("OLD {0} string data", enc.EncodingName));
#endif

                    var replacementBytes = originalBytes;

                    // Alright, this might require some explaination.
                    // This is putting a byte in the location that previously held the NULL terminator at the end of the string.
                    // We can just place anything in there without affecting the program. Now, the actual *reason* we're putting
                    // a byte in here is to reduce the chance of the recompressed binary becoming smaller than the original one.
                    // We want it to remain the exact same size. Now, of course, this is not always going to happen, but this
                    // should improve the chance significantly.
                    replacementBytes[originalBytes.Length - encCharSize] = 0x7f;

                    // Now we do the actual replacement
                    enc.GetBytes(replacementString)
                        .CopyTo(replacementBytes, 0);
                    replacementBytes.CopyTo(data, result);

                    replaced = true;

#if DEBUG
                    HexDisplay(data, result, originalBytes.Length, string.Format("NEW {0} string data", enc.EncodingName));
#endif
                }
            }

            return replaced;
        }
        
#if DEBUG
        private static void HexDisplay(IEnumerable<byte> data, int offset, int length, string comment = null, Func<int, ConsoleColor> colorCb = null)
        {
            if (colorCb == null)
                colorCb = i => ConsoleColor.DarkGray;

            var bytes = new Queue<byte>(data.Skip(offset).Take(length));

            comment = string.Format("{2} at 0x{0:X8} ({1} bytes)", offset, length, comment ?? "Raw data");

            Console.ForegroundColor = ConsoleColor.DarkGray;
            
            Console.WriteLine(comment);

                var np = 0;
            while (bytes.Any())
            {
                var rowBytes = new List<byte>();
                for (var i = 0; i < 16; i++)
                    if (bytes.Any())
                        rowBytes.Add(bytes.Dequeue());

                var rowChars = rowBytes
                    .Select(b => (char) b)
                    .Select(c => IsPrintable(c) ? c : '.');

                Console.Write("\t");
                var pad = 16 * 3;
                foreach (var b in rowBytes)
                {
                    Console.ForegroundColor = colorCb(np);
                    Console.Write("{0:X2} ", b);
                    pad -= 3;
                    np++;
                }

                Console.Write(new string(' ', pad));

                np -= 16;
                foreach (var c in rowChars)
                {
                    Console.ForegroundColor = colorCb(np);
                    Console.Write(c);
                    np++;
                }

                Console.WriteLine();
            }

            Console.ResetColor();
        }
#endif

        private static bool IsPrintable(char c)
        {
            return !Char.IsControl(c)
                   && c != (char) 0x2028 && c != (char) 0x2029; // see comment in http://stackoverflow.com/a/13499234
        }
    }
}