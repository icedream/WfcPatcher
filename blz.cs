using System;

namespace WfcPatcher
{
    internal class Blz
    {
        // Ported from blz.c and slightly edited for possible optimization

        /*----------------------------------------------------------------------------*/
        /*--  blz.c - Bottom LZ coding for Nintendo GBA/DS                          --*/
        /*--  Copyright (C) 2011 CUE                                                --*/
        /*--                                                                        --*/
        /*--  This program is free software: you can redistribute it and/or modify  --*/
        /*--  it under the terms of the GNU General Public License as published by  --*/
        /*--  the Free Software Foundation, either version 3 of the License, or     --*/
        /*--  (at your option) any later version.                                   --*/
        /*--                                                                        --*/
        /*--  This program is distributed in the hope that it will be useful,       --*/
        /*--  but WITHOUT ANY WARRANTY; without even the implied warranty of        --*/
        /*--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the          --*/
        /*--  GNU General Public License for more details.                          --*/
        /*--                                                                        --*/
        /*--  You should have received a copy of the GNU General Public License     --*/
        /*--  along with this program. If not, see <http://www.gnu.org/licenses/>.  --*/
        /*----------------------------------------------------------------------------*/

        /*----------------------------------------------------------------------------*/
        public const uint CmdDecode = 0x00; // decode
        public const uint CmdEncode = 0x01; // encode

        public const uint BlzNormal = 0; // normal mode
        public const uint BlzBest = 1; // best mode

        public const uint BlzShift = 1; // bits to shift
        public const byte BlzMask = 0x80; // bits to check: ((((1 << BLZ_SHIFT) - 1) << (8 - BLZ_SHIFT)

        public const uint BlzThreshold = 2; // max number of bytes to not encode
        public const uint BlzN = 0x1002; // max offset ((1 << 12) + 2)
        public const uint BlzF = 0x12; // max coded ((1 << 4) + BLZ_THRESHOLD)

        public const uint RawMinim = 0x00000000; // empty file, 0 bytes
        public const uint RawMaxim = 0x00FFFFFF; // 3-bytes length, 16MB - 1

        public const uint BlzMinim = 0x00000004; // header only (empty RAW file)
        public const uint BlzMaxim = 0x01400000; // 0x0120000A, padded to 20MB:
        // * length, RAW_MAXIM
        // * flags, (RAW_MAXIM + 7) / 8
        // * header, 11
        // 0x00FFFFFF + 0x00200000 + 12 + padding

        public int Arm9;
        public bool FileWasNotCompressed = false;

        /*----------------------------------------------------------------------------*/

/*
        private byte[] Load(string filename, out uint length, uint min, uint max)
        {
            var fi = new FileInfo(filename);
            if ((fi.Length < min) || (fi.Length > max))
            {
                throw new Exception("\nFile size error\n");
            }
            length = (uint) fi.Length;
            return File.ReadAllBytes(filename);
        }
*/

        /*----------------------------------------------------------------------------*/

/*
        private void Save(string filename, byte[] buffer, uint length)
        {
            if (buffer.Length == length)
            {
                File.WriteAllBytes(filename, buffer);
            }
            else
            {
                var b = new byte[length];
                for (int i = 0; i < length; ++i)
                {
                    b[i] = buffer[i];
                }
                File.WriteAllBytes(filename, b);
            }
        }
*/

        private static void BLZ_Invert(byte[] buffer, uint start, uint length)
        {
            var bottom = start + length - 1;

            while (start < bottom)
            {
                var ch = buffer[start];
                buffer[start++] = buffer[bottom];
                buffer[bottom--] = ch;
            }
        }

        /*----------------------------------------------------------------------------*/

        private static byte[] Memory(int length, int size)
        {
            return new byte[length*size];
        }

        /*----------------------------------------------------------------------------*/

        public byte[] BLZ_Decode(byte[] pakBuffer)
        {
            FileWasNotCompressed = false;
            uint len;
            byte flags = 0;

            //Console.Write( "- decoding" );

            var pakLen = (uint) pakBuffer.Length;


            var incLen = BitConverter.ToUInt32(pakBuffer, (int) pakLen - 4);
            if (incLen == 0)
            {
                throw new Exception("Not coded file!");
                /*enc_len = 0;
                dec_len = pak_len;
                pak_len = 0;
                raw_len = dec_len;

                fileWasNotCompressed = true;
                //Console.WriteLine();
                return pak_buffer;*/
            }
            if (pakLen < 8) throw new Exception("File has a bad header");
            uint hdrLen = pakBuffer[pakLen - 5];
            if ((hdrLen < 0x08) || (hdrLen > 0x0B)) throw new Exception("Bad header length");
            if (pakLen <= hdrLen) throw new Exception("Bad length");
            uint encLen = BitConverter.ToUInt32(pakBuffer, (int) pakLen - 8) & 0x00FFFFFF;
            uint decLen = pakLen - encLen;
            pakLen = encLen - hdrLen;
            uint rawLen = decLen + encLen + incLen;
            if (rawLen > RawMaxim) throw new Exception("Bad decoded length");

            byte[] rawBuffer = Memory((int) rawLen, 1);

            uint pak = 0;
            uint raw = 0;
            uint pakEnd = decLen + pakLen;
            uint rawEnd = rawLen;

            for (len = 0; len < decLen; len++)
            {
                rawBuffer[raw++] = pakBuffer[pak++];
            }

            BLZ_Invert(pakBuffer, decLen, pakLen);

            //Save( "init_pak", pak_buffer, pak_len );
            //Save( "init_raw", raw_buffer, raw_len );

            byte mask = 0;

            while (raw < rawEnd)
            {
                mask = (byte) (((uint) mask) >> ((int) BlzShift));

                if (mask == 0)
                {
                    if (pak == pakEnd) break;
                    flags = pakBuffer[pak++];
                    mask = BlzMask;
                }

                if ((flags & mask) == 0)
                {
                    if (pak == pakEnd) break;
                    //Console.WriteLine( "C# Copy pak " + pak + " to raw " + raw );
                    rawBuffer[raw++] = pakBuffer[pak++];
                }
                else
                {
                    if (pak + 1 >= pakEnd) break;
                    var pos = (uint) (pakBuffer[pak++] << 8);
                    pos |= pakBuffer[pak++];
                    len = (pos >> 12) + BlzThreshold + 1;
                    if (raw + len > rawEnd)
                    {
                        Console.Write(@", {0}", "WARNING: wrong decoded length!");
                        len = rawEnd - raw;
                    }
                    pos = (pos & 0xFFF) + 3;
                    while (len-- != 0)
                    {
                        //Console.WriteLine( "C# Copy raw " + (raw - pos) + " to raw " + raw );
                        rawBuffer[raw] = rawBuffer[raw - pos];
                        raw++;
                    }
                }
            }

            //Save( "post_pak", pak_buffer, pak_len );
            //Save( "post_raw", raw_buffer, raw_len );
            BLZ_Invert(rawBuffer, decLen, rawLen - decLen);
            //Save( "posti_pak", pak_buffer, pak_len );
            //Save( "posti_raw", raw_buffer, raw_len );

/*
            raw_len = raw;
*/

            if (raw != rawEnd) Console.Write(@", {0}", "WARNING: unexpected end of encoded file!");

            //Save( filename + ".dec", raw_buffer, raw_len );

            //Console.WriteLine();

            return rawBuffer;
        }

        //*----------------------------------------------------------------------------
        public byte[] BLZ_Encode(byte[] rawBuffer, uint mode)
        {
            uint newLen;

            //Console.Write("- encoding");

            var rawLen = (uint) rawBuffer.Length;

            var pakLen = BlzMaxim + 1;

            var newBuffer = BLZ_Code(rawBuffer, rawLen, out newLen, mode);
            if (newLen >= pakLen)
                throw new InsufficientMemoryException(string.Format("Can only compress up to {0} bytes but {1} were given.", pakLen, newLen));
            
            var pakBuffer = newBuffer;
            pakLen = newLen;

            //Save(filename + ".enc", pak_buffer, pak_len);

            if (pakBuffer.Length == pakLen)
                return pakBuffer;

            var retbuf = new byte[pakLen];
            for (var i = 0; i < pakLen; ++i)
            {
                retbuf[i] = pakBuffer[i];
            }
            pakBuffer = retbuf;

            //Console.WriteLine();

            return pakBuffer;
        }

        private static void Search(out uint l, ref uint p, ref byte[] rawBuffer, ref uint raw, ref uint rawEnd, out uint max,
            out uint pos, out uint len)
        {
            l = BlzThreshold;

            max = raw >= BlzN ? BlzN : raw;
            for (pos = 3; pos <= max; pos++)
            {
                for (len = 0; len < BlzF; len++)
                {
                    if (raw + len == rawEnd) break;
                    if (len >= pos) break;
                    if (rawBuffer[raw + len] != rawBuffer[raw + len - pos]) break;
                }

                if (len <= l)
                    continue;
                p = pos;
                if ((l = len) == BlzF) break;
            }

            len = 0;
        }

        //*----------------------------------------------------------------------------
        private byte[] BLZ_Code(byte[] rawBuffer, uint rawLen, out uint newLen, uint best)
        {
            uint len;
            var flg = 0u;
            var posBest = 0u;
            var posNext = 0u;
            var posPost = 0u;

            var pakTmp = 0u;
            var rawTmp = rawLen;

            var pakLen = rawLen + ((rawLen + 7)/8) + 11;
            var pakBuffer = Memory((int) pakLen, 1);

            var rawNew = rawLen;
            if (Arm9 != 0)
            {
                if (rawLen < 0x4000)
                {
                    Console.Write(", WARNING: ARM9 must be greater as 16KB, switch [9] disabled");
                    //} else if (
                    //	BitConverter.ToUInt32(raw_buffer, 0x0) != 0xE7FFDEFFu ||
                    //	BitConverter.ToUInt32(raw_buffer, 0x4) != 0xE7FFDEFFu ||
                    //	BitConverter.ToUInt32(raw_buffer, 0x8) != 0xE7FFDEFFu ||
                    //	BitConverter.ToUInt16(raw_buffer, 0xC) != 0xDEFFu
                    //) {
                    //	Console.Write(", WARNING: invalid Secure Area ID, switch [9] disabled");
                    //} else if (BitConverter.ToUInt16(raw_buffer, 0x7FE) != 0) {
                    //	Console.Write(", WARNING: invalid Secure Area 2KB end, switch [9] disabled");
                }
                else
                {
                    var crc = BLZ_CRC16(rawBuffer, 0x10, 0x07F0);
                    var crcbytes = BitConverter.GetBytes(crc);
                    if (!(rawBuffer[0x0E] == crcbytes[0] && rawBuffer[0x0F] == crcbytes[1]))
                    {
                        Console.WriteLine("WARNING: CRC16 Secure Area 2KB do not match");
                        rawBuffer[0x0E] = crcbytes[0];
                        rawBuffer[0x0F] = crcbytes[1];
                    }
                    rawNew -= 0x4000;
                }
            }

            BLZ_Invert(rawBuffer, 0, rawLen);

            uint pak = 0;
            uint raw = 0;
            var rawEnd = rawNew;

            byte mask = 0;

            while (raw < rawEnd)
            {
                mask = (byte) (((uint) mask) >> ((int) BlzShift));

                if (mask == 0)
                {
                    flg = pak++;
                    pakBuffer[flg] = 0;
                    mask = BlzMask;
                }

                uint lenBest;
                uint pos;
                uint max;
                Search(out lenBest, ref posBest, ref rawBuffer, ref raw, ref rawEnd, out max, out pos, out len);

                // LZ-CUE optimization start
                if (best != 0)
                {
                    if (lenBest > BlzThreshold)
                    {
                        if (raw + lenBest < rawEnd)
                        {
                            raw += lenBest;
                            uint lenNext;
                            Search(out lenNext, ref posNext, ref rawBuffer, ref raw, ref rawEnd, out max, out pos,
                                out len);
                            raw -= lenBest - 1;
                            uint lenPost;
                            Search(out lenPost, ref posPost, ref rawBuffer, ref raw, ref rawEnd, out max, out pos,
                                out len);
                            raw--;

                            if (lenNext <= BlzThreshold) lenNext = 1;
                            if (lenPost <= BlzThreshold) lenPost = 1;

                            if (lenBest + lenNext <= 1 + lenPost) lenBest = 1;
                        }
                    }
                }
                // LZ-CUE optimization end

                pakBuffer[flg] <<= 1;
                if (lenBest > BlzThreshold)
                {
                    raw += lenBest;
                    pakBuffer[flg] |= 1;
                    pakBuffer[pak] = (byte) (((lenBest - (BlzThreshold + 1)) << 4) | ((posBest - 3) >> 8));
                    pak++;
                    pakBuffer[pak] = (byte) ((posBest - 3) & 0xFF);
                    pak++;
                }
                else
                {
                    pakBuffer[pak] = rawBuffer[raw];
                    pak++;
                    raw++;
                }

                if (pak + rawLen - (raw) >= pakTmp + rawTmp)
                    continue;

                pakTmp = pak;
                rawTmp = rawLen - (raw);
            }

            while ((mask != 0) && (mask != 1))
            {
                mask = (byte) (((uint) mask) >> ((int) BlzShift));
                pakBuffer[flg] <<= 1;
            }

            pakLen = pak;

            BLZ_Invert(rawBuffer, 0, rawLen);
            BLZ_Invert(pakBuffer, 0, pakLen);

            if ((pakTmp == 0) || (rawLen + 4 < ((pakTmp + rawTmp + 3) & -4) + 8))
            {
                pak = 0;
                raw = 0;
                rawEnd = rawLen;

                while (raw < rawEnd)
                {
                    pakBuffer[pak] = rawBuffer[raw];
                    pak++;
                    raw++;
                }

                while ((pak & 3) != 0)
                {
                    pakBuffer[pak] = 0;
                    pak++;
                }

                pakBuffer[pak] = 0;
                pakBuffer[pak + 1] = 0;
                pakBuffer[pak + 2] = 0;
                pakBuffer[pak + 3] = 0;
                pak += 4;
            }
            else
            {
                var tmp = Memory((int) (rawTmp + pakTmp + 11), 1);

                for (len = 0; len < rawTmp; len++)
                    tmp[len] = rawBuffer[len];

                for (len = 0; len < pakTmp; len++)
                    tmp[rawTmp + len] = pakBuffer[len + pakLen - pakTmp];

/*
                pak = 0;
*/
                // TODO: Look up source code and make this equivalent to the original
                pakBuffer = tmp;

                //free(pak);

                pak = rawTmp + pakTmp;

                var encLen = pakTmp;
                var hdrLen = 8;
                var incLen = rawLen - pakTmp - rawTmp;

                while ((pak & 3) != 0)
                {
                    pakBuffer[pak] = 0xFF;
                    pak++;
                    hdrLen++;
                }

                //*(unsigned int *)pak = enc_len + hdr_len; pak += 3;
                //*pak++ = hdr_len;
                //*(unsigned int *)pak = inc_len - hdr_len; pak += 4;
                var tmpbyte = BitConverter.GetBytes(encLen + hdrLen);
                tmpbyte.CopyTo(pakBuffer, pak);
                pak += 3;
                pakBuffer[pak] = (byte) hdrLen;
                pak++;
                tmpbyte = BitConverter.GetBytes(incLen - hdrLen);
                tmpbyte.CopyTo(pakBuffer, pak);
                pak += 4;
            }

            //*new_len = pak - pak_buffer;
            newLen = pak;

            return (pakBuffer);
        }

        /*----------------------------------------------------------------------------*/

        //*----------------------------------------------------------------------------
        private static ushort BLZ_CRC16(byte[] buffer, uint bloc, uint length)
        {
            ushort crc = 0xFFFF;
            while ((length--) != 0)
            {
                crc ^= buffer[bloc++];
                uint nbits = 8;
                while ((nbits--) != 0)
                {
                    if ((crc & 1) != 0)
                    {
                        crc = (ushort) ((crc >> 1) ^ 0xA001);
                    }
                    else
                    {
                        crc = (ushort) (crc >> 1);
                    }
                }
            }

            return (crc);
        }

        /*----------------------------------------------------------------------------*/
        /*--  EOF                                           Copyright (C) 2011 CUE  --*/
        /*----------------------------------------------------------------------------*/
    }
}