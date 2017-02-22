// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Security.Cryptography;
using System.Text;

namespace Internal.Cryptography.Pal
{
    internal sealed partial class X509Pal
    {
        private static readonly byte[] s_pemHyphens = Encoding.ASCII.GetBytes("-----");
        private static readonly byte[] s_pemBegin = Encoding.ASCII.GetBytes("BEGIN ");
        private static readonly byte[] s_pemEnd = Encoding.ASCII.GetBytes("END ");

        private static byte[] PemToDer(byte[] rawData)
        {
            // PEM armor is 5 hyphens, the word BEGIN, a space, another word
            // (1 or more characters), 5 hyphens, some base64 data, 5 hyphens,
            // the word END, a space, theoretically the same word as before, and
            // 5 hyphens.
            //
            // So, 20 hyphens, 2 spaces, 2 other characters, BEGIN (5) and END (3).
            // 20 + 2 + 2 + 5 + 3 => 32

            if (rawData.Length < 32)
                return null;

            int offset = 0;

            // Experimentation with OpenSSL (1.0.2g) says that
            // 1) The character before the PEM armor must be BOF or a newline character.
            //   1a) Other whitespace is allowed before the newline
            // 2) No extra spaces are allowed in the PEM armor
            // 3) The newlines are mandatory
            // 4) The END word and BEGIN word must match.

            while (offset < rawData.Length && char.IsWhiteSpace((char)rawData[offset]))
            {
                offset++;
            }

            if (!SequenceEquals(s_pemHyphens, rawData, ref offset))
                return null;

            if (!SequenceEquals(s_pemBegin, rawData, ref offset))
                return null;

            while (offset < rawData.Length && rawData[offset] != (byte)'-')
            {
                offset++;
            }

            if (!SequenceEquals(s_pemHyphens, rawData, ref offset))
                return null;

            int base64Start = offset;

            // The Base64 character set does not include hyphen, so scan until we see one.

            while (offset < rawData.Length && rawData[offset] != (byte)'-')
            {
                offset++;
            }

            int base64Length = offset - base64Start;

            if (!SequenceEquals(s_pemHyphens, rawData, ref offset))
                return null;

            if (!SequenceEquals(s_pemEnd, rawData, ref offset))
                return null;

            // We could validate that the set of bytes is the same as in the BEGIN header,
            // but if we're just going to pass the original input down to the native layer
            // we can leave that validation to them.
            while (offset < rawData.Length && rawData[offset] != (byte)'-')
            {
                offset++;
            }

            if (!SequenceEquals(s_pemHyphens, rawData, ref offset))
                return null;

            return ConvertBase64(rawData, base64Start, base64Length);
        }

        private static byte[] ConvertBase64(byte[] rawData)
        {
            return ConvertBase64(rawData, 0, rawData.Length);
        }

        private static byte[] ConvertBase64(byte[] rawData, int index, int count)
        {
            char[] charData = Encoding.ASCII.GetChars(rawData, index, count);

            try
            {
                return Convert.FromBase64CharArray(charData, 0, charData.Length);
            }
            catch (FormatException)
            {
                return null;
            }
        }

        private static bool ScanContentInfo(DerSequenceReader reader, string targetOid)
        {
            if (!reader.HasTag(DerSequenceReader.DerTag.ObjectIdentifier))
                return false;

            string oidValue = reader.ReadOidAsString();

            if (oidValue != targetOid)
                return false;

            if (!reader.HasTag(DerSequenceReader.ContextSpecificConstructedTag0))
                return false;

            reader.SkipValue();

            // If there's still more data it's not a ContentInfo.
            return !reader.HasData;
        }

        private static bool SequenceEquals(byte[] expected, byte[] candidate, ref int offset)
        {
            if (candidate.Length - offset < expected.Length)
                return false;

            for (int i = 0; i < expected.Length; i++)
            {
                if (expected[i] != candidate[i + offset])
                {
                    return false;
                }
            }

            offset += expected.Length;
            return true;
        }
    }
}
