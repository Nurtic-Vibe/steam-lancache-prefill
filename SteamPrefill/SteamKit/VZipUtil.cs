namespace SteamKit2
{
    class VZipUtil
    {
        private static UInt16 VZipHeader = 0x5A56;
        private static UInt16 VZipFooter = 0x767A;
        private static int HeaderLength = 7;
        private static int FooterLength = 10;

        private static char Version = 'a';


        public static byte[] Decompress(byte[] buffer)
        {
            using (MemoryStream ms = new MemoryStream(buffer))
            using (BinaryReader reader = new BinaryReader(ms))
            {
                if (reader.ReadUInt16() != VZipHeader)
                {
                    throw new Exception("Expecting VZipHeader at start of stream");
                }

                if (reader.ReadChar() != Version)
                {
                    throw new Exception("Expecting VZip version 'a'");
                }

                // Sometimes this is a creation timestamp (e.g. for Steam Client VZips).
                // Sometimes this is a CRC32 (e.g. for depot chunks).
                /* uint creationTimestampOrSecondaryCRC = */ reader.ReadUInt32();

                byte[] properties = reader.ReadBytes(5);
                byte[] compressedBuffer = reader.ReadBytes((int)ms.Length - HeaderLength - FooterLength - 5);

                uint outputCRC = reader.ReadUInt32();
                uint sizeDecompressed = reader.ReadUInt32();

                if (reader.ReadUInt16() != VZipFooter)
                {
                    throw new Exception("Expecting VZipFooter at end of stream");
                }

                SevenZip.Compression.LZMA.Decoder decoder = new SevenZip.Compression.LZMA.Decoder();
                decoder.SetDecoderProperties(properties);

                using (MemoryStream inputStream = new MemoryStream(compressedBuffer))
                using (MemoryStream outStream = new MemoryStream((int)sizeDecompressed))
                {
                    decoder.Code(inputStream, outStream, compressedBuffer.Length, sizeDecompressed, null);

                    var outData = outStream.ToArray();
                    if (Crc32.Compute(outData) != outputCRC)
                    {
                        throw new InvalidDataException("CRC does not match decompressed data. VZip data may be corrupted.");
                    }

                    return outData;
                }
            }
        }
    }
}
