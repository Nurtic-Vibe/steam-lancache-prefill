namespace SteamPrefill.SteamKit
{
    static class Util
    {
        // Validate a file against Steam3 Chunk data
        //public static List<ChunkData> ValidateSteam3FileChecksums(FileStream fs, ChunkData[] chunkdata)
        //{
        //    var neededChunks = new List<ChunkData>();
        //    int read;

        //    foreach (var data in chunkdata)
        //    {
        //        var chunk = new byte[data.UncompressedLength];
        //        fs.Seek((long)data.Offset, SeekOrigin.Begin);
        //        read = fs.Read(chunk, 0, (int)data.UncompressedLength);

        //        byte[] tempchunk;
        //        if (read < data.UncompressedLength)
        //        {
        //            tempchunk = new byte[read];
        //            Array.Copy(chunk, 0, tempchunk, 0, read);
        //        }
        //        else
        //        {
        //            tempchunk = chunk;
        //        }

        //        var adler = AdlerHash(tempchunk);
        //        if (!adler.SequenceEqual(data.Checksum))
        //        {
        //            neededChunks.Add(data);
        //        }
        //    }

        //    return neededChunks;
        //}

        public static byte[] AdlerHash(byte[] input)
        {
            uint a = 0, b = 0;
            for (var i = 0; i < input.Length; i++)
            {
                a = (a + input[i]) % 65521;
                b = (b + a) % 65521;
            }

            return BitConverter.GetBytes(a | b << 16);
        }

        public static byte[] SHAHash(byte[] input)
        {
            using (var sha = SHA1.Create())
            {
                var output = sha.ComputeHash(input);

                return output;
            }
        }

        //public static byte[] DecodeHexString(string hex)
        //{
        //    if (hex == null)
        //        return null;

        //    var chars = hex.Length;
        //    var bytes = new byte[chars / 2];

        //    for (var i = 0; i < chars; i += 2)
        //        bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);

        //    return bytes;
        //}

        public static string EncodeHexString(byte[] input)
        {
            return input.Aggregate(new StringBuilder(),
                (sb, v) => sb.Append(v.ToString("x2"))
            ).ToString();
        }

    }
}
