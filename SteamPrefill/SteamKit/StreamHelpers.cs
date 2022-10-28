using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Text;

namespace SteamKit2
{
    internal static class StreamHelpers
    {
        [ThreadStatic]
        static byte[]? data;

#if NET5_0_OR_GREATER
        [MemberNotNull(nameof(data))]
#endif

        public static int ReadAll( this Stream stream, byte[] buffer )
        {
            int bytesRead;
            int totalRead = 0;
            while ( ( bytesRead = stream.Read( buffer, totalRead, buffer.Length - totalRead ) ) != 0 )
            {
                totalRead += bytesRead;
            }
            return totalRead;
        }
    }
}
