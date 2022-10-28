
using System.IO.Compression;
using System.Text;

namespace SteamKit2
{
    static class ZipUtil
    {
        private static UInt32 LocalFileHeader = 0x04034b50;
        private static UInt32 CentralDirectoryHeader = 0x02014b50;
        private static UInt32 EndOfDirectoryHeader = 0x06054b50;

        private static UInt16 DeflateCompression = 8;
        private static UInt16 StoreCompression = 0;

        private static UInt16 Version = 20;

        public static byte[] Decompress( byte[] buffer )
        {
            using ( MemoryStream ms = new MemoryStream( buffer ) )
            using ( BinaryReader reader = new BinaryReader( ms ) )
            {
                if ( !PeekHeader( reader, LocalFileHeader ) )
                {
                    throw new Exception( "Expecting LocalFileHeader at start of stream" );
                }

                string fileName;
                UInt32 decompressedSize;
                UInt16 compressionMethod;
                uint crc;
                byte[] compressedBuffer = ReadLocalFile( reader, out fileName, out decompressedSize, out compressionMethod, out crc );

                if ( !PeekHeader( reader, CentralDirectoryHeader ) )
                {
                    throw new Exception( "Expecting CentralDirectoryHeader following filename" );
                }

                string cdrFileName;
                /*Int32 relativeOffset =*/ ReadCentralDirectory( reader, out cdrFileName );

                if ( !PeekHeader( reader, EndOfDirectoryHeader ) )
                {
                    throw new Exception( "Expecting EndOfDirectoryHeader following CentralDirectoryHeader" );
                }

                /*UInt32 count =*/ ReadEndOfDirectory( reader );

                byte[] decompressed;

                if ( compressionMethod == DeflateCompression )
                    decompressed = InflateBuffer( compressedBuffer, decompressedSize );
                else
                    decompressed = compressedBuffer;

                uint checkSum = Crc32.Compute( decompressed );

                if ( checkSum != crc )
                {
                    throw new Exception( "Checksum validation failed for decompressed file" );
                }

                return decompressed;
            }
        }

        private static bool PeekHeader( BinaryReader reader, UInt32 expecting )
        {
            UInt32 header = reader.ReadUInt32();

            return header == expecting;
        }

        private static UInt32 ReadEndOfDirectory( BinaryReader reader )
        {
            /*UInt16 diskNumber =*/ reader.ReadUInt16();
            /*UInt16 CDRDisk =*/ reader.ReadUInt16();
            UInt16 CDRCount = reader.ReadUInt16();
            /*UInt16 CDRTotal =*/ reader.ReadUInt16();

            /*UInt32 CDRSize =*/ reader.ReadUInt32();
            /*Int32 CDROffset =*/ reader.ReadInt32();

            UInt16 commentLength = reader.ReadUInt16();
            /*byte[] comment =*/ reader.ReadBytes( commentLength );

            return CDRCount;
        }

        private static Int32 ReadCentralDirectory( BinaryReader reader, out String fileName )
        {
            /*UInt16 versionGenerator =*/ reader.ReadUInt16();
            /*UInt16 versionExtract =*/ reader.ReadUInt16();
            /*UInt16 bitflags =*/ reader.ReadUInt16();
            UInt16 compression = reader.ReadUInt16();

            if ( compression != DeflateCompression && compression != StoreCompression )
            {
                throw new Exception( "Invalid compression method " + compression );
            }

            /*UInt16 modtime =*/ reader.ReadUInt16();
            /*UInt16 createtime =*/ reader.ReadUInt16();
            /*UInt32 crc =*/ reader.ReadUInt32();

            /*UInt32 compressedSize =*/ reader.ReadUInt32();
            /*UInt32 decompressedSize =*/ reader.ReadUInt32();

            UInt16 nameLength = reader.ReadUInt16();
            UInt16 fieldLength = reader.ReadUInt16();
            UInt16 commentLength = reader.ReadUInt16();

            /*UInt16 diskNumber =*/ reader.ReadUInt16();
            /*UInt16 internalAttributes =*/ reader.ReadUInt16();
            /*UInt32 externalAttributes =*/ reader.ReadUInt32();

            Int32 relativeOffset = reader.ReadInt32();

            byte[] name = reader.ReadBytes( nameLength );
            /*byte[] fields =*/ reader.ReadBytes( fieldLength );
            /*byte[] comment =*/ reader.ReadBytes( commentLength );

            fileName = Encoding.UTF8.GetString( name );
            return relativeOffset;
        }

        private static byte[] ReadLocalFile( BinaryReader reader, out String fileName, out UInt32 decompressedSize, out UInt16 compressionMethod, out UInt32 crc )
        {
            /*UInt16 version =*/ reader.ReadUInt16();
            /*UInt16 bitflags =*/ reader.ReadUInt16();
            compressionMethod = reader.ReadUInt16();

            if ( compressionMethod != DeflateCompression && compressionMethod != StoreCompression )
            {
                throw new Exception( "Invalid compression method " + compressionMethod );
            }

            /*UInt16 modtime =*/ reader.ReadUInt16();
            /*UInt16 createtime =*/ reader.ReadUInt16();
            crc = reader.ReadUInt32();

            UInt32 compressedSize = reader.ReadUInt32();
            decompressedSize = reader.ReadUInt32();

            UInt16 nameLength = reader.ReadUInt16();
            UInt16 fieldLength = reader.ReadUInt16();

            byte[] name = reader.ReadBytes( nameLength );
            /*byte[] fields =*/ reader.ReadBytes( fieldLength );

            fileName = Encoding.UTF8.GetString( name );

            return reader.ReadBytes( ( int )compressedSize );
        }


        private static byte[] InflateBuffer( byte[] compressedBuffer, UInt32 decompressedSize )
        {
            using ( MemoryStream ms = new MemoryStream( compressedBuffer ) )
            using ( DeflateStream deflateStream = new DeflateStream( ms, CompressionMode.Decompress ) )
            {
                byte[] inflated = new byte[ decompressedSize ];
                deflateStream.ReadAll( inflated );

                return inflated;
            }
        }

    }
}
