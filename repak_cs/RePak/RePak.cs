namespace RePak;

using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public enum Version : byte
{
    V0 = 0,
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
    V6 = 6,
    V7 = 7,
    V8A = 8,
    V8B = 9,
    V9 = 10,
    V10 = 11,
    V11 = 12
}

public enum Compression : byte
{
    Zlib,
    Gzip,
    Oodle,
    Zstd,
    LZ4
}

/// <summary>A game's deviations from the standard pak format; the values match repak_bind's.</summary>
public enum PakVariant : byte
{
    Standard = 0,
    MarvelRivals = 1
}

public class PakBuilder : SafeHandleZeroOrMinusOneIsInvalid
{
    public PakBuilder() : base(true)
    {
        SetHandle(RePakInterop.pak_builder_new());
    }
    protected override bool ReleaseHandle()
    {
        RePakInterop.pak_builder_drop(handle);
        return true;
    }

    public PakBuilder Key(byte[] key)
    {
        if (key.Length != 32) throw new Exception("Invalid AES key length");
        SetHandle(RePakInterop.pak_builder_key(handle, key));
        return this;
    }

    /// <summary>Selects a game's pak format; builders default to <see cref="PakVariant.Standard"/>.</summary>
    public PakBuilder Variant(PakVariant variant)
    {
        SetHandle(RePakInterop.pak_builder_variant(handle, (byte)variant));
        if (handle == IntPtr.Zero) throw new Exception($"Unknown pak variant {variant}");
        return this;
    }

    public PakBuilder Compression(Compression[] compressions)
    {
        SetHandle(RePakInterop.pak_builder_compression(handle, compressions.Select(c => Convert.ToByte(c)).ToArray(), compressions.Length));
        return this;
    }

    public PakWriter Writer(Stream stream, Version version = Version.V11, string mountPoint = "../../../", ulong pathHashSeed = 0)
    {
        if (handle == IntPtr.Zero) throw new Exception("PakBuilder handle invalid");

        var streamCtx = StreamCallbacks.Create(stream);

        IntPtr writerHandle = RePakInterop.pak_builder_writer(handle, streamCtx, version, mountPoint, pathHashSeed);

        // pak_builder_reader consumes the builder
        SetHandleAsInvalid();
        SetHandle(IntPtr.Zero);

        return new PakWriter(writerHandle, streamCtx.Context);
    }

    public PakReader Reader(Stream stream)
    {
        if (handle == IntPtr.Zero) throw new Exception("PakBuilder handle invalid");

        var streamCtx = StreamCallbacks.Create(stream);

        IntPtr readerHandle = RePakInterop.pak_builder_reader(handle, streamCtx);
        StreamCallbacks.Free(streamCtx.Context);

        // pak_builder_reader consumes the builder
        SetHandleAsInvalid();
        SetHandle(IntPtr.Zero);

        if (readerHandle == IntPtr.Zero) throw new Exception("Failed to create PakReader");
        return new PakReader(readerHandle, stream);
    }
}

public class PakWriter : SafeHandleZeroOrMinusOneIsInvalid
{
    private IntPtr _streamCtx;

    public PakWriter(IntPtr handle, IntPtr streamCtx) : base(true)
    {
        SetHandle(handle);
        _streamCtx = streamCtx;
    }
    protected override bool ReleaseHandle()
    {
        RePakInterop.pak_writer_drop(handle);
        StreamCallbacks.Free(_streamCtx);
        return true;
    }

    public void WriteFile(string path, byte[] data)
    {
        if (handle == IntPtr.Zero) throw new Exception("PakWriter handle invalid");
        int result = RePakInterop.pak_writer_write_file(handle, path, data, data.Length);
        if (result != 0) throw new Exception("Failed to write file");
    }

    public void WriteIndex()
    {
        int result = RePakInterop.pak_writer_write_index(handle);

        // write_index drops the writer
        SetHandleAsInvalid();
        SetHandle(IntPtr.Zero);
        StreamCallbacks.Free(_streamCtx);

        if (result != 0) throw new Exception("Failed to write index");
    }
}

public class PakReader : SafeHandleZeroOrMinusOneIsInvalid
{
    public PakReader(IntPtr handle, Stream stream) : base(true)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        RePakInterop.pak_reader_drop(handle);
        return true;
    }

    public string GetMountPoint()
    {
        if (handle == IntPtr.Zero) throw new Exception("PakReader handle invalid");

        var cstring = RePakInterop.pak_reader_mount_point(handle);
        var mountPoint = Marshal.PtrToStringAnsi(cstring);

        RePakInterop.pak_cstring_drop(cstring);

        return mountPoint ?? throw new InvalidOperationException("repak returned no mount point");
    }

    public Version GetVersion()
    {
        if (handle == IntPtr.Zero) throw new Exception("PakReader handle invalid");

        return RePakInterop.pak_reader_version(handle);
    }

    public byte[] Get(Stream stream, string path)
    {
        if (handle == IntPtr.Zero) throw new Exception("PakReader handle invalid");

        var streamCtx = StreamCallbacks.Create(stream);

        IntPtr bufferPtr;
        ulong length;
        IntPtr errorPtr;
        int result = RePakInterop.pak_reader_get(handle, path, streamCtx, out bufferPtr, out length, out errorPtr);

        StreamCallbacks.Free(streamCtx.Context);

        if (result != 0)
        {
            var message = Marshal.PtrToStringUTF8(errorPtr);
            if (errorPtr != IntPtr.Zero) RePakInterop.pak_cstring_drop(errorPtr);
            throw new Exception($"Failed to get file: {message}");
        }

        byte[] buffer = new byte[length];
        Marshal.Copy(bufferPtr, buffer, 0, (int)length);

        RePakInterop.pak_buffer_drop(bufferPtr, length);

        return buffer;
    }

    public string[] Files()
    {
        if (handle == IntPtr.Zero) throw new Exception("PakReader handle invalid");

        ulong length;
        IntPtr filesPtr = RePakInterop.pak_reader_files(handle, out length);
        var files = new List<string>();
        try
        {
            for (ulong i = 0; i < length; i++)
            {
                IntPtr currentPtr = Marshal.ReadIntPtr(filesPtr, (int)i * IntPtr.Size);
                files.Add(Marshal.PtrToStringAnsi(currentPtr) ?? throw new InvalidOperationException("repak returned a null file name"));
            }
        }
        finally
        {
            RePakInterop.pak_drop_files(filesPtr, length);
        }
        return files.ToArray();
    }
}


public class StreamCallbacks
{
    public static RePakInterop.StreamCallbacks Create(Stream stream)
    {
        return new RePakInterop.StreamCallbacks
        {
            Context = GCHandle.ToIntPtr(GCHandle.Alloc(stream)),
            ReadCb = StreamCallbacks.ReadCallback,
            WriteCb = StreamCallbacks.WriteCallback,
            SeekCb = StreamCallbacks.SeekCallback,
            FlushCb = StreamCallbacks.FlushCallback
        };
    }
    public static void Free(IntPtr streamCtx)
    {
        GCHandle.FromIntPtr(streamCtx).Free();
    }

    // An exception must not cross into native code, so each callback looks the stream up inside its
    // try and reports a failure through its error return value.
    private static Stream StreamOf(IntPtr context) =>
        GCHandle.FromIntPtr(context).Target as Stream
            ?? throw new InvalidOperationException("Stream callback invoked after its stream was released");

    public static long ReadCallback(IntPtr context, IntPtr buffer, ulong bufferLen)
    {
        try
        {
            var stream = StreamOf(context);
            byte[] bufferManaged = new byte[bufferLen];
            int bytesRead = stream.Read(bufferManaged, 0, (int)bufferLen);
            Marshal.Copy(bufferManaged, 0, buffer, bytesRead);
            return bytesRead;
        }
        catch (Exception e)
        {
            Console.WriteLine($"Error during read {e}");
            return -1;
        }
    }

    public static int WriteCallback(IntPtr context, IntPtr buffer, int bufferLen)
    {
        try
        {
            var stream = StreamOf(context);
            var bufferManaged = new byte[bufferLen];
            Marshal.Copy(buffer, bufferManaged, 0, bufferLen);
            stream.Write(bufferManaged, 0, bufferLen);
            return bufferLen;
        }
        catch (Exception e)
        {
            Console.WriteLine($"Error during write {e}");
            return -1;
        }
    }

    public static ulong SeekCallback(IntPtr context, long offset, int origin)
    {
        try
        {
            var stream = StreamOf(context);
            long newPosition = stream.Seek(offset, (SeekOrigin)origin);
            return (ulong)newPosition;
        }
        catch (Exception e)
        {
            Console.WriteLine($"Error during seek {e}");
            return ulong.MaxValue;
        }
    }

    public static int FlushCallback(IntPtr context)
    {
        try
        {
            var stream = StreamOf(context);
            stream.Flush();
            return 0;
        }
        catch (Exception e)
        {
            Console.WriteLine($"Error during flush {e}");
            return 1;
        }
    }
}
