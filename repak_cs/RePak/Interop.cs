namespace RePak;

using System;
using System.Runtime.InteropServices;

/// <summary>
/// The repak_bind exports. Sizes are <c>nuint</c>/<c>nint</c> because the Rust side takes and
/// returns <c>usize</c>/<c>isize</c>: a 32-bit value in a 64-bit register leaves its upper half
/// undefined. Strings are UTF-8 both ways.
/// </summary>
internal static class RePakInterop
{
    public const string NativeLib = "repak_bind";

    /// <summary>Takes this thread's most recent native error message; free it with <see cref="pak_cstring_drop"/>.</summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr pak_last_error();

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr pak_builder_new();

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pak_builder_drop(IntPtr builder);
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pak_reader_drop(IntPtr reader);
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pak_writer_drop(IntPtr writer);
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pak_buffer_drop(IntPtr buffer, nuint length);
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pak_cstring_drop(IntPtr cstring);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr pak_builder_key(IntPtr builder, byte[] key);
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr pak_builder_variant(IntPtr builder, byte variant);
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr pak_builder_compression(IntPtr builder, byte[] compressions, nuint length);
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr pak_builder_reader_ex(IntPtr builder, StreamCallbacks ctx, out IntPtr error_message);
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr pak_builder_writer(IntPtr builder, StreamCallbacks ctx, Version version, [MarshalAs(UnmanagedType.LPUTF8Str)] string mount_point, ulong path_hash_seed = 0);

    /// <summary>The pak's <see cref="Version"/>, or 255 on failure.</summary>
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern byte pak_reader_version(IntPtr reader);
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr pak_reader_mount_point(IntPtr reader);
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern int pak_reader_get(IntPtr reader, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, StreamCallbacks ctx, out IntPtr buffer, out nuint length, out IntPtr error_message);
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr pak_reader_files(IntPtr reader, out nuint length);
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pak_drop_files(IntPtr buffer, nuint length);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern int pak_writer_write_file(IntPtr writer, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, byte[] data, nuint data_len);
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern int pak_writer_write_index(IntPtr writer);

    // Each callback mirrors the Rust field it fills; a negative result is a failure.
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate nint ReadCallback(IntPtr context, IntPtr buffer, nuint bufferLen);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate nint WriteCallback(IntPtr context, IntPtr buffer, nuint bufferLen);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate long SeekCallback(IntPtr context, long offset, int origin);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int FlushCallback(IntPtr context);

    [StructLayout(LayoutKind.Sequential)]
    public struct StreamCallbacks
    {
        public IntPtr Context;
        public ReadCallback ReadCb;
        public WriteCallback WriteCb;
        public SeekCallback SeekCb;
        public FlushCallback FlushCb;
    }
}
