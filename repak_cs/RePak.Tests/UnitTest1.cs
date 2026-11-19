namespace RePak.Tests;

using System.IO;
using System.Text;

public class UnitTest1
{
    [Fact]
    public void TestLeaks()
    {
        var key = Convert.FromBase64String("lNJbw660IOC+kU7cnVQ1oeqrXyhk4J6UAZrCBbcnp94=");

        using (PakBuilder builder = new PakBuilder())
        {
            builder.Compression(new Compression[] { Compression.Zlib });
            using (var stream = new FileStream("output.pak", FileMode.Create))
            {
                using (var writer = builder.Writer(stream))
                {
                    writer.WriteFile("a_file1.txt", Encoding.ASCII.GetBytes("some file contents"));
                    writer.WriteFile("a_file2.txt", Encoding.ASCII.GetBytes("another file with contents"));
                    writer.WriteFile("a_file3.txt", Encoding.ASCII.GetBytes("last file with some contents"));
                    writer.WriteFile("a_file4.txt", Encoding.ASCII.GetBytes("lol jk one more"));
                    writer.WriteIndex();
                }
                Console.WriteLine($"Bytes written={stream.Length}");
            }
        }

        using (PakBuilder builder = new PakBuilder())
        {
            using (var fileStream = new FileStream("../../../../../repak/tests/packs/pack_v11_compress_encrypt_encryptindex.pak", FileMode.Open))
            {
                builder.Key(key);
                using (var reader = builder.Reader(fileStream))
                {
                    Console.WriteLine($"MountPoint = {reader.GetMountPoint()}");
                    Console.WriteLine($"Version = {reader.GetVersion()}");
                    foreach (var file in reader.Files())
                    {
                        Console.WriteLine($"File={file} Contents={Encoding.ASCII.GetString(reader.Get(fileStream, file)).Substring(0, 10)}...");
                    }
                }
            }
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
    }

    [Fact]
    public void TestLz4RoundTrip()
    {
        // Rust's Compression::LZ4 is the fifth variant of a #[repr(u8)] enum.
        Assert.Equal(4, (byte)Compression.LZ4);
        var contents = Encoding.ASCII.GetBytes(new string('a', 1000));
        using var stream = new MemoryStream();
        using (var builder = new PakBuilder())
        {
            builder.Compression(new[] { Compression.LZ4 });
            using var writer = builder.Writer(stream);
            writer.WriteFile("lz4.txt", contents);
            writer.WriteIndex();
        }

        using (var builder = new PakBuilder())
        {
            using var reader = builder.Reader(stream);
            Assert.Equal(contents, reader.Get(stream, "lz4.txt"));
        }
    }

    private static readonly byte[] MarvelKey = Enumerable.Repeat((byte)7, 32).ToArray();
    private static readonly byte[] MarvelContents = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("some file contents", 100)));

    private static MemoryStream WriteMarvelRivalsPak()
    {
        var stream = new MemoryStream();
        using var builder = new PakBuilder();
        builder.Key(MarvelKey).Variant(PakVariant.MarvelRivals);
        using var writer = builder.Writer(stream);
        writer.WriteFile("a/file.txt", MarvelContents);
        writer.WriteIndex();
        return stream;
    }

    [Fact]
    public void TestMarvelRivalsRoundTrip()
    {
        using var stream = WriteMarvelRivalsPak();

        using var builder = new PakBuilder();
        builder.Key(MarvelKey).Variant(PakVariant.MarvelRivals);
        using var reader = builder.Reader(stream);
        Assert.Equal(MarvelContents, reader.Get(stream, "a/file.txt"));
    }

    [Fact]
    public void TestStandardVariantDoesNotReadAMarvelRivalsPak()
    {
        using var stream = WriteMarvelRivalsPak();

        byte[]? read = null;
        Record.Exception(() =>
        {
            using var builder = new PakBuilder();
            builder.Key(MarvelKey);
            using var reader = builder.Reader(stream);
            read = reader.Get(stream, "a/file.txt");
        });
        Assert.NotEqual(MarvelContents, read);
    }

    [Fact]
    public void TestNonAsciiEntryNamesRoundTrip()
    {
        var names = new[] { "é.txt", "日本語/ファイル.txt", "plain.txt" };
        using var stream = new MemoryStream();
        using (var builder = new PakBuilder())
        {
            using var writer = builder.Writer(stream);
            foreach (var name in names) writer.WriteFile(name, Encoding.UTF8.GetBytes("contents of " + name));
            writer.WriteIndex();
        }

        using (var builder = new PakBuilder())
        {
            using var reader = builder.Reader(stream);
            Assert.Equal(names.Order(StringComparer.Ordinal), reader.Files().Order(StringComparer.Ordinal));
            foreach (var name in names)
                Assert.Equal("contents of " + name, Encoding.UTF8.GetString(reader.Get(stream, name)));
        }
    }

    private sealed class FailingStream : MemoryStream
    {
        public override void Write(ReadOnlySpan<byte> buffer) => throw new IOException("disk full");
    }

    [Fact]
    public void TestStreamThatThrowsOnWriteGivesAManagedException()
    {
        using var stream = new FailingStream();
        using var builder = new PakBuilder();
        using var writer = builder.Writer(stream);

        var error = Assert.Throws<RePakException>(() => writer.WriteFile("a.txt", new byte[] { 1, 2, 3 }));
        var inner = Assert.IsType<IOException>(error.InnerException);
        Assert.Equal("disk full", inner.Message);
    }

    [Fact]
    public void TestALaterFailureDoesNotCarryAnEarlierStreamException()
    {
        using var stream = new FailsDifferentlyStream();
        using var builder = new PakBuilder();
        using var writer = builder.Writer(stream);

        var first = Assert.Throws<RePakException>(() => writer.WriteFile("a.txt", new byte[] { 1, 2, 3 }));
        Assert.IsType<IOException>(first.InnerException);
        var later = Assert.Throws<RePakException>(() => writer.WriteFile("b.txt", new byte[] { 1 }));
        Assert.IsType<InvalidOperationException>(later.InnerException);
    }

    private sealed class FailsDifferentlyStream : MemoryStream
    {
        private int _writes;

        public override void Write(ReadOnlySpan<byte> buffer) =>
            throw (_writes++ == 0 ? new IOException("disk full") : new InvalidOperationException("closed"));
    }

    [Fact]
    public void TestAnInteriorNulInANameIsRefused()
    {
        using var stream = new MemoryStream();
        using var builder = new PakBuilder();
        using var writer = builder.Writer(stream);

        // Marshalling would cut the name at the NUL and write "b" instead.
        Assert.Throws<ArgumentException>(() => writer.WriteFile("b\0c.txt", new byte[] { 1 }));
    }

    [Fact]
    public void TestStreamThatThrowsOnReadGivesAManagedException()
    {
        using var builder = new PakBuilder();
        var error = Assert.Throws<RePakException>(() => builder.Reader(new ThrowingReadStream()));
        Assert.IsType<NotSupportedException>(error.InnerException);
    }

    private sealed class ThrowingReadStream() : MemoryStream(new byte[300])
    {
        public override int Read(Span<byte> buffer) => throw new NotSupportedException("no reads");
    }

    [Fact]
    public void TestUnknownCompressionIsAnError()
    {
        using var builder = new PakBuilder();
        var error = Assert.Throws<RePakException>(() => builder.Compression(new[] { Compression.Zlib, (Compression)99 }));
        Assert.Contains("99 is not a compression method", error.Message);
    }

    [Fact]
    public void TestUnknownVersionIsAnError()
    {
        using var builder = new PakBuilder();
        var error = Assert.Throws<RePakException>(() => builder.Writer(new MemoryStream(), (Version)200));
        Assert.Contains("200 is not a pak version", error.Message);
    }

    [Fact]
    public void TestGarbageIsNotAPak()
    {
        using var builder = new PakBuilder();
        using var stream = new MemoryStream(Enumerable.Repeat((byte)0xAB, 300).ToArray());
        Assert.Throws<RePakException>(() => builder.Reader(stream));
    }

    [Fact]
    public void TestWriteIndexTwiceIsRefused()
    {
        using var stream = new MemoryStream();
        using var builder = new PakBuilder();
        using var writer = builder.Writer(stream);
        writer.WriteIndex();
        Assert.Throws<InvalidOperationException>(() => writer.WriteIndex());
        Assert.Throws<InvalidOperationException>(() => writer.WriteFile("late.txt", new byte[] { 1 }));
    }

    [Fact]
    public void TestWritePak()
    {
        Console.WriteLine("Writing pak");
        using (FileStream stream = new FileStream("output2.pak", FileMode.Create))
        {
            var builder = new RePak.PakBuilder();
            var pak_writer = builder.Writer(stream);
            pak_writer.WriteFile("a_file.txt", Encoding.ASCII.GetBytes("some file contents\n"));
            pak_writer.WriteFile("another_file.txt", Encoding.ASCII.GetBytes("lorem ipsum\ndolor sit\n"));
            pak_writer.WriteFile("nested/file.txt", Encoding.ASCII.GetBytes("hello world\n"));
            pak_writer.WriteIndex();
        }
        Console.WriteLine("Reading pak");
        using (FileStream stream = new FileStream("output2.pak", FileMode.Open))
        {
            var builder = new RePak.PakBuilder();
            var pak_reader = builder.Reader(stream);
            foreach (var file in pak_reader.Files())
            {
                Console.WriteLine($"File: {file}");
                var bytes = pak_reader.Get(stream, file);
                Console.WriteLine($"Contents: {Encoding.ASCII.GetString(bytes)}");
            }
            Assert.Equal("hello world\n", Encoding.ASCII.GetString(pak_reader.Get(stream, "nested/file.txt")));
            var error = Assert.Throws<RePakException>(() => pak_reader.Get(stream, "missing.txt"));
            Assert.Contains("No entry found at missing.txt", error.Message);
        }
    }
}
