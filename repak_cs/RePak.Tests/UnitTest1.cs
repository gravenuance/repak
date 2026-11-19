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
            var error = Assert.Throws<Exception>(() => pak_reader.Get(stream, "missing.txt"));
            Assert.Contains("No entry found at missing.txt", error.Message);
        }
    }
}
