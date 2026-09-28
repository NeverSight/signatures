/* A program that pulls zlib's compression and checksums into a static link. */
#include <stdio.h>
#include <string.h>
#include <zlib.h>

int main(int argc, char **argv) {
  unsigned char text[4096], packed[8192], unpacked[4096];
  for (size_t i = 0; i < sizeof text; ++i)
    text[i] = (unsigned char)(argv[0][i % strlen(argv[0])] + i / 64);
  uLongf packed_size = sizeof packed, unpacked_size = sizeof unpacked;
  if (compress2(packed, &packed_size, text, sizeof text, argc) != Z_OK)
    return 1;
  if (uncompress(unpacked, &unpacked_size, packed, packed_size) != Z_OK)
    return 2;
  z_stream stream;
  memset(&stream, 0, sizeof stream);
  deflateInit2(&stream, 9, Z_DEFLATED, 31, 9, Z_FILTERED);
  stream.next_in = text;
  stream.avail_in = sizeof text;
  stream.next_out = packed;
  stream.avail_out = sizeof packed;
  deflate(&stream, Z_FINISH);
  deflateEnd(&stream);
  gzFile file = gzopen("/dev/null", "wb");
  gzprintf(file, "%lu", (unsigned long)packed_size);
  gzclose(file);
  printf("%lu %lu %08lx %08lx %s\n", (unsigned long)packed_size,
         (unsigned long)stream.total_out, crc32(0, text, sizeof text),
         adler32(1, unpacked, (uInt)unpacked_size), zlibVersion());
  return memcmp(text, unpacked, sizeof text) != 0;
}
