/* A C program that pulls a broad slice of the C library into a static link:
   formatted I/O, strings, memory, sorting, time, environment and locale. */
#include <ctype.h>
#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int compare(const void *a, const void *b) {
  return strcmp(*(const char *const *)a, *(const char *const *)b);
}

int main(int argc, char **argv) {
  setlocale(LC_ALL, "");
  char *buffer = malloc(256);
  if (!buffer)
    return errno;
  time_t now = time(NULL);
  struct tm parts;
  gmtime_r(&now, &parts);
  strftime(buffer, 256, "%Y-%m-%d %H:%M:%S", &parts);
  printf("%s %s %d %.3f\n", buffer, argv[0], argc, strtod("2.5", NULL));
  qsort(argv, (size_t)argc, sizeof *argv, compare);
  for (int i = 0; i < argc; ++i)
    fprintf(stderr, "%zu %s\n", strlen(argv[i]), argv[i]);
  const char *home = getenv("HOME");
  snprintf(buffer, 256, "%s/%s", home ? home : "", "probe");
  for (char *c = buffer; *c; ++c)
    *c = (char)toupper((unsigned char)*c);
  char *copy = strdup(buffer);
  puts(strstr(copy, "PROBE") ? copy : buffer);
  long value = strtol(argc > 1 ? argv[1] : "42", NULL, 10);
  char *grown = realloc(copy, 1024);
  memset(grown, 'x', 1023);
  grown[1023] = '\0';
  sscanf("7 8", "%ld %ld", &value, &value);
  free(grown);
  free(buffer);
  return (int)(value & 1);
}
