/* htoprc parser + writer: the input is the user's ~/.config/htop/htoprc. */
#include "config.h"

#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "DynamicColumn.h"
#include "DynamicMeter.h"
#include "DynamicScreen.h"
#include "Hashtable.h"
#include "Machine.h"
#include "Settings.h"

/* defined in htop.c next to main(), which is not linked */
const char* program = PACKAGE;

static char scratchDir[PATH_MAX];
static char rcPath[PATH_MAX];
static Machine host;
static Hashtable* dynMeters;
static Hashtable* dynColumns;
static Hashtable* dynScreens;

static void cleanup(void) {
   unlink(rcPath);
   rmdir(scratchDir);
}

int LLVMFuzzerInitialize(int* argc, char*** argv) {
   (void)argc;
   (void)argv;
   const char* tmp = getenv("TMPDIR");
   snprintf(scratchDir, sizeof(scratchDir), "%s/htoprc-XXXXXX", tmp ? tmp : "/tmp");
   if (!mkdtemp(scratchDir))
      return 1;
   snprintf(rcPath, sizeof(rcPath), "%s/htoprc", scratchDir);
   setenv("HTOPRC", rcPath, 1);
   atexit(cleanup);

   /* Settings_defaultMeters() sizes the CPU meters from the active CPU count. */
   host.activeCPUs = 4;
   host.existingCPUs = 4;

   dynMeters = DynamicMeters_new();
   dynColumns = DynamicColumns_new();
   dynScreens = DynamicScreens_new();
   return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
   int fd = open(rcPath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
   if (fd < 0)
      return 0;
   size_t off = 0;
   while (off < size) {
      ssize_t n = write(fd, data + off, size - off);
      if (n <= 0)
         break;
      off += (size_t)n;
   }
   close(fd);

   Settings* settings = Settings_new(&host, dynMeters, dynColumns, dynScreens);
   Settings_write(settings, false);
   Settings_delete(settings);

   /* Re-read what the writer produced. */
   settings = Settings_new(&host, dynMeters, dynColumns, dynScreens);
   Settings_delete(settings);
   return 0;
}
