/* Search/filter line editor with its history file.
 *
 * Input: history-file bytes, one 0xFF byte (not valid UTF-8, so never part of a real history
 * file), then the key stream: two bytes per key, the low 9 bits being the ncurses key code. */
#include "config.h"

#include <curses.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "History.h"
#include "LineEditor.h"

/* defined in htop.c next to main(), which is not linked */
const char* program = PACKAGE;

static char scratchDir[PATH_MAX];
static char historyPath[PATH_MAX];

static void cleanup(void) {
   unlink(historyPath);
   rmdir(scratchDir);
}

int LLVMFuzzerInitialize(int* argc, char*** argv) {
   (void)argc;
   (void)argv;
   const char* tmp = getenv("TMPDIR");
   snprintf(scratchDir, sizeof(scratchDir), "%s/history-XXXXXX", tmp ? tmp : "/tmp");
   if (!mkdtemp(scratchDir))
      return 1;
   snprintf(historyPath, sizeof(historyPath), "%s/history", scratchDir);
   atexit(cleanup);
   return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
   const uint8_t* sep = memchr(data, 0xFF, size);
   size_t fileLen = sep ? (size_t)(sep - data) : size;
   const uint8_t* keys = sep ? sep + 1 : data + size;
   size_t keyBytes = (size_t)(data + size - keys);

   int fd = open(historyPath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
   if (fd < 0)
      return 0;
   size_t off = 0;
   while (off < fileLen) {
      ssize_t n = write(fd, data + off, fileLen - off);
      if (n <= 0)
         break;
      off += (size_t)n;
   }
   close(fd);

   History* history = History_new(historyPath);
   LineEditor editor;
   LineEditor_init(&editor);

   for (size_t i = 0; i + 1 < keyBytes; i += 2) {
      int ch = keys[i] | ((keys[i + 1] & 1) << 8);
      if (ch == KEY_UP || ch == KEY_DOWN) {
         const char* entry = History_navigate(history, &editor, ch == KEY_UP);
         if (entry)
            LineEditor_setText(&editor, entry);
      } else if (ch == '\r' || ch == KEY_ENTER) {
         const char* text = LineEditor_getText(&editor);
         if (text[0] != '\0')
            History_add(history, text);
         History_resetPosition(history);
         LineEditor_reset(&editor);
      } else if (ch == 27) {
         History_resetPosition(history);
         LineEditor_reset(&editor);
      } else {
         LineEditor_handleKey(&editor, ch);
      }
      LineEditor_updateScroll(&editor, 1 + (keys[i + 1] >> 1));
      LineEditor_click(&editor, keys[i] >> 2, keys[i + 1] >> 5);
   }

   History_save(history);
   History_delete(history);
   return 0;
}
