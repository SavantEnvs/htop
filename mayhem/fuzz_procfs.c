/* /proc/<pid>/* readers and command-line rendering.
 *
 * The readers are static in linux/LinuxProcessTable.c, so this file includes that .c directly and
 * build.sh leaves linux/LinuxProcessTable.o out of the link.
 *
 * Input: byte 0 picks which /proc/<pid> file the rest of the input stands in for, byte 1 holds
 * display-setting bits, the remainder is the file content. */
#include "linux/LinuxProcessTable.c"

#include <fcntl.h>
#include <stdlib.h>

#include "CRT.h"
#include "Object.h"
#include "RichString.h"
#include "linux/LinuxMachine.h"

/* defined in htop.c next to main(), which is not linked */
const char* program = PACKAGE;

static char scratchDir[PATH_MAX];
static int procFd = -1;
static LinuxMachine lhost;
static Settings settings;
static int colors[LAST_COLORELEMENT];

static void unlinkAll(void) {
   static const char* const names[] = {
      "stat", "status", "statm", "cgroup", "oom_score", "oom_adj", "oom_score_adj",
      "cmdline", "exe", "comm", "io", "maps", "smaps", "autogroup",
   };
   for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
      unlinkat(procFd, names[i], 0);
}

static void cleanup(void) {
   unlinkAll();
   rmdir(scratchDir);
}

int LLVMFuzzerInitialize(int* argc, char*** argv) {
   (void)argc;
   (void)argv;
   const char* tmp = getenv("TMPDIR");
   snprintf(scratchDir, sizeof(scratchDir), "%s/procfs-XXXXXX", tmp ? tmp : "/tmp");
   if (!mkdtemp(scratchDir))
      return 1;
   procFd = open(scratchDir, O_RDONLY | O_DIRECTORY);
   if (procFd < 0)
      return 1;
   atexit(cleanup);

   /* Process_writeCommand() reads CRT_colors, which CRT_init() would set up on a terminal. */
   for (int i = 0; i < LAST_COLORELEMENT; i++)
      colors[i] = i;
   CRT_colors = colors;

   settings.screenTabs = true;
   /* Process_makeCommandStr() skips processes whose merged command is not older than this stamp. */
   settings.lastUpdate = 1;
   lhost.super.settings = &settings;
   lhost.super.realtimeMs = 1000000;
   lhost.super.activeCPUs = 4;
   lhost.super.existingCPUs = 4;
   lhost.super.totalMem = 1 << 20;
   lhost.jiffies = 100;
   lhost.pageSize = 4096;
   lhost.pageSizeKB = 4;
   lhost.boottime = 1700000000;
   return 0;
}

static void putFile(const char* name, const uint8_t* data, size_t size) {
   int fd = openat(procFd, name, O_WRONLY | O_CREAT | O_TRUNC, 0600);
   if (fd < 0)
      return;
   size_t off = 0;
   while (off < size) {
      ssize_t n = write(fd, data + off, size - off);
      if (n <= 0)
         break;
      off += (size_t)n;
   }
   close(fd);
}

static void render(Process* process) {
   Process_makeCommandStr(process, &settings);
   RichString_begin(out);
   Process_writeCommand(process, 0, 0, &out);
   RichString_delete(&out);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
   if (size < 2)
      return -1;
   const unsigned sel = data[0] % 12;
   const uint8_t flags = data[1];
   const uint8_t* body = data + 2;
   const size_t bodyLen = size - 2;

   settings.showProgramPath = flags & 1;
   settings.showMergedCommand = flags & 2;
   settings.findCommInCmdline = flags & 4;
   settings.stripExeFromCmdline = flags & 8;
   settings.highlightBaseName = flags & 16;
   settings.highlightDeletedExe = flags & 32;
   settings.showThreadNames = flags & 64;
   settings.shadowDistPathPrefix = flags & 128;

   LinuxProcess* lp = (LinuxProcess*)LinuxProcess_new(&lhost.super);
   Process* process = &lp->super;

   switch (sel) {
   case 0: {
      /* A real stat line starts with the pid of the directory it was read from. */
      char* text = xMalloc(bodyLen + 1);
      memcpy(text, body, bodyLen);
      text[bodyLen] = '\0';
      Process_setPid(process, atoi(text));
      free(text);
      putFile("stat", body, bodyLen);
      char command[256];
      LinuxProcessTable_readStatFile(lp, procFd, &lhost, false, command, sizeof(command));
      break;
   }
   case 1:
      putFile("status", body, bodyLen);
      LinuxProcessTable_readStatusFile(process, procFd);
      break;
   case 2:
      putFile("statm", body, bodyLen);
      LinuxProcessTable_readStatmFile(lp, procFd, &lhost, NULL);
      break;
   case 3:
      putFile("cgroup", body, bodyLen);
      LinuxProcessTable_readCGroupFile(lp, procFd);
      break;
   case 4:
      putFile("oom_score", body, bodyLen);
      putFile("oom_adj", body, bodyLen);
      putFile("oom_score_adj", body, bodyLen);
      LinuxProcessTable_readOomData(lp, procFd, NULL);
      break;
   case 5:
      putFile("cmdline", body, bodyLen);
      LinuxProcessTable_readCmdlineFile(process, procFd, NULL);
      render(process);
      break;
   case 6: {
      /* exe is a symlink: the input is its target. */
      size_t len = strnlen((const char*)body, bodyLen);
      char* target = xMalloc(len + 1);
      memcpy(target, body, len);
      target[len] = '\0';
      if (len > 0 && len < PATH_MAX)
         (void)!symlinkat(target, procFd, "exe");
      free(target);
      LinuxProcessList_readExe(process, procFd, NULL);
      render(process);
      break;
   }
   case 7:
      putFile("comm", body, bodyLen);
      LinuxProcessList_readComm(process, procFd);
      render(process);
      break;
   case 8:
      putFile("io", body, bodyLen);
      LinuxProcessTable_readIoFile(lp, procFd, false);
      break;
   case 9:
      putFile("maps", body, bodyLen);
      LinuxProcessTable_readMaps(lp, procFd, &lhost, true, true);
      break;
   case 10:
      putFile("smaps", body, bodyLen);
      LinuxProcessTable_readSmapsFile(lp, procFd, false);
      break;
   default:
      putFile("autogroup", body, bodyLen);
      LinuxProcessTable_readAutogroup(lp, procFd, NULL);
      break;
   }

   Object_delete(process);
   unlinkAll();
   return 0;
}
