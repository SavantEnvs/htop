/* Known-answer tests for the pieces the fuzz target covers: the /proc/<pid> readers and the command screen. Prints one "ok"/"not ok" line per check and
 * a final "SUMMARY passed=<n> failed=<n>" line that mayhem/test.sh parses. */
#include "linux/LinuxProcessTable.c"

#include <curses.h>
#include <fcntl.h>
#include <stdlib.h>

#include "CRT.h"
#include "CommandScreen.h"
#include "ProvideCurses.h"
#include "Object.h"
#include "RichString.h"
#include "linux/LinuxMachine.h"

/* defined in htop.c next to main(), which is not linked */
const char* program = PACKAGE;

static int passed;
static int failed;

#define CHECK(cond, name) check((cond), (name), __LINE__)

static void check(bool cond, const char* name, int line) {
   if (cond) {
      passed++;
      printf("ok %d - %s\n", passed + failed, name);
   } else {
      failed++;
      printf("not ok %d - %s (line %d)\n", passed + failed, name, line);
   }
}

static char scratch[PATH_MAX];

static void path(char* out, const char* name) {
   snprintf(out, PATH_MAX, "%s/%s", scratch, name);
}

static void put(const char* name, const char* data, size_t len) {
   char p[PATH_MAX];
   path(p, name);
   FILE* fp = fopen(p, "w");
   if (!fp) {
      perror(p);
      exit(2);
   }
   fwrite(data, 1, len, fp);
   fclose(fp);
}

static char* slurp(const char* name) {
   char p[PATH_MAX];
   path(p, name);
   FILE* fp = fopen(p, "r");
   if (!fp)
      return xStrdup("");
   char* buf = xCalloc(1, 65536);
   size_t n = fread(buf, 1, 65535, fp);
   buf[n] = '\0';
   fclose(fp);
   return buf;
}

static bool has(const char* haystack, const char* needle) {
   return strstr(haystack, needle) != NULL;
}

static LinuxMachine lhost;
static Settings settings;
static int colors[LAST_COLORELEMENT];

static void testProcfs(void) {
   int procFd = open(scratch, O_RDONLY | O_DIRECTORY);
   CHECK(procFd >= 0, "scratch /proc directory opens");

   LinuxProcess* lp = (LinuxProcess*)LinuxProcess_new(&lhost.super);
   Process* p = &lp->super;
   const char stat[] =
      "4242 (my (prog)) S 1 4242 4200 34816 4242 4194560 100 200 3 4 700 300 50 25 20 0 3 0 123456 10240000 500 "
      "18446744073709551615 1 1 0 0 0 0 0 4096 0 0 0 0 17 5 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
   put("stat", stat, strlen(stat));
   Process_setPid(p, 4242);
   char command[128];
   bool ok = LinuxProcessTable_readStatFile(lp, procFd, &lhost, false, command, sizeof(command));
   CHECK(ok, "stat: parses a full line");
   CHECK(String_eq(command, "my (prog)"), "stat: comm may contain parentheses");
   CHECK(p->state == SLEEPING, "stat: state S is sleeping");
   CHECK(Process_getParent(p) == 1 && p->pgrp == 4242 && p->session == 4200, "stat: ppid, pgrp, session");
   CHECK(p->tty_nr == 34816 && p->tpgid == 4242, "stat: tty_nr, tpgid");
   CHECK(p->minflt == 100 && lp->cminflt == 200 && p->majflt == 3 && lp->cmajflt == 4, "stat: fault counters");
   CHECK(lp->utime == 700 && lp->stime == 300 && lp->cutime == 50 && lp->cstime == 25, "stat: times");
   CHECK(p->time == 1000, "stat: process time is utime + stime");
   CHECK(p->priority == 20 && p->nice == 0 && p->nlwp == 3, "stat: priority, nice, nlwp");
   CHECK(p->processor == 5, "stat: processor");
   CHECK(p->starttime_ctime == 1700000000 + 1234, "stat: start time is boot time plus ticks");
   CHECK(!LinuxProcessTable_readStatFile(lp, procFd, &lhost, true, command, sizeof(command)), "stat: a missing task/<pid>/stat fails");

   put("stat", "4242 (truncated", 15);
   CHECK(!LinuxProcessTable_readStatFile(lp, procFd, &lhost, false, command, sizeof(command)), "stat: a truncated line fails");

   const char statm[] = "2500 500 120 30 0 200 0\n";
   put("statm", statm, strlen(statm));
   CHECK(LinuxProcessTable_readStatmFile(lp, procFd, &lhost, NULL), "statm: parses seven fields");
   CHECK(p->m_virt == 10000 && p->m_resident == 2000, "statm: pages become KiB");
   CHECK(lp->m_share == 120 && lp->m_trs == 30 && lp->m_drs == 200 && lp->m_priv == 2000 - 120 * 4, "statm: shared, text, data, private");

   const char status[] =
      "Name:\tmy prog\nNSpid:\t4242\t17\nvoluntary_ctxt_switches:\t10\nnonvoluntary_ctxt_switches:\t4\n";
   put("status", status, strlen(status));
   CHECK(LinuxProcessTable_readStatusFile(p, procFd), "status: parses");
   CHECK(lp->ctxt_total == 14 && lp->ctxt_diff == 14, "status: context switches are summed");
   CHECK(p->isRunningInContainer == TRI_ON, "status: two NSpid entries mean a container");

   const char cgroup[] = "0::/system.slice/docker-0123456789abcdef.scope\n";
   put("cgroup", cgroup, strlen(cgroup));
   LinuxProcessTable_readCGroupFile(lp, procFd);
   CHECK(lp->cgroup && String_eq(lp->cgroup, "/system.slice/docker-0123456789abcdef.scope"), "cgroup: unified hierarchy path");

   put("oom_score", "666\n", 4);
   put("oom_adj", "3\n", 2);
   put("oom_score_adj", "-250\n", 5);
   LinuxProcessTable_readOomData(lp, procFd, NULL);
   CHECK(lp->oom == 666, "oom: oom_score");

   Object_delete(p);

   lp = (LinuxProcess*)LinuxProcess_new(&lhost.super);
   p = &lp->super;
   static const char cmdline[] = "/usr/bin/python3\0-m\0http.server\0";
   put("cmdline", cmdline, sizeof(cmdline) - 1);
   CHECK(LinuxProcessTable_readCmdlineFile(p, procFd, NULL), "cmdline: parses");
   CHECK(p->cmdline && String_eq(p->cmdline, "/usr/bin/python3\n-m\nhttp.server"), "cmdline: arguments are separated by newlines");
   CHECK(p->cmdlineBasenameStart == 9 && p->cmdlineBasenameEnd == 16, "cmdline: program basename bounds");
   settings.showMergedCommand = false;
   settings.showProgramPath = true;
   settings.lastUpdate++;
   Process_makeCommandStr(p, &settings);
   CHECK(p->mergedCommand.str && String_eq(p->mergedCommand.str, "/usr/bin/python3 -m http.server"), "command string: path and arguments");
   settings.showProgramPath = false;
   p->mergedCommand.lastUpdate = 0;
   settings.lastUpdate++;
   Process_makeCommandStr(p, &settings);
   CHECK(p->mergedCommand.str && String_eq(p->mergedCommand.str, "python3 -m http.server"), "command string: hidden program path");
   {
      RichString_begin(rs);
      Process_writeCommand(p, 0, 0, &rs);
      CHECK(RichString_sizeVal(rs) == (int)strlen("python3 -m http.server"), "command rendering: length of the visible command");
      RichString_delete(&rs);
   }
   Object_delete(p);

   lp = (LinuxProcess*)LinuxProcess_new(&lhost.super);
   p = &lp->super;
   put("comm", "kworker/0:1\n", 12);
   LinuxProcessList_readComm(p, procFd);
   CHECK(p->procComm && String_eq(p->procComm, "kworker/0:1"), "comm: trailing newline is dropped");
   Object_delete(p);

   close(procFd);
}

static int lineCount(CommandScreen* cs) {
   return Panel_size(cs->super.display);
}

static const char* lineText(CommandScreen* cs, int i) {
   return ListItem_getRef((ListItem*)Panel_get(cs->super.display, i));
}

/* Lays commands out on a screen COLS wide and checks the wrapped lines. */
static void testCommandScreen(void) {
   int procFd = open(scratch, O_RDONLY | O_DIRECTORY);
   CHECK(procFd >= 0, "command screen: scratch /proc directory opens");

   /* 8 words of 9 letters, single-space separated: 79 characters. A 40-column screen holds 4 words
    * (39 characters) per line, wrapped at the last space. */
   static const char words[] = "aaaaaaaaa\0bbbbbbbbb\0ccccccccc\0ddddddddd\0eeeeeeeee\0fffffffff\0ggggggggg\0hhhhhhhhh";
   put("cmdline", words, sizeof(words) - 1);
   LinuxProcess* lp = (LinuxProcess*)LinuxProcess_new(&lhost.super);
   Process* p = &lp->super;
   CHECK(LinuxProcessTable_readCmdlineFile(p, procFd, NULL), "command screen: cmdline parses");
   settings.showMergedCommand = false;
   settings.showProgramPath = true;
   settings.lastUpdate++;
   Process_makeCommandStr(p, &settings);
   CHECK(p->mergedCommand.str && String_eq(p->mergedCommand.str, "aaaaaaaaa bbbbbbbbb ccccccccc ddddddddd eeeeeeeee fffffffff ggggggggg hhhhhhhhh"),
         "command screen: merged command joins the arguments with spaces");

   CommandScreen* cs = CommandScreen_new(p);
   InfoScreen_scan(&cs->super);
   CHECK(lineCount(cs) == 2, "command screen: a long command wraps onto two lines");
   if (lineCount(cs) == 2) {
      CHECK(String_eq(lineText(cs, 0), "aaaaaaaaa bbbbbbbbb ccccccccc ddddddddd"), "command screen: first line breaks at the last space");
      CHECK(String_eq(lineText(cs, 1), " eeeeeeeee fffffffff ggggggggg hhhhhhhhh"), "command screen: second line holds the rest, from the space it broke at");
   }
   Object_delete(cs);
   Object_delete(p);

   /* A short command stays on one line. */
   static const char shortCmd[] = "/bin/ls\0-l";
   put("cmdline", shortCmd, sizeof(shortCmd) - 1);
   lp = (LinuxProcess*)LinuxProcess_new(&lhost.super);
   p = &lp->super;
   CHECK(LinuxProcessTable_readCmdlineFile(p, procFd, NULL), "command screen: short cmdline parses");
   settings.lastUpdate++;
   Process_makeCommandStr(p, &settings);
   cs = CommandScreen_new(p);
   InfoScreen_scan(&cs->super);
   CHECK(lineCount(cs) == 1 && String_eq(lineText(cs, 0), "/bin/ls -l"), "command screen: a short command is one line");
   Object_delete(cs);
   Object_delete(p);

   close(procFd);
}

int main(void) {
   const char* tmp = getenv("TMPDIR");
   snprintf(scratch, sizeof(scratch), "%s/htop-selftest-XXXXXX", tmp ? tmp : "/tmp");
   if (!mkdtemp(scratch)) {
      perror("mkdtemp");
      return 2;
   }
   COLS = 40;
   LINES = 24;

   for (int i = 0; i < LAST_COLORELEMENT; i++)
      colors[i] = i;
   CRT_colors = colors;
   settings.screenTabs = true;
   settings.findCommInCmdline = true;
   settings.stripExeFromCmdline = true;
   lhost.super.settings = &settings;
   lhost.super.realtimeMs = 1000000;
   lhost.super.activeCPUs = 2;
   lhost.jiffies = 100;
   lhost.pageSize = 4096;
   lhost.pageSizeKB = 4;
   lhost.boottime = 1700000000;

   testProcfs();
   testCommandScreen();

   char cmd[PATH_MAX + 16];
   snprintf(cmd, sizeof(cmd), "rm -rf '%s'", scratch);
   if (system(cmd) != 0)
      perror("cleanup");

   printf("SUMMARY passed=%d failed=%d\n", passed, failed);
   return failed ? 1 : 0;
}
