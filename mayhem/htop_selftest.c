/* Known-answer tests for the pieces the fuzz targets cover: the htoprc reader/writer, the line
 * editor and its history, and the /proc/<pid> readers. Prints one "ok"/"not ok" line per check and
 * a final "SUMMARY passed=<n> failed=<n>" line that mayhem/test.sh parses. */
#include "linux/LinuxProcessTable.c"

#include <curses.h>
#include <fcntl.h>
#include <stdlib.h>

#include "CRT.h"
#include "DynamicColumn.h"
#include "DynamicMeter.h"
#include "DynamicScreen.h"
#include "History.h"
#include "LineEditor.h"
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

static Machine plainHost;
static Hashtable *dm, *dc, *ds;

static Settings* loadSettings(const char* htoprc) {
   put("htoprc", htoprc, strlen(htoprc));
   return Settings_new(&plainHost, dm, dc, ds);
}

static void testSettings(void) {
   Settings* s = loadSettings(
      "config_reader_min_version=3\n"
      "hide_kernel_threads=0\n"
      "show_program_path=0\n"
      "highlight_changes=1\n"
      "highlight_changes_delay_secs=7\n"
      "delay=25\n"
      "color_scheme=2\n"
      "header_layout=two_67_33\n"
      "left_meters=Memory Swap\n"
      "left_meter_modes=1 1\n"
      "right_meters=Tasks LoadAverage\n"
      "right_meter_modes=2 2\n"
      "screen:Main=PID USER PERCENT_CPU COMM\n"
      ".sort_key=PERCENT_CPU\n"
      ".sort_direction=-1\n"
      ".tree_view=1\n"
      "screen:IO=PID IO_RATE\n"
      ".sort_key=IO_RATE\n");
   CHECK(s->delay == 25, "htoprc: delay=25");
   CHECK(!s->hideKernelThreads, "htoprc: hide_kernel_threads=0 overrides the default");
   CHECK(!s->showProgramPath, "htoprc: show_program_path=0");
   CHECK(s->highlightChanges && s->highlightDelaySecs == 7, "htoprc: highlight_changes with delay");
   CHECK(s->colorScheme == 2, "htoprc: color_scheme=2");
   CHECK(s->hLayout == HF_TWO_67_33, "htoprc: header_layout by name");
   CHECK(s->nScreens == 2, "htoprc: two screen: sections");
   CHECK(s->nScreens == 2 && String_eq(s->screens[0]->heading, "Main") && String_eq(s->screens[1]->heading, "IO"),
         "htoprc: screen headings");
   CHECK(s->nScreens == 2 && s->screens[0]->treeView && !s->screens[1]->treeView, ".tree_view applies to its own screen");
   CHECK(s->nScreens == 2 && s->screens[0]->sortKey == PERCENT_CPU && s->screens[0]->direction == -1,
         ".sort_key / .sort_direction");
   CHECK(s->nScreens == 2 && s->screens[0]->fields[0] == PID && s->screens[0]->fields[1] == USER &&
         s->screens[0]->fields[2] == PERCENT_CPU && s->screens[0]->fields[3] == PROC_COMM && s->screens[0]->fields[4] == 0,
         "screen fields keep their order and are zero terminated");

   CHECK(Settings_write(s, false) == 0, "Settings_write succeeds");
   Settings_delete(s);
   char* written = slurp("htoprc");
   CHECK(has(written, "delay=25\n"), "written file: delay=25");
   CHECK(has(written, "hide_kernel_threads=0\n"), "written file: hide_kernel_threads=0");
   CHECK(has(written, "highlight_changes_delay_secs=7\n"), "written file: highlight_changes_delay_secs=7");
   CHECK(has(written, "screen:Main=PID USER PERCENT_CPU COMM\n"), "written file: screen:Main fields");
   CHECK(has(written, "screen:IO=PID IO_RATE\n"), "written file: screen:IO fields");
   free(written);

   s = Settings_new(&plainHost, dm, dc, ds);
   CHECK(s->delay == 25 && s->nScreens == 2 && s->screens[0]->treeView && s->screens[1]->sortKey == IO_RATE,
         "round trip: reading the written file restores the settings");
   Settings_delete(s);

   s = loadSettings("config_reader_min_version=3\ndelay=9999\n");
   CHECK(s->delay == 255, "htoprc: delay is clamped to 255");
   Settings_delete(s);
   s = loadSettings("config_reader_min_version=3\ndelay=0\n");
   CHECK(s->delay == 1, "htoprc: delay is clamped to 1");
   Settings_delete(s);

   s = loadSettings("config_reader_min_version=3\nhide_kernel_threads=0\nthis line has no equals sign\n=\nunknown_option=5\n");
   CHECK(!s->hideKernelThreads, "htoprc: unknown and malformed lines are skipped");
   Settings_delete(s);

   s = loadSettings("config_reader_min_version=99\nhide_kernel_threads=0\ndelay=40\n");
   CHECK(s->hideKernelThreads && s->delay == DEFAULT_DELAY && s->nScreens >= 1,
         "htoprc from a newer format version is ignored in favour of the defaults");
   Settings_delete(s);

   s = loadSettings("");
   CHECK(s->nScreens >= 1 && s->hideKernelThreads, "empty htoprc yields the default screens");
   Settings_delete(s);
}

static void typeText(LineEditor* e, const char* text) {
   for (; *text; text++)
      LineEditor_handleKey(e, (unsigned char)*text);
}

static void testLineEditor(void) {
   LineEditor e;
   LineEditor_init(&e);
   typeText(&e, "hello");
   CHECK(String_eq(LineEditor_getText(&e), "hello") && LineEditor_getCursor(&e) == 5, "line editor: typing appends");
   LineEditor_handleKey(&e, KEY_LEFT);
   LineEditor_handleKey(&e, KEY_LEFT);
   CHECK(LineEditor_getCursor(&e) == 3, "line editor: left moves the cursor");
   CHECK(LineEditor_handleKey(&e, KEY_BACKSPACE), "line editor: backspace reports a change");
   CHECK(String_eq(LineEditor_getText(&e), "helo") && LineEditor_getCursor(&e) == 2, "line editor: backspace deletes before the cursor");
   LineEditor_handleKey(&e, KEY_HOME);
   typeText(&e, "X");
   CHECK(String_eq(LineEditor_getText(&e), "Xhelo"), "line editor: insert at home");
   LineEditor_handleKey(&e, KEY_END);
   LineEditor_handleKey(&e, KEY_CTRL('W'));
   CHECK(String_eq(LineEditor_getText(&e), ""), "line editor: ctrl-W deletes the word before the cursor");
   typeText(&e, "foo bar baz");
   LineEditor_handleKey(&e, KEY_CTRL('W'));
   CHECK(String_eq(LineEditor_getText(&e), "foo bar "), "line editor: ctrl-W keeps earlier words");
   LineEditor_handleKey(&e, KEY_CTRL('A'));
   LineEditor_handleKey(&e, KEY_CTRL('K'));
   CHECK(String_eq(LineEditor_getText(&e), "") && e.len == 0, "line editor: ctrl-K deletes to the end");

   LineEditor_initWithMax(&e, 3);
   typeText(&e, "abcdef");
   CHECK(String_eq(LineEditor_getText(&e), "abc"), "line editor: input stops at the maximum length");
   CHECK(!LineEditor_handleKey(&e, KEY_DC), "line editor: delete at the end changes nothing");
}

static void testHistory(void) {
   char p[PATH_MAX];
   path(p, "history");
   put("history", "one\ntwo\nthree\n", 14);
   History* h = History_new(p);
   CHECK(h->count == 3 && String_eq(h->entries[0], "one") && String_eq(h->entries[2], "three"), "history: loads the file");

   LineEditor e;
   LineEditor_init(&e);
   typeText(&e, "draft");
   const char* entry = History_navigate(h, &e, true);
   CHECK(entry && String_eq(entry, "three"), "history: up gives the newest entry");
   entry = History_navigate(h, &e, true);
   CHECK(entry && String_eq(entry, "two"), "history: up again gives the next older entry");
   entry = History_navigate(h, &e, false);
   CHECK(entry && String_eq(entry, "three"), "history: down returns to the newer entry");
   entry = History_navigate(h, &e, false);
   CHECK(entry && String_eq(entry, "draft"), "history: down past the newest restores the draft");
   CHECK(History_navigate(h, &e, false) == NULL, "history: down at the newest entry stops");

   History_add(h, "one");
   CHECK(h->count == 3 && String_eq(h->entries[2], "one") && String_eq(h->entries[0], "two"), "history: adding a duplicate moves it to the end");
   History_add(h, "");
   CHECK(h->count == 3, "history: empty entries are ignored");
   History_add(h, "four");
   History_save(h);
   History_delete(h);
   char* saved = slurp("history");
   CHECK(String_eq(saved, "two\nthree\none\nfour\n"), "history: saved file lists the entries oldest first");
   free(saved);

   put("history", "a\n\nb\n", 5);
   h = History_new(p);
   CHECK(h->count == 2 && String_eq(h->entries[1], "b"), "history: blank lines are not entries");
   History_delete(h);
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

int main(void) {
   const char* tmp = getenv("TMPDIR");
   snprintf(scratch, sizeof(scratch), "%s/htop-selftest-XXXXXX", tmp ? tmp : "/tmp");
   if (!mkdtemp(scratch)) {
      perror("mkdtemp");
      return 2;
   }
   char rc[PATH_MAX];
   path(rc, "htoprc");
   setenv("HTOPRC", rc, 1);

   plainHost.activeCPUs = 2;
   plainHost.existingCPUs = 2;
   dm = DynamicMeters_new();
   dc = DynamicColumns_new();
   ds = DynamicScreens_new();

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

   testSettings();
   testLineEditor();
   testHistory();
   testProcfs();

   char cmd[PATH_MAX + 16];
   snprintf(cmd, sizeof(cmd), "rm -rf '%s'", scratch);
   if (system(cmd) != 0)
      perror("cleanup");

   printf("SUMMARY passed=%d failed=%d\n", passed, failed);
   return failed ? 1 : 0;
}
