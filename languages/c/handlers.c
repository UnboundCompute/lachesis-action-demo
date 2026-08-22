/*
 * C request handlers — classic memory-safety and injection bugs.
 *
 * NOTE ON THE CURRENT ACTION: these C defects are detected by the Lachesis
 * engine's candidate registry (buffer overflow -> memory.copy.capacity,
 * unbounded allocation -> memory.alloc.size), but the packaged Action's SARIF
 * export currently queries only the taint "security-paths" projection, which
 * does not yet stamp C sources/sinks. So today these show up when you run
 *   lachesis-candidates <graph.kuzu>
 * but NOT as GitHub code-scanning alerts. The C matrix leg in the workflow
 * prints the candidate census to the job summary to make that visible.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Buffer overflow: attacker-influenced read copied into a fixed 64-byte stack
 * buffer with strcpy, which does no bounds check. -> memory.copy.capacity */
void handle_name(int fd) {
  char buf[64];
  char input[4096];
  ssize_t n = read(fd, input, sizeof(input) - 1);
  if (n > 0) {
    input[n] = '\0';
    strcpy(buf, input); /* no bound: input can be far larger than buf */
    printf("hello %s\n", buf);
  }
}

/* Unbounded allocation: a size taken from the environment is passed to malloc
 * with no upper bound, so a huge value exhausts memory. -> memory.alloc.size */
char *handle_alloc(void) {
  const char *raw = getenv("BUFSIZE");
  long size = raw ? atol(raw) : 0; /* attacker controls size, no ceiling */
  char *p = (char *)malloc(size);
  if (p) {
    memset(p, 0, size);
  }
  return p;
}

/* Command injection: an environment-controlled string is handed to system().
 * getenv -> system with no validation. */
void handle_cmd(void) {
  const char *cmd = getenv("REPORT_CMD");
  if (cmd) {
    system(cmd); /* untrusted command executed by a shell */
  }
}

int main(void) {
  handle_name(0);
  free(handle_alloc());
  handle_cmd();
  return 0;
}
