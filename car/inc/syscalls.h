
/**
 * @file syscalls.h
 * @author Zheyuan Ma
 * @brief eCTF UB Syscalls Hook
 * @date 2023
 *
 * @copyright Copyright (c) 2023 UB Cacti Lab
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef SYSCALLS_H
#define SYSCALLS_H

extern void __putchar(char ch);

int _read_r(struct _reent *r, int file, char *ptr, int len)
{
  r = r;
  file = file;
  ptr = ptr;
  len = len;
  errno = EINVAL;
  return -1;
}

int _sbrk_r(int incr)
{
  return 0;
}

int _lseek_r(struct _reent *r, int file, int ptr, int dir)
{
  r = r;
  file = file;
  ptr = ptr;
  dir = dir;

  return 0;
}

int _write_r(struct _reent *r, int file, char *ptr, int len)
{
  r = r;
  file = file;
  ptr = ptr;

#if 0
    int index;

    /* For example, output string by UART */
    for (index = 0; index < len; index++)
    {
        if (ptr[index] == '\n')
        {
            __putchar('\r');
        }

        __putchar(ptr[index]);
    }
#endif

  return len;
}

int _close_r(struct _reent *r, int file)
{
  return 0;
}

int _fstat_r(struct _reent *r, int file, struct stat *st)
{
  r = r;
  file = file;

  memset(st, 0, sizeof(*st));
  st->st_mode = S_IFCHR;
  return 0;
}

int _isatty_r(struct _reent *r, int fd)
{
  r = r;
  fd = fd;

  return 1;
}

void _exit(int a)
{
  a = a;

  while (1)
  {
  };
}

int _kill(int a, int b)
{
  a = a;
  b = b;

  return 0;
}

int _getpid(int a)
{
  a = a;

  return 0;
}

#endif /* SYSCALLS_H */
