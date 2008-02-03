#ifndef _HOOKPATTERN_H
#define _HOOKPATTERN_H

/* exported */
extern int SetHookPattern(void*, char *exe, char *library, char *function);
/* internal */
extern BOOL DoExeLib(struct trace_block*, char *basename, char *libname, void **ptr);
extern BOOL DoFn(char *fn, void *ptr);

#endif /* _HOOKPATTERN_H */
