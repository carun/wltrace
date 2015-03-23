Similar to linux's ltrace and VC++'s Spy program, this allows the tracing of Win32 calls made by a program during it's execution.

This can be useful for determining what a program actually does during its execution, and finding out where error conditions are arising (eg which win32 registry calls return errors).

Code is written in C++, and uses native Win32 debugging calls (this is not a cygwin hack). Code is reasonably well laid out, so it should be easy to cannibalise it for other projects.

It's slightly non-standard in the way it handles the hooking of DLLs (effectively creating a jump table in the target process' address space), but it works reasonably quickly.

Notes on usage and configuration files contained in the project itself. Required Visual C++ v6.0.