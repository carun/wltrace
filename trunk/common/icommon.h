/*
    LTRACE32.C -- cruddy win32 trace program.

    Copyright (C) 2002 	johnbrazel@gmail.com

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef _ICOMMON_H
#define _ICOMMON_H

/* The size of the array passed to EnumProcessModules() is hardcoded,
 * as there is *NO* way to determine what size it should be before
 * calling routine (No, Anastasia, you can't pass in a NULL pointer
 * and read the lpcbNeeded parameter, it will segfault sooner or later).
 */ 

#define ENUMPROC_SZ		4096

#endif /* _ICOMMON_H */
