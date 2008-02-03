#include <windows.h>
#include <stdio.h>
#include "parse.h"

/* typedef char *(ContentHandler)(DWORD*, struct param*, HANDLE, int); */

ContentHandler hex_handler;
ContentHandler int_handler;
ContentHandler uint_handler;
ContentHandler dwptr_handler;
ContentHandler pptr_handler;
ContentHandler string_handler;
ContentHandler ustring_handler;
ContentHandler data_handler;
ContentHandler snmp_handler;
ContentHandler sockaddrin_handler;
ContentHandler objattr_handler;

struct type_defn types_list[]={
	{ "int", int_handler },
	{ "uint", uint_handler },
	{ "flags", hex_handler },
	{ "ptr", hex_handler },
	{ "dword_ptr", dwptr_handler },
	{ "pptr", pptr_handler },
	{ "string",	string_handler },
	{ "ustring",	ustring_handler },
	{ "buffer",	data_handler },
	{ "snmpvarbindlist", snmp_handler },
	{ "snmpop",	snmp_handler },
	{ "snmpid", snmp_handler },
	{ "sockaddr_in", sockaddrin_handler },
	{ "pobject_attributes", objattr_handler },
	{ NULL, NULL }
};

#ifndef TYPE_NAMES_ONLY

#include "ptrace.h"
#include "write.h"

static char hexbuf[11];

char*
hex_handler(DWORD *arg, struct param *argtype, HANDLE proc, int direction)
{
	sprintf(hexbuf,"0x%08x",*arg);
	return hexbuf;
}

char*
int_handler(DWORD *arg, struct param *argtype, HANDLE proc, int direction)
{
	static char intbuf[11];
	sprintf(intbuf, "%i", *arg);
	return intbuf;
}

char*
uint_handler(DWORD *arg, struct param *argtype, HANDLE proc, int direction)
{
	static char intbuf[11];
	sprintf(intbuf, "%u", *arg);
	return intbuf;
}

char*
dwptr_handler(DWORD *arg, struct param *argtype, HANDLE proc, int direction)
{
	DWORD len, value;

	sprintf(hexbuf,"0x%08x",*arg);

	if (direction == 0 && argtype->direction == OUT_ARG)
	{
		return hexbuf;
	}

	if (!ReadProcessMemory(proc, (LPCVOID)*arg, &value, sizeof(value), &len))
	{
		WinPerror("ReadProcessMemory(arg<dword_ptr>)");
		return hexbuf;
	}

	sprintf(hexbuf, "%lu", value);
	return hexbuf;
}

char*
pptr_handler(DWORD *arg, struct param *argtype, HANDLE proc, int direction)
{
	DWORD len, value;

	sprintf(hexbuf,"0x%08x",*arg);

	if (direction == 0 && argtype->direction == OUT_ARG)
	{
		return hexbuf;
	}

	if (!ReadProcessMemory(proc, (LPCVOID)*arg, &value, sizeof(value), &len))
	{
		WinPerror("ReadProcessMemory(arg<pptr>)");
		return hexbuf;
	}

	sprintf(hexbuf, "%08x", value);
	return hexbuf;
}

static int
strnlen(char *data, int buf_sz)
{
	int i = buf_sz;
	while(*data++ && buf_sz)
		buf_sz--;
	return (i - buf_sz);
}

char*
string_handler(DWORD *arg, struct param *argtype, HANDLE proc, int direction)
{
	static char strbuf[128];
	DWORD len;
	int e;

	if (*arg == 0)
		return "NULL";

	if (direction == 0 && argtype->direction == OUT_ARG)
	{
		sprintf(hexbuf,"0x%08x",*arg);
		return hexbuf;
	}

	strbuf[0]='"';

	if (ReadProcessMemory(proc, (LPCVOID)*arg, strbuf+1, sizeof(strbuf)-3, &len) == 0 &&
		GetLastError() != ERROR_PARTIAL_COPY)
	{
		WinPerror("ReadProcessMemory(arg<string>)");
		sprintf(hexbuf,"0x%08x",*arg);
		return hexbuf;
	}

	e = strnlen(strbuf,sizeof(strbuf));

	if (e >= sizeof(strbuf))
	{
		strcpy(&strbuf[sizeof(strbuf)-5],"...\"");
	}
	else
	{
		strcpy(&strbuf[e], "\"");
	}
	return strbuf;
}

static int
ustrnlen(char *data, int buf_sz)
{
	int len = 0;

	while((*data || *(data+1)) && buf_sz)
	{
		buf_sz -= 2;
		data += 2;
		len++;
	}
	return len;
}

char*
ustring_handler(DWORD *arg, struct param *argtype, HANDLE proc, int direction)
{
	static char strbuf[64],wbuf[128];
	DWORD len;
	int e, i;

	if (*arg == 0)
		return "NULL";

	if (direction == 0 && argtype->direction == OUT_ARG)
	{
		sprintf(hexbuf,"0x%08x",*arg);
		return hexbuf;
	}

	strbuf[0]='"';

	if (ReadProcessMemory(proc, (LPCVOID)*arg, wbuf, sizeof(wbuf), &len) == 0 &&
		GetLastError() != ERROR_PARTIAL_COPY)
	{
		WinPerror("ReadProcessMemory(arg<ustring>)");
		sprintf(hexbuf,"0x%08x",*arg);
		return hexbuf;
	}

	e = ustrnlen(wbuf,sizeof(wbuf));

	for(i=0; i < e; i++)
	{
		strbuf[i+1] = wbuf[(i*2)];
	}

	if (e >= sizeof(wbuf)/2)
	{
		strcpy(&strbuf[sizeof(strbuf)-5],"...\"");
	}
	else
	{
		strcpy(&strbuf[e+1], "\"");
	}
	return strbuf;
}

char*
data_handler(DWORD *arg, struct param *argtype, HANDLE proc, int direction)
{
	static char strbuf[518];
	unsigned char inbuf[128];
	DWORD out_len, in_len, e;

	if (*arg == 0)
		return "NULL";

	if (direction == 0 && argtype->direction == OUT_ARG)
	{
		sprintf(hexbuf,"0x%08x",*arg);
		return hexbuf;
	}

	strcpy(strbuf, "\"");
	in_len = arg[1];

	if (in_len > sizeof(inbuf))
	{
		in_len = sizeof(inbuf);
	}

	if (ReadProcessMemory(proc, (LPCVOID)*arg, inbuf, in_len, &out_len) == 0 &&
		GetLastError() != ERROR_PARTIAL_COPY)
	{
		WinPerror("ReadProcessMemory(arg<buffer>)");
		sprintf(hexbuf,"0x%08x",*arg);
		return hexbuf;
	}

	if (in_len > out_len)
	{
		in_len = out_len;
	}

	for(e = 0; e < in_len; e++)
	{
		if ((inbuf[e] > 127) || !isprint(inbuf[e]))
		{
			char hexbuf[5];

			if (sizeof(strbuf) - 3 - strlen(strbuf) < 5)
				break;

			sprintf(hexbuf,"\\x%02x", (int)inbuf[e] & 0xff);
			strcat(strbuf, hexbuf);
		}
		else
		{
			unsigned short charbuf = (unsigned short)inbuf[e] & 0xff;

			/* XXX this only works on little-endian machines */
			strcat(strbuf,(const char*)&charbuf);
		}
	}

	if (arg[1] > in_len)
	{
		strcat(strbuf,"\"...");
	}
	else
	{
		strcat(strbuf, "\"");
	}
 
	return strbuf;
}

#define SFCOPY(a,b,c) (sizeof(b) - (int)(a - b) >= c)

	/* Types purloined from MSVC++ includes */

#pragma pack(4)

typedef struct {
	BYTE * stream;     
	UINT   length;     
	BOOL   dynamic;    
} AsnOctetString;

typedef struct {
	UINT   idLength;   
	UINT * ids;        
} AsnObjectIdentifier;

typedef LONG                    AsnInteger32;
typedef ULONG                   AsnUnsigned32;
typedef ULARGE_INTEGER          AsnCounter64;
typedef AsnUnsigned32           AsnCounter32;
typedef AsnUnsigned32           AsnGauge32;
typedef AsnUnsigned32           AsnTimeticks;
typedef AsnOctetString          AsnBits;
typedef AsnOctetString          AsnSequence;
typedef AsnOctetString          AsnImplicitSequence;
typedef AsnOctetString          AsnIPAddress;
typedef AsnOctetString          AsnNetworkAddress;
typedef AsnOctetString          AsnDisplayString;
typedef AsnOctetString          AsnOpaque;

typedef struct {
	BYTE asnType;
	union {
		AsnInteger32            number;     // ASN_INTEGER
		AsnUnsigned32           unsigned32; // ASN_UNSIGNED32
		AsnCounter64            counter64;  // ASN_COUNTER64
		AsnOctetString          string;     // ASN_OCTETSTRING
		AsnBits                 bits;       // ASN_BITS
		AsnObjectIdentifier     object;     // ASN_OBJECTIDENTIFIER
		AsnSequence             sequence;   // ASN_SEQUENCE
		AsnIPAddress            address;    // ASN_IPADDRESS
		AsnCounter32            counter;    // ASN_COUNTER32
		AsnGauge32              gauge;      // ASN_GAUGE32
		AsnTimeticks            ticks;      // ASN_TIMETICKS
		AsnOpaque               arbitrary;  // ASN_OPAQUE
	} asnValue;
} AsnObjectSyntax;

typedef struct {
	AsnObjectIdentifier   name;     
	AsnObjectSyntax  value;    
} SnmpVarBind;

typedef struct {
	SnmpVarBind * list;     
	UINT          len;      
} SnmpVarBindList;

#define ASN_INTEGER                 0x02
#define ASN_BITS                    0x03
#define ASN_OCTETSTRING             0x04
#define ASN_NULL                    0x05
#define ASN_OBJECTIDENTIFIER        0x06
#define ASN_IPADDRESS               0x40
#define ASN_COUNTER32               0x41
#define ASN_GAUGE32                 0x42
#define ASN_TIMETICKS               0x43
#define ASN_OPAQUE                  0x44
#define ASN_COUNTER64               0x46
#define ASN_UNSIGNED32              0x47

#pragma pack()

static char*
snmpid_handler(HANDLE proc, AsnObjectIdentifier *item)
{
	UINT name_components[64];
	static char buf[512], *p;

	p = buf;

	while(item->idLength > 0)
	{
		/* try and limit the number of memory copies */

		int u = item->idLength, w;
		if (u > 64) u = 64;

		ReadMemory(proc, item->ids, name_components, u*sizeof(UINT));
		item->ids = &item->ids[u];
		item->idLength -= u;

		for(w=0;w<u;w++)
		{
			if (SFCOPY(p, buf, 12))
			{
				sprintf(p, "%d.", name_components[w]);
				p += strlen(p);
			}
		}
	}

	*(--p) = '\0';
	return buf;
}

char*
snmp_handler(DWORD *arg, struct param *argtype, HANDLE proc, int direction)
{
	if (!strcmp(argtype->type->type_name, "snmpid"))
	{
		AsnObjectIdentifier item;

		if (direction == 0 && argtype->direction == OUT_ARG)
		{
			sprintf(hexbuf,"0x%08x",*arg);
			return hexbuf;
		}

		ReadMemory(proc, (LPVOID)*arg, &item, sizeof(item));
		return snmpid_handler(proc, &item);
		//return "ptr";
	}
	if (!strcmp(argtype->type->type_name, "snmpvarbindlist"))
	{
		static char buf[512], *p, *q;
		SnmpVarBind item;
		SnmpVarBindList list;
		UINT i;

		if (direction == 0 && argtype->direction == OUT_ARG)
		{
			sprintf(hexbuf,"0x%08x",*arg);
			return hexbuf;
		}

		ReadMemory(proc, (LPVOID)*arg, &list, sizeof(list));
		strcpy(buf, "{ ");
		p = buf + 2;

		for(i=0;i<list.len;i++)
		{
			ReadMemory(proc, &list.list[i], &item, sizeof(item));

			if (SFCOPY(p, buf, 3))
			{
				strcpy(p, "{ ");
				p += 2;
			}

			q = snmpid_handler(proc, &item.name);

			if (SFCOPY(p, buf, strlen(q)))
			{
				strcpy(p, q);
				p += strlen(p);
			}

			switch(item.value.asnType)
			{
			case ASN_INTEGER:
				q = "INTEGER";
				break;
			case ASN_BITS:
				q = "BITS";
				break;
			case ASN_OCTETSTRING:
				q = "OCTETSTRING";
				break;
			case ASN_NULL:
				q = "NULL";
				break;
			case ASN_OBJECTIDENTIFIER:
				q = "OBJECTIDENITIFERS";
				break;
			case ASN_IPADDRESS:
				q = "IPADDRESS";
				break;
			case ASN_COUNTER32:
				q = "COUNTER32";
				break;
			case ASN_GAUGE32:
				q = "GAUGE";
				break;
			case ASN_TIMETICKS:
				q = "TIMETICKS";
				break;
			case ASN_OPAQUE:
				q = "OPAQUE";
				break;
			case ASN_COUNTER64:
				q = "COUNTER64";
				break;
			case ASN_UNSIGNED32:
				q = "UNSIGNED";
				break;
			}

			if (SFCOPY(p, buf, strlen(q) + 3))
			{
				strcpy(p, ", ");
				strcpy(p+2,  q);
				p += strlen(p);
			}

			if (SFCOPY(p, buf, 3))
			{
				strcpy(p, " }");
				p += strlen(p);
			}
		}
		return buf;
	}
	else if (!strcmp(argtype->type->type_name, "snmpop"))
	{
		static char op_buf[17];
		switch(*arg)
		{
		case 0xA0:
			return "GET";
		case 0xA1:
			return "GETNEXT";
		case 0xA2:
			return "RESPONSE";
		case 0xA3:
			return "SET";
		case 0xA4:
			return "V1TRAP";
		case 0xA5:
			return "GETBULK";
		case 0xA6:
			return "INFORM";
		case 0xA7:
			return "TRAP";
		default:
			sprintf(op_buf, "SNMP_OP_%x", *arg);
			return op_buf;
		}
	}
	else
	{
		return "???";
	}
}

char*
sockaddrin_handler(DWORD *arg, struct param *argtype, HANDLE proc, int direction)
{
	static char strbuf[128];
	struct sockaddr_in Addr;
	DWORD out_len;
	if (*arg == 0)
		return "NULL";

	if (direction == 0 && argtype->direction == OUT_ARG)
	{
		sprintf(hexbuf,"0x%08x",*arg);
		return hexbuf;
	}
	
	if (ReadProcessMemory(proc, (LPCVOID)*arg, &Addr, sizeof(Addr), &out_len) == 0 &&
		GetLastError() != ERROR_PARTIAL_COPY)
	{
		WinPerror("ReadProcessMemory(arg<sockaddr_in>)");
		sprintf(hexbuf,"0x%08x",*arg);
		return hexbuf;
	}

	_snprintf(strbuf, sizeof(strbuf), "{ %u, %u, %s }", 
			  Addr.sin_family, ntohs(Addr.sin_port),
			  inet_ntoa(Addr.sin_addr));

	return strbuf;
}

#pragma pack(1)

typedef void *PSECURITY_DECRIPTOR;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

struct object_attributes
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PSECURITY_DECRIPTOR SecurityDescriptor;
	PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
};

#pragma pack()

char*
objattr_handler(DWORD *arg, struct param *argtype, HANDLE proc, int direction)
{
	static char strbuf[1024];
	char wstrbuf[1024];
	struct object_attributes objattr;
	UNICODE_STRING uc;
	DWORD out_len;

	if (direction == 0 && argtype->direction == OUT_ARG)
	{
		sprintf(hexbuf,"0x%08x",*arg);
		return hexbuf;
	}
	
	if (ReadProcessMemory(proc, (LPCVOID)*arg, &objattr, sizeof(objattr), &out_len) == 0 &&
		GetLastError() != ERROR_PARTIAL_COPY)
	{
		WinPerror("ReadProcessMemory(arg<pobject_attributes>)");
		sprintf(hexbuf,"0x%08x",*arg);
		return hexbuf;
	}

	_snprintf(strbuf, sizeof(strbuf), "{ %u, %08x, ", objattr.Length, objattr.RootDirectory);

	if (ReadProcessMemory(proc, (LPCVOID)objattr.ObjectName, &uc, sizeof(uc), &out_len) == 0 &&
		GetLastError() != ERROR_PARTIAL_COPY)
	{
		WinPerror("ReadProcessMemory(arg<unicode_string>)");
		sprintf(hexbuf,"0x%08x",objattr.ObjectName);
		strcat(strbuf, hexbuf);
	}
	else 
	{
		DWORD Length = uc.Length;

		if (Length > sizeof(wstrbuf))
		{
			Length = sizeof(wstrbuf);
		}

		if (ReadProcessMemory(proc, (LPCVOID)uc.Buffer, wstrbuf, Length, &out_len) == 0 &&
			GetLastError() != ERROR_PARTIAL_COPY)
		{
			WinPerror("ReadProcessMemory(arg<unicode_string>)");
			sprintf(hexbuf,"0x%08x",uc.Buffer);
			strcat(strbuf, hexbuf);
		}
		else
		{
			unsigned int i;

			for(i=0; i < Length/2; i++)
			{
				wstrbuf[i] = wstrbuf[(i*2)];
			}

			wstrbuf[i] = '\0';
			if (Length < uc.Length)
			{
				strcat(wstrbuf, "\"...");
			}
			else
			{
				strcat(wstrbuf, "\"");
			}

			_snprintf(strbuf + strlen(strbuf), sizeof(strbuf) - strlen(strbuf), "\"%s", wstrbuf);
		}
	}

	sprintf(wstrbuf, ", %x, %08x, %08x }", objattr.Attributes, objattr.SecurityDescriptor, objattr.SecurityQualityOfService);
	_snprintf(strbuf + strlen(strbuf), sizeof(strbuf) - strlen(strbuf), "%s", wstrbuf);

	return strbuf;
}

#endif /* TYPE_NAMES_ONLY */

/* $Id: types.c,v 1.6 2003/01/08 23:38:42 john Exp $ -- EOF */
