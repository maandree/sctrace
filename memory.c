/* See LICENSE file for copyright and license details. */
#include "common.h"


size_t abbreviate_memory = SIZE_MAX;


char *
get_string(pid_t pid, unsigned long int addr, size_t *lenp, const char **errorp)
{
#if defined(__x86_64__) && defined(__IPL32__)
# error "x32 is not supported, would not be able to read memory from 64-bit applications with current method"
#endif
	struct iovec inv, outv;
	size_t off = 0, size = 0, page_off, read_size;
	char *out = NULL, *in = (char *)addr, *p;
	page_off = (size_t)addr % sizeof(PAGE_SIZE);
	read_size = PAGE_SIZE - page_off;
	*errorp = NULL;
	for (;; read_size = PAGE_SIZE) {
		out = realloc(out, size + PAGE_SIZE);
		if (!out)
			eprintf("realloc:");
		inv.iov_base  = &in[off];
		inv.iov_len   = read_size;
		outv.iov_base = &out[off];
		outv.iov_len  = read_size;
		if (process_vm_readv(pid, &outv, 1, &inv, 1, 0) != (ssize_t)read_size) {
			*errorp = errno == EFAULT ? "<invalid address>" : "<an error occured during reading of string>";
			*lenp = 0;
			free(out);
			return NULL;
		}
		p = memchr(&out[off], 0, read_size);
		if (p) {
			*lenp = (size_t)(p - out);
			return out;
		}
		off += read_size;
	}
}


int
get_struct(pid_t pid, unsigned long int addr, void *out, size_t size, const char **errorp)
{
	struct iovec inv, outv;
	if (!addr) {
		*errorp = "NULL";
		return -1;
	}
	*errorp = NULL;
#if defined(__x86_64__) && defined(__IPL32__)
# error "x32 is not supported, would not be able to read memory from 64-bit applications with current method"
#endif
	inv.iov_base  = (void *)addr;
	inv.iov_len   = size;
	outv.iov_base = out;
	outv.iov_len  = size;
	if (process_vm_readv(pid, &outv, 1, &inv, 1, 0) == (ssize_t)size)
		return 0;
	*errorp = errno == EFAULT ? "<invalid address>" : "<an error occured during reading of memory>";
	return -1;
}


char *
get_memory(pid_t pid, unsigned long int addr, size_t n, const char **errorp)
{
	char *out = malloc(n + (size_t)!n);
	if (!out)
		eprintf("malloc:");
	if (get_struct(pid, addr, out, n, errorp)) {
		free(out);
		return NULL;
	}
	return out;
}


static void
add_char(char **strp, size_t *sizep, size_t *lenp, char c)
{
	if (*lenp == *sizep) {
		*strp = realloc(*strp, *sizep += 128);
		if (!*strp)
			eprintf("realloc:");
	}
	(*strp)[(*lenp)++] = c;
}


static size_t
utf8len(const char *str)
{
	const uint8_t *s = (const uint8_t *)str;
	size_t ext, i, len;
	uint32_t code;

	struct {
		uint8_t  lower;
		uint8_t  upper;
		uint8_t  mask;
		uint32_t lowest;
	} lookup[] = {
		{ 0x00, 0x7F, 0x7F, UINT32_C(0x000000) },
		{ 0xC0, 0xDF, 0x1F, UINT32_C(0x000080) },
		{ 0xE0, 0xEF, 0x0F, UINT32_C(0x000800) },
		{ 0xF0, 0xF7, 0x07, UINT32_C(0x010000) }
	};

	for (ext = 0; ext < sizeof(lookup) / sizeof(*lookup); ext++)
		if (lookup[ext].lower <= s[0] && s[0] <= lookup[ext].upper)
			goto found;
	return 0;

found:
	code = s[0] & lookup[ext].mask;
	len = ext + 1;
	for (i = 1; i < len; i++) {
		if ((s[i] & 0xC0) != 0x80)
			return 0;
		code = (code << 6) | (s[i] ^ 0x80);
	}

	if (code < lookup[ext].lowest || (0xD800 <= code && code <= 0xDFFF) || code > UINT32_C(0x10FFFF))
		return 0;
	return len;
}


static int
istrigraphfinal(char c)
{
	return c == '=' || c == '(' || c == '/' || c == ')' || c == '\'' || c == '<' || c == '!' || c == '>' || c == '-';
}


static char *
escape(const char *str, size_t m, size_t max)
{
	char *ret = NULL;
	const char *s, *end;
	size_t size = 0;
	size_t len = 0;
	size_t n = 0;
	int need_new_string_hex = 0;
	int trigraph_state = 0;
	if (!str) {
		ret = strdup("NULL");
		if (!ret)
			eprintf("strdup:");
		return ret;
	}
	if (max > m)
		max = m;
	add_char(&ret, &size, &len, '"');
	for (s = str, end = &str[max]; s != end; s++) {
		if (n) {
			add_char(&ret, &size, &len, *s);
			n -= 1;
		} else if (*s == '\r') {
			add_char(&ret, &size, &len, '\\');
			add_char(&ret, &size, &len, 'r');
		} else if (*s == '\t') {
			add_char(&ret, &size, &len, '\\');
			add_char(&ret, &size, &len, 't');
		} else if (*s == '\a') {
			add_char(&ret, &size, &len, '\\');
			add_char(&ret, &size, &len, 'a');
		} else if (*s == '\f') {
			add_char(&ret, &size, &len, '\\');
			add_char(&ret, &size, &len, 'f');
		} else if (*s == '\v') {
			add_char(&ret, &size, &len, '\\');
			add_char(&ret, &size, &len, 'v');
		} else if (*s == '\b') {
			add_char(&ret, &size, &len, '\\');
			add_char(&ret, &size, &len, 'b');
		} else if (*s == '\n') {
			add_char(&ret, &size, &len, '\\');
			add_char(&ret, &size, &len, 'n');
		} else if (*s == '\"') {
			add_char(&ret, &size, &len, '\\');
			add_char(&ret, &size, &len, '"');
		} else if (*s < ' ' || *s >= 127) {
			n = utf8len(s);
			if (n > 1) {
				add_char(&ret, &size, &len, *s);
				n -= 1;
			} else {
				n = 0;
				add_char(&ret, &size, &len, '\\');
				add_char(&ret, &size, &len, 'x');
				add_char(&ret, &size, &len, "0123456789abcdef"[(int)*(unsigned char *)s >> 4]);
				add_char(&ret, &size, &len, "0123456789abcdef"[(int)*(unsigned char *)s & 15]);
				need_new_string_hex = 1;
				continue;
			}
		} else {
			if ((need_new_string_hex && isxdigit(*s)) ||
			    (trigraph_state == 2 && istrigraphfinal(*s))) {
				add_char(&ret, &size, &len, '"');
				add_char(&ret, &size, &len, '"');
			} else if (*s == '?') {
				trigraph_state += trigraph_state < 2;
				add_char(&ret, &size, &len, *s);
				need_new_string_hex = 0;
				continue;
			}
			add_char(&ret, &size, &len, *s);
		}
		trigraph_state = 0;
		need_new_string_hex = 0;
	}
	add_char(&ret, &size, &len, '"');
	if (m > max) {
		add_char(&ret, &size, &len, '.');
		add_char(&ret, &size, &len, '.');
		add_char(&ret, &size, &len, '.');
	}
	add_char(&ret, &size, &len, '\0');
	return ret;
}


char *
escape_memory(const char *str, size_t m)
{
	return escape(str, m, abbreviate_memory);
}


char *
escape_string(const char *str, size_t m)
{
	return escape(str, m, SIZE_MAX);
}


char *
get_escaped_string(pid_t pid, unsigned long int addr, size_t *lenp, const char **errorp)
{
	char *r, *ret;
	if (!addr) {
		*errorp = "NULL";
		return NULL;
	}
	r = get_string(pid, addr, lenp, errorp);
	ret = escape_string(r, *lenp);
	free(r);
	return ret;
}


char *
get_escaped_memory(pid_t pid, unsigned long int addr, size_t n, const char **errorp)
{
	char *r, *ret;
	if (!addr) {
		*errorp = "NULL";
		return NULL;
	}
	r = get_memory(pid, addr, n, errorp);
	ret = escape_memory(r, n);
	free(r);
	return ret;
}
