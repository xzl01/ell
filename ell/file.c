/*
 * Embedded Linux library
 * Copyright (C) 2017  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include "file.h"
#include "private.h"
#include "useful.h"

/**
 * l_file_get_contents:
 * @filename: File to load
 * @out_len: Set to the length of the loaded file
 *
 * Attempts to load the contents of a file via sequential read system calls.
 * This can be useful for files that are not mmapable, e.g. sysfs entries.
 *
 * Returns: A newly allocated memory region with the file contents
 **/
LIB_EXPORT void *l_file_get_contents(const char *filename, size_t *out_len)
{
	int fd;
	struct stat st;
	uint8_t *contents;
	size_t bytes_read = 0;
	ssize_t nread;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return NULL;

	if (fstat(fd, &st) < 0) {
		close(fd);
		return NULL;
	}

	contents = l_malloc(st.st_size);

	do {
		nread = read(fd, contents + bytes_read, 4096);

		if (nread < 0) {
			if (errno == EINTR)
				continue;

			goto error;
		}

		bytes_read += nread;
	} while (nread != 0);

	if (out_len)
		*out_len = bytes_read;

	close(fd);
	return contents;

error:
	l_free(contents);
	close(fd);
	return NULL;
}

/**
 * l_file_set_contents:
 * @filename: Destination filename
 * @contents: Pointer to the contents
 * @len: Length in bytes of the contents buffer
 *
 * Given a content buffer, write it to a file named @filename.  This function
 * ensures that the contents are consistent (i.e. due to a crash right after
 * opening or during write() by writing the contents to a temporary which is then
 * renamed to @filename.
 *
 * Returns: 0 if successful, a negative errno otherwise
 **/
LIB_EXPORT int l_file_set_contents(const char *filename,
					const void *contents, size_t len)
{
	_auto_(l_free) char *tmp_path = NULL;
	ssize_t r;
	int fd;

	if (!filename || !contents)
		return -EINVAL;

	tmp_path = l_strdup_printf("%s.XXXXXX.tmp", filename);

	fd = L_TFR(mkostemps(tmp_path, 4, O_CLOEXEC));
	if (fd == -1)
		return -errno;

	r = L_TFR(write(fd, contents, len));
	L_TFR(close(fd));

	if (r != (ssize_t) len) {
		r = -EIO;
		goto error_write;
	}

	/*
	 * Now that the file contents are written, rename to the real
	 * file name; this way we are uniquely sure that the whole
	 * thing is there.
	 * conserve @r's value from 'write'
	 */
	if (rename(tmp_path, filename) == -1)
		r = -errno;

error_write:
	if (r < 0)
		unlink(tmp_path);

	return r < 0 ? r : 0;
}
