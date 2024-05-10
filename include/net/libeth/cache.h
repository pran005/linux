/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Intel Corporation */

#ifndef __LIBETH_CACHE_H
#define __LIBETH_CACHE_H

#include <linux/cache.h>

/* __aligned_largest is architecture-dependent. Get the actual alignment */
#define ___LIBETH_LARGEST_ALIGN						   \
	sizeof(struct { long __UNIQUE_ID(long_); } __aligned_largest)
#define __LIBETH_LARGEST_ALIGN						   \
	(___LIBETH_LARGEST_ALIGN > SMP_CACHE_BYTES ?			   \
	 ___LIBETH_LARGEST_ALIGN : SMP_CACHE_BYTES)
#define __LIBETH_LARGEST_ALIGNED(sz)					   \
	ALIGN(sz, __LIBETH_LARGEST_ALIGN)

#define __libeth_cacheline_group_begin(grp)				   \
	__cacheline_group_begin(grp) __aligned(__LIBETH_LARGEST_ALIGN)
#define __libeth_cacheline_group_end(grp)				   \
	__cacheline_group_end(grp) __aligned(4)

#define libeth_cacheline_group(grp, ...)				   \
	struct_group(grp,						   \
		__libeth_cacheline_group_begin(grp);			   \
		__VA_ARGS__						   \
		__libeth_cacheline_group_end(grp);			   \
	)

#if defined(CONFIG_64BIT) && L1_CACHE_BYTES == 64
#define libeth_cacheline_group_assert(type, grp, sz)			   \
	static_assert(offsetof(type, __cacheline_group_end__##grp) -	   \
		      offsetofend(type, __cacheline_group_begin__##grp) == \
		      (sz))
#define __libeth_cacheline_struct_assert(type, sz)			   \
	static_assert(sizeof(type) == (sz))
#else /* !CONFIG_64BIT || L1_CACHE_BYTES != 64 */
#define libeth_cacheline_group_assert(type, grp, sz)			   \
	static_assert(offsetof(type, __cacheline_group_end__##grp) -	   \
		      offsetofend(type, __cacheline_group_begin__##grp) <= \
		      (sz))
#define __libeth_cacheline_struct_assert(type, sz)			   \
	static_assert(sizeof(type) <= (sz))
#endif /* !CONFIG_64BIT || L1_CACHE_BYTES != 64 */

#define __libeth_cls1(sz1)						   \
	__LIBETH_LARGEST_ALIGNED(sz1)
#define __libeth_cls2(sz1, sz2)						   \
	(__LIBETH_LARGEST_ALIGNED(sz1) + __LIBETH_LARGEST_ALIGNED(sz2))
#define __libeth_cls3(sz1, sz2, sz3)					   \
	(__LIBETH_LARGEST_ALIGNED(sz1) + __LIBETH_LARGEST_ALIGNED(sz2) +   \
	 __LIBETH_LARGEST_ALIGNED(sz3))
#define __libeth_cls(...)						   \
	CONCATENATE(__libeth_cls, COUNT_ARGS(__VA_ARGS__))(__VA_ARGS__)
#define libeth_cacheline_struct_assert(type, ...)			   \
	__libeth_cacheline_struct_assert(type, __libeth_cls(__VA_ARGS__))

#define libeth_cacheline_set_assert(type, ro, rw, c)			   \
	libeth_cacheline_group_assert(type, read_mostly, ro);		   \
	libeth_cacheline_group_assert(type, read_write, rw);		   \
	libeth_cacheline_group_assert(type, cold, c);			   \
	libeth_cacheline_struct_assert(type, ro, rw, c)

#endif /* __LIBETH_CACHE_H */
