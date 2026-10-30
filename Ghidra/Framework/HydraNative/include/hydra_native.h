/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * The C ABI of hydra_native (crates/hydra-native/src/lib.rs). Java calls it through the foreign
 * function API (ghidra.util.HydraCpu) with normal downcalls; the struct offsets are checked by
 * the crate's layout test and read by HydraCpu at the same offsets.
 */
#ifndef HYDRA_NATIVE_H
#define HYDRA_NATIVE_H

#include <stddef.h>
#include <stdint.h>

#define HYDRA_NATIVE_ABI_VERSION 1

#define HYDRA_OK            0
#define HYDRA_ERR_NULL     -1 /* out is NULL */
#define HYDRA_ERR_SIZE     -2 /* out_size < sizeof(HydraCpuInfo) */
#define HYDRA_ERR_OVERRIDE -3 /* the override is not UTF-8 */

/* Counts of CPUs and cores are of the CPUs the process may run on, except system_cpus. */
typedef struct HydraCpuInfo {
	uint32_t size;               /*   0: sizeof(HydraCpuInfo) */
	uint32_t abi_version;        /*   4: HYDRA_NATIVE_ABI_VERSION */
	uint64_t memory_limit;       /*   8: bytes: min(job/cgroup limit, physical) */
	uint64_t physical_memory;    /*  16 */
	uint32_t system_cpus;        /*  24: logical CPUs on the machine */
	uint32_t affinity_cpus;      /*  28: logical CPUs the process may run on */
	uint32_t granted_cpus;       /*  32: affinity_cpus lowered by a CPU quota */
	uint32_t performance_cpus;   /*  36: in the highest efficiency class */
	uint32_t efficiency_cpus;    /*  40 */
	uint32_t performance_cores;  /*  44 */
	uint32_t efficiency_cores;   /*  48 */
	uint32_t llc_groups;         /*  52 */
	uint32_t l2_groups;          /*  56: 0 when the OS does not report L2 */
	uint32_t cpu_quota_milli;    /*  60: thousandths of a CPU, 0 = none */
	uint32_t vendor;             /*  64: 0 unknown, 1 Intel, 2 AMD, 3 other */
	uint32_t family;             /*  68 */
	uint32_t model;              /*  72 */
	uint32_t stepping;           /*  76 */
	uint32_t hybrid;             /*  80: 1 when there is more than one core class */
	uint32_t simd_level;         /*  84: 0 baseline, 1 SSE4.2, 2 AVX2, 3 AVX-512 */
	uint32_t latency_threads;    /*  88 */
	uint32_t compute_threads;    /*  92 */
	uint32_t background_threads; /*  96 */
	uint32_t placement;          /* 100: 0 any, 1 latency work on performance cores */
	uint32_t profile_source;     /* 104: 0 auto, 1 forced, 2 unknown override (generic) */
	uint32_t reserved;           /* 108 */
	char vendor_id[16];          /* 112: NUL-terminated */
	char profile_name[32];       /* 128 */
	char brand[64];              /* 160 */
} HydraCpuInfo;                  /* 224 bytes */

uint32_t hydra_native_abi_version(void);

size_t hydra_cpu_info_size(void);

/*
 * Fills *out for the calling process. profile_override is override_len bytes of UTF-8 ("auto",
 * "generic" or a profile name; empty means auto), or NULL to read HYDRA_CPU_PROFILE.
 */
int32_t hydra_cpu_query(const uint8_t *profile_override, size_t override_len, HydraCpuInfo *out,
	size_t out_size);

#endif
