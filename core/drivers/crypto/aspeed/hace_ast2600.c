// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Aspeed Technology Inc.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <io.h>
#include <drvcrypt_hash.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <kernel/delay.h>
#include <tee/cache.h>

#include "hace_ast2600.h"

#define HACE_BASE	0x1e6d0000

/* register offsets and bit fields */
#define HACE_STS		0x1C
#define   HACE_STS_HASH_INT		BIT(9)
#define   HACE_STS_HASH_BUSY		BIT(0)
#define HACE_HASH_DATA		0x20
#define HACE_HASH_DIGEST	0x24
#define HACE_HASH_HMAC_KEY	0x28
#define HACE_HASH_DATA_LEN	0x2C
#define HACE_HASH_CMD		0x30
#define   HACE_HASH_CMD_ACCUM		BIT(8)
#define   HACE_HASH_CMD_ALG_SHA1	BIT(5)
#define   HACE_HASH_CMD_ALG_SHA256	(BIT(6) | BIT(4))
#define   HACE_HASH_CMD_ALG_SHA384	(BIT(10) | BIT(6) | BIT(5))
#define   HACE_HASH_CMD_ALG_SHA512	(BIT(6) | BIT(5))
#define   HACE_HASH_CMD_SHA_BE		BIT(3)

/* buffer size based on SHA-512 need */
#define HASH_BLK_BUFSZ	128
#define HASH_DGT_BUFSZ	64

register_phys_mem(MEM_AREA_IO_SEC,
		  HACE_BASE,
		  SMALL_PAGE_SIZE);

struct ast2600_hace_ctx {
	const struct crypto_hash_ops *ops;
	uint32_t cmd;
	uint32_t algo;
	uint32_t dgt_size;
	uint32_t blk_size;
	uint32_t pad_size;
	uint64_t total[2];
	uint8_t buf[HASH_BLK_BUFSZ];
	uint8_t digest[HASH_DGT_BUFSZ] __aligned((8));
};

static vaddr_t hace_virt;
struct mutex hace_mtx = MUTEX_INITIALIZER;

static const uint32_t iv_sha1[8] = {
	0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210,
	0xf0e1d2c3, 0, 0, 0
};

static const uint32_t iv_sha256[8] = {
	0x67e6096a, 0x85ae67bb, 0x72f36e3c, 0x3af54fa5,
	0x7f520e51, 0x8c68059b, 0xabd9831f, 0x19cde05b
};

static const uint32_t iv_sha384[16] = {
	0x5d9dbbcb, 0xd89e05c1, 0x2a299a62, 0x07d57c36,
	0x5a015991, 0x17dd7030, 0xd8ec2f15, 0x39590ef7,
	0x67263367, 0x310bc0ff, 0x874ab48e, 0x11155868,
	0x0d2e0cdb, 0xa78ff964, 0x1d48b547, 0xa44ffabe
};

static const uint32_t iv_sha512[16] = {
	0x67e6096a, 0x08c9bcf3, 0x85ae67bb, 0x3ba7ca84,
	0x72f36e3c, 0x2bf894fe, 0x3af54fa5, 0xf1361d5f,
	0x7f520e51, 0xd182e6ad, 0x8c68059b, 0x1f6c3e2b,
	0xabd9831f, 0x6bbd41fb, 0x19cde05b, 0x79217e13
};

static TEE_Result ast2600_hace_process(struct crypto_hash_ctx *ctx,
				       const uint8_t *data, size_t len)
{
	TEE_Result rc = TEE_SUCCESS;
	uint64_t tref;
	uint32_t sts = io_read32(hace_virt + HACE_STS);
	struct ast2600_hace_ctx *hace_ctx = (struct ast2600_hace_ctx *)(void *)ctx;

	if (sts & HACE_STS_HASH_BUSY)
		return TEE_ERROR_BUSY;

	mutex_lock(&hace_mtx);

	cache_operation(TEE_CACHEFLUSH, (void *)data, len);

	io_write32(hace_virt + HACE_STS, HACE_STS_HASH_INT);

	io_write32(hace_virt + HACE_HASH_DATA, virt_to_phys((void *)data));
	io_write32(hace_virt + HACE_HASH_DIGEST, virt_to_phys(hace_ctx->digest));
	io_write32(hace_virt + HACE_HASH_HMAC_KEY, virt_to_phys(hace_ctx->digest));
	io_write32(hace_virt + HACE_HASH_DATA_LEN, len);
	io_write32(hace_virt + HACE_HASH_CMD, hace_ctx->cmd);

	/* poll for completion */
	tref = timeout_init_us(1000 + (len >> 3));

	do {
		sts = io_read32(hace_virt + HACE_STS);
		if (timeout_elapsed(tref)) {
			rc = TEE_ERROR_TARGET_DEAD;
			goto unlock_n_out;
		}
	} while (!(sts & HACE_STS_HASH_INT));

unlock_n_out:
	mutex_unlock(&hace_mtx);

	return rc;
}

static TEE_Result ast2600_hace_init(struct crypto_hash_ctx *ctx)
{
	struct ast2600_hace_ctx *hace_ctx = (struct ast2600_hace_ctx*)(void *)ctx;

	switch (hace_ctx->algo) {
	case TEE_ALG_SHA1:
		memcpy(hace_ctx->digest, iv_sha1, sizeof(iv_sha1));
		break;
	case TEE_ALG_SHA256:
		memcpy(hace_ctx->digest, iv_sha256, sizeof(iv_sha256));
		break;
	case TEE_ALG_SHA384:
		memcpy(hace_ctx->digest, iv_sha384, sizeof(iv_sha384));
		break;
	case TEE_ALG_SHA512:
		memcpy(hace_ctx->digest, iv_sha512, sizeof(iv_sha512));
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	hace_ctx->total[0] = 0;
	hace_ctx->total[1] = 0;

	cache_operation(TEE_CACHEFLUSH, hace_ctx->digest, sizeof(hace_ctx->digest));

	return TEE_SUCCESS;
}

static TEE_Result ast2600_hace_update(struct crypto_hash_ctx *ctx,
				      const uint8_t *data, size_t len)
{
	TEE_Result rc;
	uint32_t left, fill;
	struct ast2600_hace_ctx *hace_ctx = (struct ast2600_hace_ctx*)(void *)ctx;

	left = hace_ctx->total[0] & (hace_ctx->blk_size - 1);
	fill = hace_ctx->blk_size - left;

	hace_ctx->total[0] += len;
	if (hace_ctx->total[0] < len)
		hace_ctx->total[1]++;

	if (left && len >= fill) {
		memcpy(hace_ctx->buf + left, data, fill);
		rc = ast2600_hace_process(ctx, hace_ctx->buf, hace_ctx->blk_size);
		if (rc)
			return rc;

		data += fill;
		len -= fill;
		left = 0;
	}

	while (len >= hace_ctx->blk_size) {
		rc = ast2600_hace_process(ctx, data, hace_ctx->blk_size);
		if (rc)
			return rc;

		data += hace_ctx->blk_size;
		len -= hace_ctx->blk_size;
	}

	if (len)
		memcpy(hace_ctx->buf + left, data, len);

	return TEE_SUCCESS;
}

static TEE_Result ast2600_hace_final(struct crypto_hash_ctx *ctx,
				     uint8_t *digest, size_t len)
{
	TEE_Result rc;
	uint32_t last, padn;
	uint8_t pad[HASH_BLK_BUFSZ * 2];
	uint64_t dbits_h, dbits_l;
	uint64_t dbits_be_h, dbits_be_l;
	struct ast2600_hace_ctx *hace_ctx = (struct ast2600_hace_ctx*)(void *)ctx;

	if (len < hace_ctx->dgt_size)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(pad, 0, sizeof(pad));
	pad[0] = 0x80;

	dbits_h = (hace_ctx->total[0] >> 61) | (hace_ctx->total[1] << 3);
	dbits_be_h = get_be64(&dbits_h);

	dbits_l = (hace_ctx->total[0] << 3);
	dbits_be_l = get_be64(&dbits_l);

	last = hace_ctx->total[0] & (hace_ctx->blk_size -1);

	switch (hace_ctx->algo) {
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA256:
		padn = (last < 56) ? (56 - last) : (120 - last);

		rc = ast2600_hace_update(ctx, pad, padn);
		if (rc)
			return rc;

		rc = ast2600_hace_update(ctx, (uint8_t *)&dbits_be_l, sizeof(dbits_be_l));
		if (rc)
			return rc;

		break;
	case TEE_ALG_SHA384:
	case TEE_ALG_SHA512:
		padn = (last < 112) ? (112 - last) : (240 - last);

		rc = ast2600_hace_update(ctx, pad, padn);
		if (rc)
			return rc;

		rc = ast2600_hace_update(ctx, (uint8_t *)&dbits_be_h, sizeof(dbits_be_h)) |
		     ast2600_hace_update(ctx, (uint8_t *)&dbits_be_l, sizeof(dbits_be_l));
		if (rc)
			return rc;

		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	cache_operation(TEE_CACHEINVALIDATE, hace_ctx->digest, sizeof(hace_ctx->digest));

	memcpy(digest, hace_ctx->digest, hace_ctx->dgt_size);

	return TEE_SUCCESS;
}

static void ast2600_hace_free(struct crypto_hash_ctx *ctx)
{
	free(ctx);
}

static void ast2600_hace_copy_state(struct crypto_hash_ctx *dst_ctx,
				    struct crypto_hash_ctx *src_ctx)
{
	cache_operation(TEE_CACHEINVALIDATE, src_ctx, sizeof(struct ast2600_hace_ctx));

	memcpy(dst_ctx, src_ctx, sizeof(struct ast2600_hace_ctx));

	cache_operation(TEE_CACHEFLUSH, dst_ctx, sizeof(struct ast2600_hace_ctx));
}

static const struct crypto_hash_ops ast2600_hace_ops = {
	.init = ast2600_hace_init,
	.update = ast2600_hace_update,
	.final = ast2600_hace_final,
	.free_ctx = ast2600_hace_free,
	.copy_state = ast2600_hace_copy_state,
};

static TEE_Result ast2600_hace_alloc(struct crypto_hash_ctx **pctx, uint32_t algo)
{
	struct ast2600_hace_ctx *hace_ctx;

	hace_ctx = calloc(1, sizeof(*hace_ctx));
	if (!hace_ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	hace_ctx->ops = &ast2600_hace_ops;
	hace_ctx->algo = algo;
	hace_ctx->cmd = HACE_HASH_CMD_ACCUM | HACE_HASH_CMD_SHA_BE;

	switch (algo) {
	case TEE_ALG_SHA1:
		hace_ctx->dgt_size = 20;
		hace_ctx->blk_size = 64;
		hace_ctx->pad_size = 8;
		hace_ctx->cmd |= HACE_HASH_CMD_ALG_SHA1;
		break;
	case TEE_ALG_SHA256:
		hace_ctx->dgt_size = 32;
		hace_ctx->blk_size = 64;
		hace_ctx->pad_size = 8;
		hace_ctx->cmd |= HACE_HASH_CMD_ALG_SHA256;
		break;
	case TEE_ALG_SHA384:
		hace_ctx->dgt_size = 48;
		hace_ctx->blk_size = 128;
		hace_ctx->pad_size = 16;
		hace_ctx->cmd |= HACE_HASH_CMD_ALG_SHA384;
		break;
	case TEE_ALG_SHA512:
		hace_ctx->dgt_size = 64;
		hace_ctx->blk_size = 128;
		hace_ctx->pad_size = 16;
		hace_ctx->cmd |= HACE_HASH_CMD_ALG_SHA512;
		break;
	default:
		free(hace_ctx);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	*pctx = (struct crypto_hash_ctx *)hace_ctx;

	return TEE_SUCCESS;
}

TEE_Result ast2600_drvcrypt_register_hash(void)
{
	hace_virt = core_mmu_get_va(HACE_BASE,
				    MEM_AREA_IO_SEC, SMALL_PAGE_SIZE);
	if (!hace_virt) {
		EMSG("cannot get HACE virtual address\n");
		return TEE_ERROR_GENERIC;
	}

	return drvcrypt_register_hash(ast2600_hace_alloc);
}
