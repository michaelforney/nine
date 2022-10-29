/* SPDX-License-Identifier: Unlicense */
static inline uint_least32_t
getbe32(void *p)
{
	unsigned char *b;
	uint_least32_t v;

	b = p;
	v = (uint_least32_t)b[0] << 24;
	v |= (uint_least32_t)b[1] << 16;
	v |= (uint_least32_t)b[2] << 8;
	v |= b[3];
	return v;
}

static inline uint_least64_t
getbe64(void *p)
{
	unsigned char *b;
	uint_least64_t v;

	b = p;
	v = (uint_least64_t)b[0] << 56;
	v |= (uint_least64_t)b[1] << 48;
	v |= (uint_least64_t)b[2] << 40;
	v |= (uint_least64_t)b[3] << 32;
	v |= (uint_least64_t)b[4] << 24;
	v |= (uint_least64_t)b[5] << 16;
	v |= (uint_least64_t)b[6] << 8;
	v |= b[7];
	return v;
}

static inline void *
putle8(void *p, uint_least8_t v)
{
	unsigned char *b;

	b = p;
	b[0] = v & 0xff;
	return b + 1;
}

static inline void *
putle16(void *p, uint_least16_t v)
{
	unsigned char *b;

	b = p;
	b[0] = v      & 0xff;
	b[1] = v >> 8 & 0xff;
	return b + 2;
}

static inline void *
putle32(void *p, uint_least32_t v)
{
	unsigned char *b;

	b = p;
	b[0] = v       & 0xff;
	b[1] = v >> 8  & 0xff;
	b[2] = v >> 16 & 0xff;
	b[3] = v >> 24 & 0xff;
	return b + 4;
}

static inline void *
putle64(void *p, uint_least64_t v)
{
	unsigned char *b;

	b = p;
	b[0] = v       & 0xff;
	b[1] = v >> 8  & 0xff;
	b[2] = v >> 16 & 0xff;
	b[3] = v >> 24 & 0xff;
	b[4] = v >> 32 & 0xff;
	b[5] = v >> 40 & 0xff;
	b[6] = v >> 48 & 0xff;
	b[7] = v >> 56 & 0xff;
	return b + 8;
}
