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
