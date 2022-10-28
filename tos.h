typedef struct Tos Tos;
typedef struct Plink Plink;

struct Tos {
	struct				/* Per process profiling */
	{
		Plink		*pp;	/* known to be 0(ptr) */
		Plink		*next;	/* known to be 4(ptr) */
		Plink		*last;
		Plink		*first;
		uint32_t	pid;
		uint32_t	what;
	} prof;
	uint64_t	cyclefreq;	/* cycle clock frequency if there is one, 0 otherwise */
	int64_t		kcycles;	/* cycles spent in kernel */
	int64_t		pcycles;	/* cycles spent in process (kernel + user) */
	uint32_t	pid;		/* might as well put the pid here */
	uint32_t	clock;
	/* top of stack is here */
};

extern Tos *_tos;
