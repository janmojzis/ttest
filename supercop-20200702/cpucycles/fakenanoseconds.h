#ifndef CPUCYCLES_fakenanoseconds_h
#define CPUCYCLES_fakenanoseconds_h

#ifdef __cplusplus
extern "C" {
#endif

extern long long cpucycles_fakenanoseconds(void);
extern long long cpucycles_fakenanoseconds_persecond(void);

#ifdef __cplusplus
}
#endif

#ifndef cpucycles_implementation
#define cpucycles_implementation "fakenanoseconds"
#define cpucycles cpucycles_fakenanoseconds
#define cpucycles_persecond cpucycles_fakenanoseconds_persecond
#endif

#endif
