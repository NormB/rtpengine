#ifndef __REDIS_CLUSTER_H__
#define __REDIS_CLUSTER_H__

#include "redis.h"

#ifdef HAVE_HIREDIS_CLUSTER

#include <hiredis_cluster/hircluster.h>

/* Cluster connection lifecycle */
struct redis *redis_cluster_new(const char *nodes, int db_prefix, const char *auth,
		int no_redis_required);
void redis_cluster_close(struct redis *r);

/* Sync data operations — called from dispatch wrappers in redis.c */
void redis_cluster_update_onekey(call_t *c, struct redis *r);
void redis_cluster_do_delete(call_t *c, struct redis *r);
int redis_cluster_restore(struct redis *r, bool foreign, int db);
void redis_cluster_wipe(struct redis *r);

/* Thread loops */
void redis_cluster_notify_loop(void *d);
void redis_cluster_delete_async_loop(void *d);

/* Async event base actions */
int redis_cluster_async_event_base_action(struct redis *r, enum event_base_action action);

/* Key formatting helper — returns g_malloc'd string: "rtpe<db>:<callid>" */
char *redis_cluster_key(int db, const str *callid);

/* Channel name helper — returns g_malloc'd string: "rtpe:notify:<db>" */
char *redis_cluster_notify_channel(int db);

#else /* !HAVE_HIREDIS_CLUSTER */

/* Stubs when hiredis-cluster is not available */
#define redis_cluster_new(...) NULL
#define redis_cluster_close(r) do {} while(0)

#endif /* HAVE_HIREDIS_CLUSTER */

#endif /* __REDIS_CLUSTER_H__ */
