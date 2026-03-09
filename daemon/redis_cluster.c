/*
 * redis_cluster.c — Redis Cluster support for rtpengine
 *
 * All cluster-specific code lives here. Activated by --redis-cluster flag.
 * Uses hiredis-cluster (Nordix) for automatic MOVED/ASK redirect handling.
 *
 * Key differences from standalone mode:
 * - No SELECT — Redis Cluster only supports DB 0
 * - Keys prefixed with "rtpe<N>:" to isolate per-instance keyspaces
 * - PUBLISH/SUBSCRIBE channels instead of keyspace notifications
 * - SCAN across all master nodes instead of KEYS *
 */

#include "redis_cluster.h"

#ifdef HAVE_HIREDIS_CLUSTER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <glib.h>
#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include <hiredis/adapters/libevent.h>
#include <hiredis_cluster/hircluster.h>
#include <event2/thread.h>

#include "log.h"
#include "log_funcs.h"
#include "call.h"
#include "str.h"
#include "main.h"
#include "helpers.h"
#include "media_socket.h"
#include "codec.h"
#include "sdp.h"
#include "recording.h"
#include "rtplib.h"
#include "crypto.h"
#include "dtls.h"
#include "ssrc.h"

/* Shared functions from redis.c — made non-static for cluster support */
extern void json_restore_call(struct redis *r, const str *callid, bool foreign);
extern str redis_encode_json(ng_parser_ctx_t *ctx, call_t *c, void **to_free);
extern const ng_parser_t *const redis_format_parsers[];
extern void redis_set_keepalive(int fd);

#define rlog(l, x...) ilog(l | LOG_FLAG_RESTORE, x)

/* ─── Key formatting ─────────────────────────────────────────────────── */

char *redis_cluster_key(int db, const str *callid) {
	return g_strdup_printf("rtpe%d:" STR_FORMAT, db, STR_FMT(callid));
}

char *redis_cluster_notify_channel(int db) {
	return g_strdup_printf("rtpe:notify:%d", db);
}

/* ─── Connection lifecycle ───────────────────────────────────────────── */

struct redis *redis_cluster_new(const char *nodes, int db_prefix, const char *auth,
		int no_redis_required) {
	struct redis *r;
	redisClusterContext *cc;

	r = g_new0(struct redis, 1);
	r->is_cluster = true;
	r->db = db_prefix; /* used as key prefix number, not SELECT */
	r->auth = auth;
	r->state = REDIS_STATE_DISCONNECTED;
	r->no_redis_required = no_redis_required;
	r->consecutive_errors = 0;
	r->current_db = -1;
	mutex_init(&r->lock);
	mutex_init(&r->async_lock);
	g_queue_init(&r->async_queue);

	cc = redisClusterContextInit();
	if (!cc) {
		rlog(LOG_ERR, "Redis Cluster: failed to init context");
		goto err;
	}

	if (redisClusterSetOptionAddNodes(cc, nodes) != REDIS_OK) {
		rlog(LOG_ERR, "Redis Cluster: failed to set nodes '%s': %s",
				nodes, cc->errstr);
		goto err_cc;
	}

	/* timeouts */
	struct timeval tv;
	int64_t connect_timeout = atomic_get_na(&rtpe_config.redis_connect_timeout) * 1000LL;
	tv = timeval_from_us(connect_timeout);
	redisClusterSetOptionConnectTimeout(cc, tv);

	int64_t cmd_timeout = atomic_get_na(&rtpe_config.redis_cmd_timeout) * 1000LL;
	if (cmd_timeout) {
		tv = timeval_from_us(cmd_timeout);
		redisClusterSetOptionTimeout(cc, tv);
	}

	/* authentication */
	if (auth) {
		if (redisClusterSetOptionPassword(cc, auth) != REDIS_OK) {
			rlog(LOG_ERR, "Redis Cluster: failed to set password: %s", cc->errstr);
			goto err_cc;
		}
	}

	/* connect to cluster */
	if (redisClusterConnect2(cc) != REDIS_OK) {
		rlog(LOG_ERR, "Redis Cluster: failed to connect to '%s': %s",
				nodes, cc->errstr);
		goto err_cc;
	}

	/* verify connectivity by PING'ing the first master node.
	 * PING has no key, so redisClusterCommand() can't route it.
	 * Use redisClusterCommandToNode() targeting the first node. */
	{
		redisClusterNodeIterator ni;
		redisClusterInitNodeIterator(&ni, cc);
		redisClusterNode *node = redisClusterNodeNext(&ni);
		if (!node) {
			rlog(LOG_ERR, "Redis Cluster: no nodes discovered");
			goto err_cc;
		}
		redisReply *rp = redisClusterCommandToNode(cc, node, "PING");
		if (!rp || rp->type == REDIS_REPLY_ERROR) {
			rlog(LOG_ERR, "Redis Cluster: PING failed: %s",
					rp ? rp->str : "no reply");
			if (rp) freeReplyObject(rp);
			goto err_cc;
		}
		freeReplyObject(rp);
	}

	r->cluster_ctx = cc;
	r->state = REDIS_STATE_CONNECTED;

	rlog(LOG_INFO, "Established connection to Redis Cluster at '%s' (prefix rtpe%d:)",
			nodes, db_prefix);
	return r;

err_cc:
	redisClusterFree(cc);
err:
	if (no_redis_required) {
		rlog(LOG_WARN, "Starting with no initial connection to Redis Cluster!");
		return r;
	}
	mutex_destroy(&r->lock);
	mutex_destroy(&r->async_lock);
	g_free(r);
	return NULL;
}

void redis_cluster_close(struct redis *r) {
	if (!r)
		return;
	if (r->cluster_ctx) {
		redisClusterFree(r->cluster_ctx);
		r->cluster_ctx = NULL;
	}
	if (r->ctx) {
		redisFree(r->ctx);
		r->ctx = NULL;
	}
	mutex_destroy(&r->lock);
	mutex_destroy(&r->async_lock);
	g_free(r);
}

/* ─── Cluster reconnect ──────────────────────────────────────────────── */

static int redis_cluster_check_conn(struct redis *r) {
	redisClusterContext *cc = r->cluster_ctx;

	if (!cc) {
		r->state = REDIS_STATE_DISCONNECTED;
		return REDIS_STATE_DISCONNECTED;
	}

	/* hiredis-cluster can leave cc->err set after transient issues
	 * (e.g. slot redirect on PUBLISH). Clear stale errors — the
	 * actual SET/DEL will fail with a meaningful error if the
	 * connection is really broken. */
	if (cc->err) {
		rlog(LOG_DEBUG, "Redis Cluster clearing stale error: %s", cc->errstr);
		cc->err = 0;
		cc->errstr[0] = '\0';
	}

	r->state = REDIS_STATE_CONNECTED;
	return REDIS_STATE_CONNECTED;
}

/* ─── Sync operations ────────────────────────────────────────────────── */

void redis_cluster_update_onekey(call_t *c, struct redis *r) {
	unsigned int redis_expires_s;
	redisClusterContext *cc;
	redisReply *rp;

	if (!r)
		return;
	if (IS_FOREIGN_CALL(c))
		return;

	LOCK(&r->lock);

	if (redis_cluster_check_conn(r) == REDIS_STATE_DISCONNECTED)
		return;

	cc = r->cluster_ctx;
	atomic64_set_na(&c->last_redis_update_us, rtpe_now);

	rwlock_lock_r(&c->master_lock);

	redis_expires_s = rtpe_config.redis_expires_secs;
	c->redis_hosted_db = r->db;

	/* encode call state */
	ng_parser_ctx_t ctx;
	bencode_buffer_t bbuf;
	redis_format_parsers[rtpe_config.redis_format]->init(&ctx, &bbuf);

	void *to_free = NULL;
	str result = redis_encode_json(&ctx, c, &to_free);
	if (!result.len)
		goto err;

	/* SET rtpe<N>:<callid> <blob> EX <ttl> */
	g_autofree char *key = redis_cluster_key(r->db, &c->callid);
	rp = redisClusterCommand(cc, "SET %s %b EX %u",
			key, result.s, (size_t) result.len, redis_expires_s);

	if (!rp || rp->type == REDIS_REPLY_ERROR) {
		rlog(LOG_ERR, "Redis Cluster SET failed for '%s': %s",
				key, rp ? rp->str : "no reply");
		if (rp) freeReplyObject(rp);
		goto err;
	}
	freeReplyObject(rp);

	/* PUBLISH notification for HA peers.
	 * PUBLISH is not natively routed by hiredis-cluster (it doesn't
	 * recognize it as a key-bearing command), so we target any node
	 * directly. In Redis Cluster, PUBLISH is broadcast to all nodes. */
	{
		redisClusterNodeIterator ni;
		redisClusterInitNodeIterator(&ni, cc);
		redisClusterNode *node = redisClusterNodeNext(&ni);
		if (node) {
			g_autofree char *channel = redis_cluster_notify_channel(r->db);
			g_autofree char *notify_msg = g_strdup_printf("set " STR_FORMAT,
					STR_FMT(&c->callid));
			rp = redisClusterCommandToNode(cc, node, "PUBLISH %s %s",
					channel, notify_msg);
			if (rp) freeReplyObject(rp);
		}
	}

	rwlock_unlock_r(&c->master_lock);
	g_free(to_free);
	bencode_buffer_free(ctx.buffer);
	return;

err:
	if (cc && cc->err)
		rlog(LOG_ERR, "Redis Cluster error: %s", cc->errstr);
	rwlock_unlock_r(&c->master_lock);
	if (to_free) g_free(to_free);
}

void redis_cluster_do_delete(call_t *c, struct redis *r) {
	redisClusterContext *cc;
	redisReply *rp;

	if (!r)
		return;
	if (c->redis_hosted_db < 0)
		return;

	LOCK(&r->lock);

	if (redis_cluster_check_conn(r) == REDIS_STATE_DISCONNECTED)
		return;

	cc = r->cluster_ctx;

	rwlock_lock_r(&c->master_lock);

	/* DEL rtpe<N>:<callid> */
	g_autofree char *key = redis_cluster_key(c->redis_hosted_db, &c->callid);
	rp = redisClusterCommand(cc, "DEL %s", key);
	if (!rp || rp->type == REDIS_REPLY_ERROR) {
		rlog(LOG_ERR, "Redis Cluster DEL failed for '%s': %s",
				key, rp ? rp->str : "no reply");
	}
	if (rp) freeReplyObject(rp);

	/* PUBLISH DEL notification for HA peers */
	{
		redisClusterNodeIterator ni;
		redisClusterInitNodeIterator(&ni, cc);
		redisClusterNode *node = redisClusterNodeNext(&ni);
		if (node) {
			g_autofree char *channel = redis_cluster_notify_channel(c->redis_hosted_db);
			g_autofree char *notify_msg = g_strdup_printf("del " STR_FORMAT,
					STR_FMT(&c->callid));
			rp = redisClusterCommandToNode(cc, node, "PUBLISH %s %s",
					channel, notify_msg);
			if (rp) freeReplyObject(rp);
		}
	}

	rwlock_unlock_r(&c->master_lock);
}

void redis_cluster_wipe(struct redis *r) {
	if (!r)
		return;

	LOCK(&r->lock);
	if (redis_cluster_check_conn(r) == REDIS_STATE_DISCONNECTED)
		return;

	redisClusterContext *cc = r->cluster_ctx;
	g_autofree char *pattern = g_strdup_printf("rtpe%d:*", r->db);

	/* SCAN each master node and DEL matching keys */
	redisClusterNodeIterator ni;
	redisClusterInitNodeIterator(&ni, cc);
	redisClusterNode *node;

	while ((node = redisClusterNodeNext(&ni)) != NULL) {
		if (node->role != REDIS_ROLE_MASTER)
			continue;

		char *cursor = g_strdup("0");
		do {
			redisReply *rp = redisClusterCommandToNode(cc, node,
					"SCAN %s MATCH %s COUNT 1000", cursor, pattern);
			g_free(cursor);
			cursor = NULL;

			if (!rp || rp->type != REDIS_REPLY_ARRAY || rp->elements != 2) {
				if (rp) freeReplyObject(rp);
				break;
			}

			cursor = g_strdup(rp->element[0]->str);
			redisReply *keys_arr = rp->element[1];

			for (size_t i = 0; i < keys_arr->elements; i++) {
				redisReply *drp = redisClusterCommand(cc,
						"DEL %s", keys_arr->element[i]->str);
				if (drp) freeReplyObject(drp);
			}

			freeReplyObject(rp);
		} while (cursor && strcmp(cursor, "0") != 0);

		g_free(cursor);
	}
}

/* ─── Restore (SCAN across all masters) ──────────────────────────────── */

int redis_cluster_restore(struct redis *r, bool foreign, int db) {
	if (!r)
		return 0;

	int prefix_db = (db >= 0) ? db : r->db;

	for (unsigned int i = 0; i < num_log_levels; i++)
		rtpe_config.common.log_levels[i] |= LOG_FLAG_RESTORE;

	rlog(LOG_DEBUG, "Restoring calls from Redis Cluster (prefix rtpe%d:)...", prefix_db);

	mutex_lock(&r->lock);

	if (redis_cluster_check_conn(r) == REDIS_STATE_DISCONNECTED) {
		rlog(LOG_WARN, "Redis Cluster not connected — skipping restore");
		mutex_unlock(&r->lock);
		goto done;
	}

	redisClusterContext *cc = r->cluster_ctx;

	/* Collect all matching keys from all master nodes via SCAN */
	g_autofree char *pattern = g_strdup_printf("rtpe%d:*", prefix_db);
	GQueue key_strings = G_QUEUE_INIT;

	redisClusterNodeIterator ni;
	redisClusterInitNodeIterator(&ni, cc);
	redisClusterNode *node;

	while ((node = redisClusterNodeNext(&ni)) != NULL) {
		if (node->role != REDIS_ROLE_MASTER)
			continue;

		char *cursor = g_strdup("0");
		do {
			redisReply *rp = redisClusterCommandToNode(cc, node,
					"SCAN %s MATCH %s COUNT 1000", cursor, pattern);
			g_free(cursor);
			cursor = NULL;

			if (!rp || rp->type != REDIS_REPLY_ARRAY || rp->elements != 2) {
				if (rp) freeReplyObject(rp);
				break;
			}

			cursor = g_strdup(rp->element[0]->str);
			redisReply *keys_arr = rp->element[1];

			for (size_t i = 0; i < keys_arr->elements; i++) {
				g_queue_push_tail(&key_strings,
						g_strndup(keys_arr->element[i]->str,
							keys_arr->element[i]->len));
			}

			freeReplyObject(rp);
		} while (cursor && strcmp(cursor, "0") != 0);

		g_free(cursor);
	}

	mutex_unlock(&r->lock);

	unsigned int total = g_queue_get_length(&key_strings);
	if (total == 0) {
		rlog(LOG_DEBUG, "No keys found in Redis Cluster for prefix rtpe%d:", prefix_db);
		goto done;
	}

	rlog(LOG_INFO, "Restoring %u calls from Redis Cluster (prefix rtpe%d:)", total, prefix_db);

	/* Temporarily set r->db to the prefix DB for json_restore_call.
	 * json_restore_call uses r->db via redis_cluster_key() in its
	 * cluster-aware GET path. */
	int saved_db = r->db;
	r->db = prefix_db;

	for (GList *l = key_strings.head; l; l = l->next) {
		char *full_key = l->data;
		char *colon = strchr(full_key, ':');
		if (!colon)
			continue;

		str callid;
		callid.s = colon + 1;
		callid.len = strlen(callid.s);

		json_restore_call(r, &callid, foreign);
	}

	r->db = saved_db;

done:
	{
		char *s;
		while ((s = g_queue_pop_head(&key_strings)))
			g_free(s);
	}

	for (unsigned int i = 0; i < num_log_levels; i++)
		if (rtpe_config.common.log_levels[i] > 0)
			rtpe_config.common.log_levels[i] &= ~LOG_FLAG_RESTORE;

	return 0;
}

/* ─── Async delete ───────────────────────────────────────────────────── */

void redis_cluster_delete_async_loop(void *d) {
	struct redis *r = rtpe_redis_write;

	if (!r || !r->is_cluster) {
		rlog(LOG_ERROR, "redis_cluster_delete_async_loop: no cluster write connection");
		return;
	}

	/*
	 * hiredis-cluster doesn't have a libevent async adapter suitable for
	 * fire-and-forget deletes, so we drain the queue with sync cluster
	 * commands on a timer. The queue entries are pre-formatted as
	 * "DEL rtpe<N>:<callid>".
	 */
	while (!rtpe_shutdown) {
		mutex_lock(&r->async_lock);

		if (!g_queue_is_empty(&r->async_queue)) {
			mutex_lock(&r->lock);

			if (redis_cluster_check_conn(r) == REDIS_STATE_CONNECTED) {
				redisClusterContext *cc = r->cluster_ctx;
				gchar *cmd;
				int total = 0;

				while ((cmd = g_queue_pop_head(&r->async_queue))) {
					redisReply *rp = redisClusterCommand(cc, cmd);
					if (rp) freeReplyObject(rp);
					g_free(cmd);
					total++;
				}

				rlog(LOG_DEBUG, "Redis Cluster async delete: processed %d commands",
						total);
			}

			mutex_unlock(&r->lock);
		}

		mutex_unlock(&r->async_lock);

		int interval = rtpe_config.redis_delete_async_interval;
		sleep(interval > 0 ? interval : 1);
	}
}

/* ─── Pub/Sub notifications ──────────────────────────────────────────── */

/*
 * Redis Cluster pub/sub: PUBLISH is broadcast to all nodes, so subscribing
 * to any single node receives all publications. We create a plain
 * redisAsyncContext to one master node for the SUBSCRIBE connection.
 */

static void on_cluster_notification(redisAsyncContext *actx, void *reply, void *privdata) {
	struct redis *r = privdata;
	redisReply *rr = reply;
	call_t *c = NULL;

	if (!rr || rr->type != REDIS_REPLY_ARRAY)
		return;

	/* ["message", "<channel>", "<payload>"]
	 * channel: "rtpe:notify:<db>"
	 * payload: "set <callid>" or "del <callid>" */
	if (rr->elements < 3)
		return;

	if (strcmp(rr->element[0]->str, "message") != 0)
		return;

	char *channel = rr->element[1]->str;
	char *payload = rr->element[2]->str;
	size_t payload_len = rr->element[2]->len;

	/* extract DB from channel */
	const char *db_str = strrchr(channel, ':');
	if (!db_str)
		return;
	db_str++;
	int notify_db = atoi(db_str);

	/* ignore notifications from our own DB prefix */
	if (notify_db == r->db)
		return;

	/* parse "set <callid>" or "del <callid>" */
	str callid;
	bool is_set = false;
	bool is_del = false;

	if (payload_len > 4 && strncmp(payload, "set ", 4) == 0) {
		is_set = true;
		callid.s = payload + 4;
		callid.len = payload_len - 4;
	} else if (payload_len > 4 && strncmp(payload, "del ", 4) == 0) {
		is_del = true;
		callid.s = payload + 4;
		callid.len = payload_len - 4;
	} else {
		rlog(LOG_WARN, "Redis Cluster notify: unknown payload: %s", payload);
		return;
	}

	log_info_str(&callid);

	if (is_set) {
		c = call_get(&callid);
		if (c) {
			rwlock_unlock_w(&c->master_lock);
			if (IS_FOREIGN_CALL(c)) {
				c->redis_hosted_db = rtpe_redis_write->db;
				redis_cluster_do_delete(c, rtpe_redis_write);
				call_destroy(c);
				release_closed_sockets();
			} else {
				rlog(LOG_DEBUG, "Redis Cluster notify: ignoring SET for OWN call "
						STR_FORMAT, STR_FMT(&callid));
				goto out;
			}
		}

		/* restore foreign call — set r->db to source DB for the GET key prefix */
		int saved_db = r->db;
		r->db = notify_db;
		json_restore_call(r, &callid, true);
		r->db = saved_db;
	}

	if (is_del) {
		c = call_get(&callid);
		if (!c) {
			rlog(LOG_NOTICE, "Redis Cluster notify: DEL — call not found: "
					STR_FORMAT, STR_FMT(&callid));
			goto out;
		}
		rwlock_unlock_w(&c->master_lock);
		if (!IS_FOREIGN_CALL(c)) {
			rlog(LOG_DEBUG, "Redis Cluster notify: ignoring DEL for OWN call "
					STR_FORMAT, STR_FMT(&callid));
			goto out;
		}
		call_destroy(c);
		release_closed_sockets();
	}

out:
	if (c)
		obj_put(c);
	log_info_reset();
}

static void cluster_notify_disconnect_cb(const redisAsyncContext *actx, int status) {
	if (status == REDIS_OK)
		rlog(LOG_NOTICE, "Redis Cluster notify: disconnected (user-initiated)");
	else
		rlog(LOG_ERR, "Redis Cluster notify: disconnected: %s",
				actx->errstr ? actx->errstr : "unknown error");
}

void redis_cluster_notify_loop(void *d) {
	struct redis *r = rtpe_redis_notify;
	if (!r) {
		rlog(LOG_ERROR, "Redis Cluster notify: no notify connection configured");
		return;
	}

	if (evthread_use_pthreads() < 0) {
		rlog(LOG_ERROR, "Redis Cluster notify: evthread_use_pthreads failed");
		return;
	}

	while (!rtpe_shutdown) {
		/* find a reachable master node for the subscribe connection */
		const char *node_host = NULL;
		int node_port = 0;

		mutex_lock(&r->lock);
		redisClusterContext *cc = r->cluster_ctx;
		if (cc && !cc->err) {
			redisClusterNodeIterator ni;
			redisClusterInitNodeIterator(&ni, cc);
			redisClusterNode *node;

			while ((node = redisClusterNodeNext(&ni)) != NULL) {
				if (node->role != REDIS_ROLE_MASTER)
					continue;
				if (node->host && node->port > 0) {
					node_host = node->host;
					node_port = node->port;
					break;
				}
			}
		}
		mutex_unlock(&r->lock);

		if (!node_host) {
			rlog(LOG_ERR, "Redis Cluster notify: no master node found");
			sleep(1);
			continue;
		}

		rlog(LOG_INFO, "Redis Cluster notify: subscribing via %s:%d",
				node_host, node_port);

		struct event_base *ev_base = event_base_new();
		if (!ev_base) {
			rlog(LOG_ERR, "Redis Cluster notify: event_base_new failed");
			sleep(1);
			continue;
		}

		redisAsyncContext *actx = redisAsyncConnect(node_host, node_port);
		if (!actx || actx->err) {
			rlog(LOG_ERR, "Redis Cluster notify: async connect failed: %s",
					actx ? actx->errstr : "alloc failed");
			if (actx) redisAsyncFree(actx);
			event_base_free(ev_base);
			sleep(1);
			continue;
		}

		redis_set_keepalive(actx->c.fd);

		if (redisAsyncSetDisconnectCallback(actx, cluster_notify_disconnect_cb) != REDIS_OK) {
			rlog(LOG_ERR, "Redis Cluster notify: set disconnect callback failed");
			redisAsyncFree(actx);
			event_base_free(ev_base);
			sleep(1);
			continue;
		}

		if (redisLibeventAttach(actx, ev_base) == REDIS_ERR) {
			rlog(LOG_ERR, "Redis Cluster notify: libevent attach failed");
			redisAsyncFree(actx);
			event_base_free(ev_base);
			sleep(1);
			continue;
		}

		/* AUTH if needed */
		if (r->auth) {
			if (redisAsyncCommand(actx, NULL, NULL, "AUTH %s", r->auth)
					!= REDIS_OK) {
				rlog(LOG_ERR, "Redis Cluster notify: AUTH failed");
				redisAsyncDisconnect(actx);
				event_base_free(ev_base);
				sleep(1);
				continue;
			}
		}

		/* SUBSCRIBE to each peer keyspace channel */
		rwlock_lock_r(&rtpe_config.keyspaces_lock);
		for (GList *l = rtpe_config.redis_subscribed_keyspaces.head; l; l = l->next) {
			int ks = GPOINTER_TO_INT(l->data);
			if (ks < 0)
				continue;
			g_autofree char *chan = redis_cluster_notify_channel(ks);
			rlog(LOG_INFO, "Redis Cluster notify: SUBSCRIBE %s", chan);
			redisAsyncCommand(actx, on_cluster_notification, r,
					"SUBSCRIBE %s", chan);
		}
		rwlock_unlock_r(&rtpe_config.keyspaces_lock);

		/* block on event loop until disconnect */
		event_base_dispatch(ev_base);

		/* cleanup */
		event_base_free(ev_base);

		if (!rtpe_shutdown) {
			rlog(LOG_WARN, "Redis Cluster notify: connection lost — reconnecting in 1s");
			sleep(1);
		}
	}
}

/* ─── Async event base actions (for shutdown) ────────────────────────── */

int redis_cluster_async_event_base_action(struct redis *r, enum event_base_action action) {
	if (!r)
		return -1;

	/* The notify loop manages its own event_base internally.
	 * For graceful shutdown, the rtpe_shutdown flag breaks the loops.
	 * If there's a shared async_ev, break it too. */
	if (action == EVENT_BASE_LOOPBREAK && r->async_ev)
		event_base_loopbreak(r->async_ev);

	return 0;
}

#endif /* HAVE_HIREDIS_CLUSTER */
