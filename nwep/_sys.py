"""_sys is the raw nerve, a 1:1 cffi binding of the libnwep c abi NWG0200 L0.

this module is ugly on purpose. it declares the c types and functions exactly as
they appear in include/nwep.h and loads the prebuilt shared library, so every
higher layer is pure python over a complete, total ffi surface. nobody is meant
to enjoy calling it directly, but it is always here, public, and reachable for
anything the safe layers do not yet wrap (no cliffs, NWG0200).

the declarations grow one protocol slice at a time. _CDEF is the single source
of the declared surface, and tests/test_coverage.py diffs the symbols named in
it against symbols.txt (the real exports), so a typo or a vanished export fails
ci NWG1000.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import cffi

if TYPE_CHECKING:
    from typing import TypeAlias

    # CData is used across all binding modules as the opaque cffi pointer type.
    # At runtime it is ffi.CData; under TYPE_CHECKING it is Any so mypy treats
    # it as a valid type alias rather than an unknown variable.
    CData: TypeAlias = Any

# the c declarations, verbatim from include/nwep.h, grown slice by slice. cffi
# cannot read #define or #include, so sizes are inlined as literals and fixed
# arrays in parameters are written as pointers (they decay to one at the abi).
_CDEF = """
/* core: version, zeroize, errors NW130000. */
const char *nwep_version(void);
void nwep_zeroize(void *ptr, size_t len);
const char *nwep_strerror(int err);

/* identity NW040200 NW090500. */
typedef struct { uint8_t bytes[32]; } nwep_node_id;
typedef struct { uint8_t pub_[32]; uint8_t priv_[32]; } nwep_keypair;

int nwep_identity_generate(nwep_node_id *out_id, nwep_keypair *out_kp);
int nwep_nodeid_verify(const nwep_node_id *id, const uint8_t *pubkey);
int nwep_nodeid_to_base58(char *out, size_t *outlen, const nwep_node_id *id);
int nwep_nodeid_from_base58(nwep_node_id *out, const char *str, size_t len);
int nwep_nodeid_from_pubkey(nwep_node_id *out, const uint8_t *pubkey);
int nwep_ed25519_sign(uint8_t *out_sig, const uint8_t *msg, size_t msg_len,
                      const uint8_t *privkey);
int nwep_ed25519_verify(const uint8_t *sig, const uint8_t *msg, size_t msg_len,
                        const uint8_t *pubkey);
int nwep_keypair_save_pem(uint8_t *out, size_t *outlen, const nwep_keypair *kp);
int nwep_keypair_load_pem(nwep_keypair *out_kp, const uint8_t *pem, size_t len);

/* shamir secret sharing NW150400. */
int nwep_shamir_split(const uint8_t *secret, size_t secret_len, size_t t, size_t n,
                      uint8_t *out, size_t *outlen);
int nwep_shamir_combine(const uint8_t *shares, size_t n_shares, size_t share_len,
                        uint8_t *out_secret, size_t *out_secret_len);

/* transport address NW110300. */
typedef struct { uint8_t opaque[32]; } nwep_address;
void nwep_address_loopback(nwep_address *out, uint16_t port);
void nwep_address_wildcard(nwep_address *out, uint16_t port);
void nwep_address_ipv4_mapped(nwep_address *out, uint8_t a, uint8_t b,
                              uint8_t c, uint8_t d, uint16_t port);
void nwep_address_from_bytes(nwep_address *out, const uint8_t *addr, uint16_t port);
uint16_t nwep_address_get_port(const nwep_address *addr);

/* web:// uri NW040400. */
typedef struct {
    nwep_node_id node_id;
    uint16_t     port;
    const char  *path;
    size_t       path_len;
} nwep_uri;
int nwep_uri_parse(nwep_uri *out, const char *input, size_t len);

/* method NW050000 + status NW080000 tokens. */
const char *nwep_method_str(int method);
const char *nwep_status_str(int status);

/* messages, server, responses NW060000 NW070000. */
typedef struct nwep_server nwep_server;
typedef struct nwep_message nwep_message;
typedef struct { void *opaque; } nwep_buf;

/* the dispatch handler, called for each decoded request inside server_tick. */
typedef int (*nwep_handler_fn)(nwep_server *server, uint64_t conn_id,
                               uint64_t stream_id, const nwep_message *request,
                               nwep_buf *resp_buf, void *userdata);

/* message accessors NW060000. returned pointers are valid for the call only. */
const char *nwep_message_get_header(const nwep_message *msg, const char *name);
int nwep_message_header_at(const nwep_message *msg, size_t i,
                           const char **name, const char **value);
const char *nwep_message_get_status(const nwep_message *msg);
const uint8_t *nwep_message_get_body(const nwep_message *msg, size_t *out_len);
size_t nwep_message_header_count(const nwep_message *msg);

/* in-handler response builders, written into the handler's resp_buf NW060000 NW080000. */
int nwep_response_ok(nwep_buf *resp, const uint8_t *body, size_t body_len);
int nwep_response_status(nwep_buf *resp, const char *status,
                         const uint8_t *body, size_t body_len);
int nwep_response_header(nwep_buf *resp, const char *name, const char *value);

/* conditional reads NW060700 + byte ranges NW060800. */
typedef struct { uint64_t start; uint64_t end; } nwep_range;
int nwep_request_is_fresh(const nwep_message *req, const char *etag);
int nwep_request_range(const nwep_message *req, uint64_t total_len, const char *etag,
                       nwep_range *out, size_t max_out, size_t *out_count);
int nwep_response_not_modified(nwep_buf *resp, const char *etag);
int nwep_response_partial(nwep_buf *resp, const uint8_t *body, size_t body_len,
                          const nwep_range *ranges, size_t count, const char *content_type);
int nwep_response_range_not_satisfiable(nwep_buf *resp, uint64_t total_len);

/* standalone response signature verify with an explicit origin key NW060900. */
int nwep_response_verify(const nwep_message *resp, const uint8_t *pubkey,
                         const char *path, uint64_t now_secs);

/* verbatim relay + pre-signed frame cache NW000017. */
int nwep_response_relay(nwep_buf *resp, const nwep_message *origin);
int nwep_response_capture(nwep_buf *resp, uint8_t *out, size_t cap, size_t *out_len);
int nwep_response_blit(nwep_buf *resp, const uint8_t *frame, size_t len);
int nwep_server_relay(nwep_server *server, uint64_t conn_id, uint64_t stream_id,
                      const nwep_message *origin_resp);
int nwep_server_respond_blit(nwep_server *server, uint64_t conn_id, uint64_t stream_id,
                             const uint8_t *frame, size_t len);

/* server lifecycle + event loop NW070000. */
int nwep_server_listen(nwep_server **out, const nwep_keypair *identity,
                       const nwep_address *bind_addr);
int nwep_server_set_handler(nwep_server *server, nwep_handler_fn handler,
                            void *userdata);
int nwep_server_tick(nwep_server *server, int64_t now_ms);
uint16_t nwep_server_local_port(const nwep_server *server);
intptr_t nwep_server_fd(const nwep_server *server);
int nwep_server_next_timeout_ms(nwep_server *server, int64_t now_ms);
int nwep_server_get_peer_nodeid(const nwep_server *server, uint64_t conn_id,
                                nwep_node_id *out_node_id);
int nwep_server_local_nodeid(const nwep_server *server, nwep_node_id *out);
void nwep_server_close(nwep_server *server);

/* multi-reactor scale-out: SO_REUSEPORT + adopted sockets + cid sharding NW000017. */
int nwep_server_listen_reuseport(nwep_server **out, const nwep_keypair *identity,
                                 const nwep_address *bind_addr);
int nwep_server_listen_fd(nwep_server **out, const nwep_keypair *identity, uintptr_t fd);
int nwep_server_listen_fd_sharded(nwep_server **out, const nwep_keypair *identity,
                                  uintptr_t fd, uint16_t shard_id);
int nwep_reuse_port_supported(void);
int nwep_cid_shard_id(const uint8_t *cid, size_t cid_len);

/* server observability + lifecycle ops NW000017. */
typedef struct {
    uint64_t connections_active;
    uint64_t connections_accepted;
    uint64_t connections_refused;
    uint64_t connections_closed;
    uint64_t bytes_received;
    uint64_t bytes_sent;
    uint64_t datagrams_received;
    uint64_t datagrams_sent;
    uint64_t requests_dispatched;
    uint64_t requests_shed;
    uint64_t parked_active;
    int32_t load;
} nwep_server_metrics;
int nwep_server_metrics_get(const nwep_server *server, nwep_server_metrics *out);
int nwep_server_load(const nwep_server *server);
void nwep_server_set_overloaded(nwep_server *server, int on);
void nwep_server_set_max_parked(nwep_server *server, size_t max_parked);
int nwep_server_drain(nwep_server *server);
int nwep_server_is_drained(const nwep_server *server);
int nwep_server_conn_compression(const nwep_server *server, uint64_t conn_id);
int nwep_server_last_handshake_error(const nwep_server *server);

/* deferred (out-of-band) response, answered later from the loop NW060900. */
int nwep_server_respond(nwep_server *server, uint64_t conn_id, uint64_t stream_id,
                        const char *status, const uint8_t *body, size_t body_len);
int nwep_server_respond_header(nwep_server *server, uint64_t conn_id,
                               uint64_t stream_id, const char *name,
                               const char *value);
void nwep_message_free(nwep_message *msg);

/* client NW070000. */
typedef struct nwep_client nwep_client;
typedef struct { const char *name; const char *value; } nwep_header;

int nwep_client_connect(nwep_client **out, const nwep_keypair *identity,
                        const nwep_node_id *target_node_id,
                        const nwep_address *target_addr);

/* alternate driven connects: adopt a socket, or non-blocking + poll NW000017. */
typedef uint64_t nwep_request_id;
int nwep_client_connect_fd(nwep_client **out, const nwep_keypair *identity,
                           const nwep_node_id *target_node_id,
                           const nwep_address *target_addr, uintptr_t fd);
int nwep_client_connect_async(nwep_client **out, const nwep_keypair *identity,
                              const nwep_node_id *target_node_id,
                              const nwep_address *target_addr);
int nwep_client_connect_fd_async(nwep_client **out, const nwep_keypair *identity,
                                 const nwep_node_id *target_node_id,
                                 const nwep_address *target_addr, uintptr_t fd);
int nwep_client_connect_poll(nwep_client *client);

/* concurrent in-flight requests on a driven client NW000017. */
typedef void (*nwep_request_done_fn)(nwep_client *client, nwep_request_id id,
                                     int status, nwep_message *resp, void *ud);
int nwep_client_request_submit(nwep_client *client, int method, const char *path,
                               const nwep_header *headers, const uint8_t *body,
                               size_t body_len, nwep_request_id *out_id);
int nwep_client_request_poll(nwep_client *client, nwep_request_id id,
                             nwep_message **out_response);
void nwep_client_request_cancel(nwep_client *client, nwep_request_id id);
int nwep_client_set_request_done(nwep_client *client, nwep_request_done_fn cb, void *ud);
int nwep_client_verify_response(const nwep_client *client, const nwep_message *resp,
                                const char *path, uint64_t now_secs);

int nwep_client_send(nwep_client *client, int method, const char *path,
                     const nwep_header *headers, const uint8_t *body,
                     size_t body_len, nwep_message **out_response);
int nwep_client_tick(nwep_client *client, int64_t now_ms);
intptr_t nwep_client_fd(const nwep_client *client);
int nwep_client_next_timeout_ms(nwep_client *client, int64_t now_ms);
int nwep_client_is_alive(const nwep_client *client);
int nwep_client_peer_pubkey(const nwep_client *client, uint8_t *out_pubkey);
nwep_message *nwep_client_poll_notify(nwep_client *client);
void nwep_client_close(nwep_client *client);

/* client observability NW000017 + negotiated compression NW000017. */
typedef struct {
    uint64_t requests_inflight;
    uint64_t requests_completed;
    uint64_t requests_failed;
    uint64_t smoothed_rtt_us;
    int32_t alive;
} nwep_client_metrics;
int nwep_client_metrics_get(const nwep_client *client, nwep_client_metrics *out);
int nwep_client_compression(const nwep_client *client);

/* server NOTIFY push NW060200: server -> connection, drained by poll_notify. */
int nwep_server_notify(nwep_server *server, uint64_t conn_id, const char *event,
                       const nwep_header *headers, const uint8_t *body, size_t body_len);

/* response cache NW060700 NW060900: per-client + shared signed. */
typedef struct nwep_cache nwep_cache;
nwep_cache *nwep_cache_create(size_t max_bytes, size_t max_entries);
void nwep_cache_free(nwep_cache *cache);
void nwep_cache_clear(nwep_cache *cache);
void nwep_cache_stats(const nwep_cache *cache, uint64_t *out_hits, uint64_t *out_misses,
                      uint64_t *out_stores, uint64_t *out_evictions);
int nwep_client_set_cache(nwep_client *client, nwep_cache *cache);
int nwep_cache_put_signed(nwep_cache *cache, const char *method, const char *path,
                          const nwep_message *resp, const uint8_t *origin_pubkey,
                          uint64_t now_secs);
int nwep_cache_get_signed(nwep_cache *cache, const char *method, const char *path,
                          const uint8_t *origin_pubkey, uint64_t now_secs,
                          nwep_message **out);

/* streamed responses (STREAM mode, NW060200). blocking, like client_send. */
int nwep_client_open_stream(nwep_client *client, int method, const char *path,
                            const nwep_header *headers, uint64_t *out_stream_id);
int nwep_client_stream_response(nwep_client *client, uint64_t stream_id,
                                nwep_message **out_response);
int nwep_client_stream_recv(nwep_client *client, uint64_t stream_id,
                            uint8_t *out_buf, size_t cap, size_t *out_len, int *out_ended);
int nwep_client_stream_verify(nwep_client *client, uint64_t stream_id, const uint8_t *pubkey);
void nwep_client_stream_close(nwep_client *client, uint64_t stream_id);

/* server out-streaming: begin from a handler, then send/end from the loop. */
int nwep_server_begin_stream(nwep_server *server, uint64_t conn_id, uint64_t stream_id,
                             const char *path, const char *status, const nwep_header *headers);
int nwep_server_stream_send(nwep_server *server, uint64_t conn_id, uint64_t stream_id,
                            const uint8_t *body, size_t body_len);
int nwep_server_stream_end(nwep_server *server, uint64_t conn_id, uint64_t stream_id);

/* dht NW110000. its clock is unix seconds, not monotonic ms. */
typedef struct nwep_dht nwep_dht;
typedef struct {
    nwep_node_id node_id;
    nwep_address addr;
} nwep_bootstrap_entry;
typedef struct {
    nwep_node_id node_id;
    nwep_address addr;
    uint8_t      pubkey[32];
    uint64_t     seq;
    uint64_t     timestamp;
} nwep_dht_record;
typedef struct {
    uint64_t datagrams_sent;
    uint64_t datagrams_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
} nwep_dht_metrics;

int nwep_dht_parse_bootstrap(nwep_bootstrap_entry *out, const char *input, size_t len);
int nwep_dht_attach(nwep_dht **out, nwep_server *server,
                    const nwep_bootstrap_entry *bootstrap_nodes,
                    size_t bootstrap_count, uint64_t initial_seq);
int nwep_dht_bootstrap(nwep_dht *dht, uint64_t now_secs);
int nwep_dht_announce(nwep_dht *dht, const nwep_address *service_addr, uint64_t now_secs);
int nwep_dht_start_lookup(nwep_dht *dht, const nwep_node_id *target_node_id, uint64_t now_secs);
int nwep_dht_lookup_result(const nwep_dht *dht, const nwep_node_id *target_node_id,
                           nwep_dht_record *out_record);
int nwep_dht_tick(nwep_dht *dht, uint64_t now_secs);
int nwep_dht_next_timeout_ms(const nwep_dht *dht, uint64_t now_secs);
int nwep_dht_metrics_get(const nwep_dht *dht, nwep_dht_metrics *out);
void nwep_dht_close(nwep_dht *dht);
/* connect by resolving a node_id through an attached dht (declared here so the
 * nwep_dht type is in scope), blocking up to lookup_timeout_ms. */
int nwep_client_connect_by_nodeid(nwep_client **out, const nwep_keypair *identity,
                                  const nwep_node_id *target_node_id, nwep_dht *dht,
                                  uint32_t lookup_timeout_ms);

/* trust-log entries + in-memory merkle log NW120200 NW120300, core, no blst. */
typedef struct {
    uint8_t node_id[32];
    uint8_t pubkey[32];
    uint8_t recovery_commitment[32];
    uint64_t timestamp;
    uint8_t signature[64];
} nwep_keybinding;
typedef struct {
    uint8_t node_id[32];
    uint8_t old_pubkey[32];
    uint8_t new_pubkey[32];
    uint64_t timestamp;
    uint64_t overlap_expiry;
    uint8_t sig_old[64];
    uint8_t sig_new[64];
} nwep_keyrotation;
typedef struct {
    uint8_t node_id[32];
    uint8_t revoked_pubkey[32];
    uint8_t recovery_pubkey[32];
    uint8_t reason;
    uint64_t timestamp;
    uint8_t signature[64];
} nwep_revocation;

int nwep_keybinding_create(const uint8_t *pubkey, const uint8_t *recovery_commitment,
                           uint64_t timestamp, const uint8_t *privkey,
                           uint8_t *out, size_t *outlen);
int nwep_keyrotation_create(const uint8_t *node_id, const uint8_t *old_pubkey,
                            const uint8_t *new_pubkey, uint64_t timestamp,
                            uint64_t overlap_expiry, const uint8_t *old_privkey,
                            const uint8_t *new_privkey, uint8_t *out, size_t *outlen);
int nwep_revocation_create(const uint8_t *node_id, const uint8_t *revoked_pubkey,
                           const uint8_t *recovery_pubkey, uint8_t reason,
                           uint64_t timestamp, const uint8_t *recovery_privkey,
                           uint8_t *out, size_t *outlen);
int nwep_log_entry_type(const uint8_t *bytes, size_t len);
int nwep_keybinding_decode(const uint8_t *bytes, size_t len, nwep_keybinding *out);
int nwep_keyrotation_decode(const uint8_t *bytes, size_t len, nwep_keyrotation *out);
int nwep_revocation_decode(const uint8_t *bytes, size_t len, nwep_revocation *out);

typedef struct nwep_log nwep_log;
nwep_log *nwep_log_create(void);
void nwep_log_free(nwep_log *log);
int64_t nwep_log_append(nwep_log *log, const uint8_t *bytes, size_t len);
uint64_t nwep_log_size(const nwep_log *log);
int nwep_log_root(const nwep_log *log, uint8_t *out_root);

/* log server: routes /log/* requests, signs with an identity NW000014. */
typedef struct nwep_log_server nwep_log_server;
typedef void (*nwep_log_append_fn)(void *ctx, const uint8_t *entry, size_t len,
                                   uint64_t index);
nwep_log_server *nwep_log_server_create(const nwep_keypair *identity, nwep_log *log);
void nwep_log_server_free(nwep_log_server *ls);
void nwep_log_server_set_on_append(nwep_log_server *ls, nwep_log_append_fn cb, void *ctx);
int nwep_log_server_dispatch(nwep_log_server *ls, uint64_t conn_id,
                             const nwep_message *req, nwep_buf *resp, int64_t now_secs);
"""

# the trust-layer c declarations NW120000. these symbols live only in the full
# libnwep.so (built with blst), not in libnwep_core.so, so they are declared
# separately and are only callable when the full library is loaded. cffi dlopen
# is lazy, so declaring them is harmless on a core-only build until one is called.
_TRUST_CDEF = """
/* the full trust-build version string NW120000. */
const char *nwep_trust_version(void);

/* bls12-381 threshold signatures NW120500. */
int nwep_bls_keygen(uint8_t *out_sk, uint8_t *out_pk);
int nwep_bls_sign(uint8_t *out_sig, const uint8_t *sk, const uint8_t *msg, size_t msg_len);
int nwep_bls_verify(const uint8_t *sig, const uint8_t *pk, const uint8_t *msg, size_t msg_len);
int nwep_bls_aggregate(uint8_t *out_sig, const uint8_t *sigs, size_t n);
int nwep_bls_verify_aggregate(const uint8_t *agg_sig, const uint8_t *pks, size_t n,
                              const uint8_t *msg, size_t msg_len);

/* checkpoint: the signed merkle commitment for an epoch NW120700. */
typedef struct nwep_checkpoint nwep_checkpoint;
int nwep_checkpoint_decode(const uint8_t *bytes, size_t len, nwep_checkpoint **out_cp);
void nwep_checkpoint_free(nwep_checkpoint *cp);
int nwep_checkpoint_staleness(const nwep_checkpoint *cp, int64_t now_secs);
int nwep_genesis_checkpoint_create(const uint8_t *bls_secrets, const uint8_t *bls_pubkeys,
                                   const uint8_t *indices, size_t n_founders,
                                   size_t threshold, uint8_t *out, size_t *outlen);

/* trust store: the anchor set + installed checkpoint state NW120700 NW120800. */
typedef struct nwep_trust_store nwep_trust_store;
nwep_trust_store *nwep_trust_store_create(void);
void nwep_trust_store_free(nwep_trust_store *ts);
int nwep_trust_store_load_genesis_anchors(nwep_trust_store *ts, const uint8_t *pubkeys, size_t n);
int nwep_trust_store_update_checkpoint(nwep_trust_store *ts, const uint8_t *cp_bytes,
                                       size_t cp_len, int64_t now_secs);
int nwep_checkpoint_verify(const nwep_trust_store *ts, const uint8_t *cp_bytes,
                           size_t cp_len, int64_t now_secs);
int nwep_trust_store_apply_anchor_change(nwep_trust_store *ts, const uint8_t *entry_bytes,
                                         size_t entry_len, uint64_t current_epoch);
int nwep_trust_store_observe_log_size(nwep_trust_store *ts, uint64_t observed);
uint64_t nwep_trust_store_max_log_size(const nwep_trust_store *ts);
int nwep_trust_store_save(const nwep_trust_store *ts, uint8_t *out, size_t *outlen);
int nwep_trust_store_load(nwep_trust_store *ts, const uint8_t *bytes, size_t len);
int nwep_trust_store_verify_key(nwep_trust_store *ts, nwep_client *client,
                                const uint8_t *node_id, const uint8_t *recovery_commitment,
                                int64_t now_secs);
int nwep_trust_store_verify_key_binding(nwep_trust_store *ts, const uint8_t *node_id,
                                        const uint8_t *expected_pubkey,
                                        const uint8_t *bundle, size_t bundle_len,
                                        int64_t now_secs);
int nwep_trust_store_evaluate_key_rotation(const uint8_t *rotation_bytes, size_t rotation_len,
                                           const uint8_t *presented_pubkey, int64_t now_secs);

/* anchor node: the quorum checkpoint producer NW120600 NW120900. */
typedef struct nwep_anchor_node nwep_anchor_node;
nwep_anchor_node *nwep_anchor_node_create(const uint8_t *pubkey, const uint8_t *privkey,
                                          const uint8_t *bls_secret, const uint8_t *bls_pubkey,
                                          uint64_t share_index, uint64_t collection_window_ms);
void nwep_anchor_node_free(nwep_anchor_node *node);
int nwep_anchor_node_collect_log_root(nwep_anchor_node *node, uint64_t epoch,
                                      const uint8_t *server_root, uint64_t server_log_size,
                                      const uint8_t *local_root);
int nwep_anchor_node_dispatch(nwep_anchor_node *node, const uint8_t *requester_node_id,
                              const uint8_t *anchor_ids, size_t n_anchors,
                              const nwep_message *req, nwep_buf *resp, int64_t now_secs);
int nwep_anchor_node_produce_partial_sig(nwep_anchor_node *node, uint64_t epoch,
                                         const uint8_t *merkle_root, uint64_t log_size,
                                         uint8_t *out_index, uint8_t *out_sig);
int nwep_anchor_request_partial_sig(nwep_client *client, uint64_t epoch,
                                    const uint8_t *merkle_root, uint64_t log_size,
                                    const uint8_t *peer_bls_pubkey,
                                    uint8_t *out_index, uint8_t *out_sig);
int nwep_anchor_finish_checkpoint(uint64_t epoch, const uint8_t *merkle_root, uint64_t log_size,
                                  const uint8_t *indices, const uint8_t *sigs, size_t n_partials,
                                  const uint8_t *anchor_bls_pks, size_t n_anchors,
                                  uint8_t *out, size_t *outlen);
"""

# the byte sizes the protocol fixes NW040200. re-exported so the safe layer
# never hardcodes a magic number.
NODEID_SIZE = 32
PUBKEY_SIZE = 32
PRIVKEY_SIZE = 32
SIG_SIZE = 64

# bls12-381 sizes NW120500.
BLS_PUBKEY_SIZE = 48
BLS_SECKEY_SIZE = 32
BLS_SIGNATURE_SIZE = 96

# the default web/1 udp port, used when a uri omits one NW040400.
DEFAULT_PORT = 6937

ffi = cffi.FFI()
ffi.cdef(_CDEF)
ffi.cdef(_TRUST_CDEF)


def _lib_names(prefer_core: bool) -> list[str]:
    """returns the platform's shared-library filenames, in load-priority order.

    the artifact name differs per os: `libnwep.so` on linux/android, `nwep.dll`
    on windows (no `lib` prefix), `libnwep.dylib` on macos - so a binding that
    hardcodes `.so` only loads on linux NWG1200.
    full build (`nwep`) first by default; NWEP_LIB=core flips to the lean build.
    """
    if sys.platform == "win32":
        prefix, suffix = "", ".dll"
    elif sys.platform == "darwin":
        prefix, suffix = "lib", ".dylib"
    else:  # linux, android, and other elf platforms
        prefix, suffix = "lib", ".so"
    bases = ["nwep_core", "nwep"] if prefer_core else ["nwep", "nwep_core"]
    return [f"{prefix}{base}{suffix}" for base in bases]


def _candidate_dirs() -> list[Path]:
    """yields the directories to search for the built shared library, in order.

    honors the NWEP_LIB_DIR override first, then a copy bundled alongside this
    package (how a wheel ships the native lib), then the repo's zig-out relative
    to this file, then the process working directory - so a checkout works without
    configuration and a packaged install finds its bundled copy. each base is
    searched under both `lib/` and `bin/` because zig installs unix `.so`/`.dylib`
    under lib/ but windows `.dll` under bin/.
    """
    bases: list[Path] = []
    env = os.environ.get("NWEP_LIB_DIR")
    if env:
        bases.append(Path(env))
    # a wheel bundles the native lib inside the package (next to this file).
    pkg_dir = Path(__file__).resolve().parent
    bases.append(pkg_dir)
    bases.append(pkg_dir / "_libs")
    # bindings/python/nwep/_sys.py -> repo root is three parents up.
    repo_root = Path(__file__).resolve().parents[3]
    bases.append(repo_root / "zig-out")
    bases.append(Path.cwd() / "zig-out")
    # expand each zig-out-style base into its lib/ and bin/ subdirs; a bare dir
    # (NWEP_LIB_DIR, the package dir) is also searched directly.
    dirs: list[Path] = []
    for base in bases:
        dirs.append(base)
        dirs.append(base / "lib")
        dirs.append(base / "bin")
    # the nwep-installer's default install locations for this OS, user then
    # system - covers "I ran the GUI installer" with no env setup at all.
    # Mirrors installer/src-tauri/src/target.rs::default_prefix /
    # locations_at exactly; keep these in sync if that file changes.
    dirs.extend(_installer_default_dirs())
    return dirs


def _installer_default_dirs() -> list[Path]:
    """the nwep-installer's default lib/bin dirs for this OS, user scope first.

    user scope is the only one ever written to by `_download_library` (no
    elevation needed); system scope is checked but never written. Returns an
    empty list on a platform the installer doesn't target (macOS, Android -
    no "default install location" concept there).
    """
    if sys.platform == "win32":
        dirs: list[Path] = []
        local_appdata = os.environ.get("LOCALAPPDATA")
        if local_appdata:
            prefix = Path(local_appdata) / "Programs" / "nwep"
            dirs += [prefix / "lib", prefix / "bin"]
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        prefix = Path(program_files) / "nwep"
        dirs += [prefix / "lib", prefix / "bin"]
        return dirs
    if sys.platform.startswith("linux"):
        return [Path.home() / ".local" / "lib", Path("/usr/local/lib")]
    return []  # macOS, Android: not an installer target.


def _pkgconfig_libdir() -> Path | None:
    """runs `pkg-config --variable=libdir nwep` to find the install prefix lib dir.

    only attempted on Linux where the installer writes a .pc file. returns None
    silently on any failure so the caller falls through to the default dir search.
    """
    if not sys.platform.startswith("linux"):
        return None
    import subprocess

    try:
        r = subprocess.run(
            ["pkg-config", "--variable=libdir", "nwep"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode == 0 and r.stdout.strip():
            return Path(r.stdout.strip())
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return None


def _load_library() -> "cffi.api.FFI.CData":
    """loads libnwep and returns the cffi library handle NWG1200, both bundles.

    prefers the full libnwep (the trust build, with the bls anchor layer) because
    that is the artifact the bindings ship - so the trust layer is available by
    default. set NWEP_LIB=core to opt into the lean, trust-less libnwep_core
    instead (no blst), for a consumer that does not need anchor verification, and
    NWEP_LIB_DIR to point at the directory holding the .so files.

    Resolution order, first match wins: NWEP_LIB_DIR, a wheel-bundled copy, the
    repo's own zig-out, then the nwep-installer's default install locations for
    this OS.

    returns the dlopen'd library whose symbols back every call in this package.
    raises OSError when the library can't be found.
    """
    prefer_core = os.environ.get("NWEP_LIB", "").lower() in (
        "core",
        "core_only",
        "nwep_core",
    )
    names = _lib_names(prefer_core)

    # try bare names first - on a system install ldconfig (Linux) or PATH (Windows)
    # makes this work with no path at all.
    if not os.environ.get("NWEP_LIB_DIR"):
        for name in names:
            try:
                return ffi.dlopen(name)
            except OSError:
                pass

    # Linux user install: ask pkg-config where the library landed.
    if pc_dir := _pkgconfig_libdir():
        for name in names:
            path = pc_dir / name
            if path.exists():
                return ffi.dlopen(str(path))

    for directory in _candidate_dirs():
        for name in names:
            path = directory / name
            if path.exists():
                return ffi.dlopen(str(path))

    raise OSError(
        "nwep requires libnwep to be installed. "
        "download and run the installer from http://pkg.rebuildtheinter.net/tools/latest/ "
        "(if it is already installed somewhere unusual, set NWEP_LIB_DIR to the "
        "directory holding it)"
    )


lib = _load_library()


def trust_available() -> bool:
    """returns whether the loaded library is the full build with the trust layer.

    the trust symbols exist only in libnwep.so (built with blst), so this probes
    for one. the bindings ship libnwep, so this is True by default; it returns
    False only when NWEP_LIB=core opted into the lean libnwep_core build.
    """
    try:
        lib.nwep_bls_keygen  # noqa: B018 - attribute access is the dlopen probe.
        return True
    except AttributeError:
        return False
