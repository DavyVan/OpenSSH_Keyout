/* $OpenBSD: kexc25519c.c,v 1.7 2015/01/26 06:10:03 djm Exp $ */
/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2013 Aris Adamantiadis.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "sshkey.h"
#include "cipher.h"
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "ssh2.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"

static int
input_kex_c25519_reply(int type, u_int32_t seq, void *ctxt);

int
kexc25519_client(struct ssh *ssh)
{
	// /*
	//  * Added by David FAN Quan
	//  */
	// const char* filepath = "/etc/ssh.key";
	// FILE* file = fopen(filepath, "a");
	// if(file)
	// {
	// 	fprintf(file, "%s\n", "kexc25519_client()");
	// }
	// fclose(file);

	struct kex *kex = ssh->kex;
	int r;

	kexc25519_keygen(kex->c25519_client_key, kex->c25519_client_pubkey);
#ifdef DEBUG_KEXECDH
	dump_digest("client private key:", kex->c25519_client_key,
	    sizeof(kex->c25519_client_key));
#endif
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEX_ECDH_INIT)) != 0 ||
	    (r = sshpkt_put_string(ssh, kex->c25519_client_pubkey,
	    sizeof(kex->c25519_client_pubkey))) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		return r;

	debug("expecting SSH2_MSG_KEX_ECDH_REPLY");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_ECDH_REPLY, &input_kex_c25519_reply);
	return 0;
}

static int
input_kex_c25519_reply(int type, u_int32_t seq, void *ctxt)
{
	struct ssh *ssh = ctxt;
	struct kex *kex = ssh->kex;
	struct sshkey *server_host_key = NULL;
	struct sshbuf *shared_secret = NULL;
	u_char *server_pubkey = NULL;
	u_char *server_host_key_blob = NULL, *signature = NULL;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, pklen, sbloblen, hashlen;
	int r;

	if (kex->verify_host_key == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}

	/* hostkey */
	if ((r = sshpkt_get_string(ssh, &server_host_key_blob,
	    &sbloblen)) != 0 ||
	    (r = sshkey_from_blob(server_host_key_blob, sbloblen,
	    &server_host_key)) != 0)
		goto out;
	if (server_host_key->type != kex->hostkey_type ||
	    (kex->hostkey_type == KEY_ECDSA &&
	    server_host_key->ecdsa_nid != kex->hostkey_nid)) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (kex->verify_host_key(server_host_key, ssh) == -1) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}

	/* Q_S, server public key */
	/* signed H */
	if ((r = sshpkt_get_string(ssh, &server_pubkey, &pklen)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;
	if (pklen != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}

#ifdef DEBUG_KEXECDH
	dump_digest("server public key:", server_pubkey, CURVE25519_SIZE);
#endif

	if ((shared_secret = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = kexc25519_shared_key(kex->c25519_client_key, server_pubkey,
	    shared_secret)) < 0)
		goto out;

	/* calc and verify H */
	hashlen = sizeof(hash);
	if ((r = kex_c25519_hash(
	    kex->hash_alg,
	    kex->client_version_string,
	    kex->server_version_string,
	    sshbuf_ptr(kex->my), sshbuf_len(kex->my),
	    sshbuf_ptr(kex->peer), sshbuf_len(kex->peer),
	    server_host_key_blob, sbloblen,
	    kex->c25519_client_pubkey,
	    server_pubkey,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) < 0)
		goto out;

	if ((r = sshkey_verify(server_host_key, signature, slen, hash, hashlen,
	    ssh->compat)) != 0)
		goto out;

	/* save session id */
	if (kex->session_id == NULL) {
		kex->session_id_len = hashlen;
		kex->session_id = malloc(kex->session_id_len);
		if (kex->session_id == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(kex->session_id, hash, kex->session_id_len);
	}

	if ((r = kex_derive_keys(ssh, hash, hashlen, shared_secret)) == 0)
		r = kex_send_newkeys(ssh);

	/*
	 * Added by David FAN Quan
	 */
	// const char* filepath = "/etc/ssh.key";
	// FILE* file = fopen(filepath, "a");
	// if(file)
	// {
		//convert keys and session id from uchar to hex-string
		//shared secret
		// char shared_secret_hex[1000] = {0};
		// int i;
		// int shared_secret_len = sshbuf_len(shared_secret);
		// const u_char* shared_secret_ptr = sshbuf_ptr(shared_secret);
		// for(i = 0; i < shared_secret_len; i++)
		// {
		// 	if(shared_secret_ptr[i]/16 < 10)
		// 		shared_secret_hex[2*i] = shared_secret_ptr[i]/16 + '0';
		// 	else
		// 		shared_secret_hex[2*i] = shared_secret_ptr[i]/16 + 'a' - 10;
		// 	if(shared_secret_ptr[i]%16 < 10)
		// 		shared_secret_hex[2*i+1] = shared_secret_ptr[i]%16 + '0';
		// 	else
		// 		shared_secret_hex[2*i+1] = shared_secret_ptr[i]%16 + 'a' - 10;
		// }

		//session id
		// char session_id_hex[1000] = {0};
		// for(i = 0; i < kex->session_id_len; i++)
		// {
		// 	if(kex->session_id[i]/16 < 10)
		// 		session_id_hex[2*i] = kex->session_id[i]/16 + '0';
		// 	else
		// 		session_id_hex[2*i] = kex->session_id[i]/16 + 'a' - 10;
		// 	if(kex->session_id[i]%16 < 10)
		// 		session_id_hex[2*i+1] = kex->session_id[i]%16 + '0';
		// 	else
		// 		session_id_hex[2*i+1] = kex->session_id[i]%16 + 'a' - 10;
		// }

		//enc key
		// char enc_key_hex[1000] = {0};
		// u_int enc_key_len = kex->newkeys[MODE_IN]->enc.key_len;
		// u_char* enc_key_ptr = kex->newkeys[MODE_IN]->enc.key;
		// for(i = 0; i < enc_key_len; i++)
		// {
		// 	printf("%d\n", i);
		// 	if(enc_key_ptr[i]/16 < 10)
		// 		enc_key_hex[2*i] = enc_key_ptr[i]/16 + '0';
		// 	else
		// 		enc_key_hex[2*i] = enc_key_ptr[i]/16 + 'a' - 10;
		// 	if(enc_key_ptr[i]%16 < 10)
		// 		enc_key_hex[2*i+1] = enc_key_ptr[i]%16 + '0';
		// 	else
		// 		enc_key_hex[2*i+1] = enc_key_ptr[i]%16 + 'a' - 10;
		// }

		// int k;
		// for(k = 0; k < MODE_MAX; k++)
		// {
		// 	char hex[1000] = {0};
		// 	u_int len = kex->newkeys[k]->enc.key_len;
		// 	u_char* ptr = kex->newkeys[k]->enc.key;
		// 	for(i = 0; i < len; i++)
		// 	{
		// 		//printf("%d\n", i);
		// 		if(ptr[i]/16 < 10)
		// 			hex[2*i] = ptr[i]/16 + '0';
		// 		else
		// 			hex[2*i] = ptr[i]/16 + 'a' - 10;
		// 		if(ptr[i]%16 < 10)
		// 			hex[2*i+1] = ptr[i]%16 + '0';
		// 		else
		// 			hex[2*i+1] = ptr[i]%16 + 'a' - 10;
		// 	}
		// 	printf("%d %u %s\n", k, len, hex);
		// }

		// fprintf(file, "session_id=%u %s enc_key=%u %s\n",
		// 		kex->session_id_len,
		// 		session_id_hex,
		// 		// shared_secret_len,
		// 		// shared_secret_hex,
		// 		enc_key_len,
		// 		enc_key_hex);
	// }
	// fclose(file);

out:
	explicit_bzero(hash, sizeof(hash));
	explicit_bzero(kex->c25519_client_key, sizeof(kex->c25519_client_key));
	free(server_host_key_blob);
	free(server_pubkey);
	free(signature);
	sshkey_free(server_host_key);
	sshbuf_free(shared_secret);
	return r;
}
