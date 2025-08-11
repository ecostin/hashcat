
/**
 * Author......: Netherlands Forensic Institute
 * License.....: MIT
 */

/*
Pseudocode:
1. sha256(sha256(password=masterkey)||keyfile=none) = argon.in //TODO support keyfile
2. argon2(salt=transformseed, password=argon2.in) = argon2.out
2. sha512(masterseed||argon2.out||0x01) = final
3. sha512(0xFFFFFFFFFFFFFFFF||final) = out
4. hmac_sha256(init=out, data=header) = header_hmac
5. compare header_hmac to hash
*/

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_blake2b.cl)
#include M2S(INCLUDE_PATH/inc_hash_argon2.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct keepass4
{
  argon2_options_t options;

  u32 masterseed[32]; // needs to be this big because of sha512 not sure why it cannot be 512bit
  u32 header[64];

  //TODO support keyfile
} keepass4_t;

typedef struct argon2_tmp
{
  u32 state[4];

} argon2_tmp_t;

KERNEL_FQ KERNEL_FA void m34300_init (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, keepass4_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 gd4 = gid / 4;
  const u32 gm4 = gid % 4;

  GLOBAL_AS void *V;

  switch (gm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  const argon2_options_t options = esalt_bufs[DIGESTS_OFFSET_HOST].options;

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&options, V, gd4);

  sha256_ctx_t ctx0;
  sha256_init (&ctx0);
  sha256_update_global_swap (&ctx0, ((u32 *) pws[gid].i), pws[gid].pw_len);
  sha256_final (&ctx0);

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  w0[0] = ctx0.h[0];
  w0[1] = ctx0.h[1];
  w0[2] = ctx0.h[2];
  w0[3] = ctx0.h[3];
  w1[0] = ctx0.h[4];
  w1[1] = ctx0.h[5];
  w1[2] = ctx0.h[6];
  w1[3] = ctx0.h[7];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha256_update_64 (&ctx, w0, w1, w2, w3, 32);
  sha256_final (&ctx);

  pw_t pw;
  pw.pw_len=32; // output of sha256 is always 32 bytes
  for (size_t i = 0; i < 8; i++) {
    pw.i[i] = hc_swap32_S(ctx.h[i]);
  }

  argon2_init_pg (&pw, &salt_bufs[SALT_POS_HOST], &options, argon2_block);
}

KERNEL_FQ KERNEL_FA void m34300_loop (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, keepass4_t))
{
  const u64 gid = get_global_id (0);
  const u64 bid = get_group_id (0);
  const u64 lid = get_local_id (1);
  const u64 lsz = get_local_size (1);

  if (bid >= GID_CNT) return;

  const u32 argon2_thread = get_local_id (0);
  const u32 argon2_lsz = get_local_size (0);

  #ifdef ARGON2_PARALLELISM
  LOCAL_VK u64 shuffle_bufs[ARGON2_PARALLELISM][32];
  #else
  LOCAL_VK u64 shuffle_bufs[32][32];
  #endif

  LOCAL_AS u64 *shuffle_buf = shuffle_bufs[lid];

  SYNC_THREADS();

  const u32 bd4 = bid / 4;
  const u32 bm4 = bid % 4;

  GLOBAL_AS void *V;

  switch (bm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  argon2_options_t options = esalt_bufs[DIGESTS_OFFSET_HOST_BID].options;

  #ifdef IS_APPLE
  // it doesn't work on Apple, so we won't set it up
  #else
  #ifdef ARGON2_PARALLELISM
  options.parallelism = ARGON2_PARALLELISM;
  #endif
  #endif

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&options, V, bd4);

  argon2_pos_t pos;

  pos.pass   = (LOOP_POS / ARGON2_SYNC_POINTS);
  pos.slice  = (LOOP_POS % ARGON2_SYNC_POINTS);

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    for (pos.lane = lid; pos.lane < options.parallelism; pos.lane += lsz)
    {
      argon2_fill_segment (argon2_block, &options, &pos, shuffle_buf, argon2_thread, argon2_lsz);
    }

    SYNC_THREADS ();

    pos.slice++;

    if (pos.slice == ARGON2_SYNC_POINTS)
    {
      pos.slice = 0;
      pos.pass++;
    }
  }
}

KERNEL_FQ KERNEL_FA void m34300_comp (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, keepass4_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 gd4 = gid / 4;
  const u32 gm4 = gid % 4;

  GLOBAL_AS void *V;

  switch (gm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  keepass4_t keepass4 = esalt_bufs[DIGESTS_OFFSET_HOST];
  argon2_options_t options = keepass4.options;

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&options, V, gd4);

  u32 out[32] = { 0 }; // needs to be this big because of sha512 not sure why it cannot be 512bit
  argon2_final (argon2_block, &options, out);

  u32 pad[32] = { 0 }; // needs to be this big because of sha512 not sure why it cannot be 512bit
  pad[0] = 0x00000001;

  sha512_ctx_t ctx;
  sha512_init (&ctx);
  sha512_update_swap (&ctx, keepass4.masterseed, 32);
  sha512_update_swap (&ctx, out, 32);
  sha512_update_swap (&ctx, pad, 1);
  sha512_final (&ctx);

  u32 uint64_max_bytes[32] = {0};
  uint64_max_bytes[0] = 0xFFFFFFFF;
  uint64_max_bytes[1] = 0xFFFFFFFF;

  u32 final[32] = { 0 };
  final[ 0] = h32_from_64_S (ctx.h[0]);
  final[ 1] = l32_from_64_S (ctx.h[0]);
  final[ 2] = h32_from_64_S (ctx.h[1]);
  final[ 3] = l32_from_64_S (ctx.h[1]);
  final[ 4] = h32_from_64_S (ctx.h[2]);
  final[ 5] = l32_from_64_S (ctx.h[2]);
  final[ 6] = h32_from_64_S (ctx.h[3]);
  final[ 7] = l32_from_64_S (ctx.h[3]);
  final[ 8] = h32_from_64_S (ctx.h[4]);
  final[ 9] = l32_from_64_S (ctx.h[4]);
  final[10] = h32_from_64_S (ctx.h[5]);
  final[11] = l32_from_64_S (ctx.h[5]);
  final[12] = h32_from_64_S (ctx.h[6]);
  final[13] = l32_from_64_S (ctx.h[6]);
  final[14] = h32_from_64_S (ctx.h[7]);
  final[15] = l32_from_64_S (ctx.h[7]);

  sha512_ctx_t ctx2;
  sha512_init (&ctx2);
  sha512_update (&ctx2, uint64_max_bytes, 8);
  sha512_update (&ctx2, final, 64);
  sha512_final (&ctx2);

  for(int i=0; i<8; i++) {
    ctx2.h[i] = hc_swap64_S(ctx2.h[i]);
  }
  u32 outu32[64] = { 0 }; //needs to be 64 in size!
  for (size_t i = 0; i < 16; i++) {
    outu32[i] = ((( u32 *)&ctx2)[i]); //ctx2=sha512 so has u64 state hence we cast it to u32
  }

  sha256_hmac_ctx_t ctx3;
  sha256_hmac_init_swap (&ctx3, outu32, 64);
  sha256_hmac_update_swap (&ctx3, keepass4.header, 253);
  sha256_hmac_final (&ctx3);

  const u32 r0 = hc_swap32_S(ctx3.opad.h[0]);
  const u32 r1 = hc_swap32_S(ctx3.opad.h[1]);
  const u32 r2 = hc_swap32_S(ctx3.opad.h[2]);
  const u32 r3 = hc_swap32_S(ctx3.opad.h[3]);

  #define il_pos 0

  #include COMPARE_M
}
