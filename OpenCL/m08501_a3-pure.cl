/**
 * Author......: Detack GmbH / part of https://www.detack.de/en/epas
 * License.....: MIT
 */

#include M2S(INCLUDE_PATH/inc_racf_kdfaes.cl)

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct pbkdf2_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];
  u32  dgst[32];
  u32  out[32];
} pbkdf2_sha256_tmp_t;

typedef struct pbkdf2_sha256
{
  u32 salt_buf[64];
} pbkdf2_sha256_t;

KERNEL_FQ void m08501_mxx (KERN_ATTR_VECTOR_ESALT (pbkdf2_sha256_t))
{
  u32 username[4] = { 0 }, salt_buf[4], pw[4], digest[4];
  const u64 gid = get_global_id (0);

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];
  #ifdef REAL_SHM 
    LOCAL_VK u32 s_te0[256];
    LOCAL_VK u32 s_te1[256];
    LOCAL_VK u32 s_te2[256];
    LOCAL_VK u32 s_te3[256];
    LOCAL_VK u32 s_te4[256];
  #endif
  
  initialize_local_buffers(s_SPtrans, s_skb
    #ifdef REAL_SHM
      , s_te0, s_te1, s_te2, s_te3, s_te4
    #endif
  );
  
  if (gid >= GID_CNT) return;
  
  for (int i = 0; i < 2; i++) username[i] = salt_bufs[SALT_POS_HOST].salt_buf_pc[i];
  for (int i = 0; i < 4; i++) salt_buf[i] = salt_bufs[SALT_POS_HOST].salt_buf_pc[2 + i];
  for (int i = 0; i < 4; i++) pw[i] = pws[gid].i[i];

  u32 pw_len = pws[gid].pw_len;
  const u32 pw0l = pw[0];
  
  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    pw[0] = pw0l | words_buf_r[il_pos / VECT_SIZE];
    racf_kdfaes(username, salt_buf, pw, digest, s_SPtrans, s_skb
      #ifdef REAL_SHM
        , s_te0, s_te1, s_te2, s_te3, s_te4
      #endif
    );

    const u32 r0 = digest[0], r1 = digest[1], r2 = digest[2], r3 = digest[3];
    #include COMPARE_M
  }    
}

KERNEL_FQ void m08501_sxx (KERN_ATTR_VECTOR_ESALT (pbkdf2_sha256_t))
{
  u32 username[4] = { 0 }, salt_buf[4], pw[4], digest[4];
  const u64 gid = get_global_id (0);

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];
  #ifdef REAL_SHM 
    LOCAL_VK u32 s_te0[256];
    LOCAL_VK u32 s_te1[256];
    LOCAL_VK u32 s_te2[256];
    LOCAL_VK u32 s_te3[256];
    LOCAL_VK u32 s_te4[256];
  #endif
  
  initialize_local_buffers(s_SPtrans, s_skb
    #ifdef REAL_SHM
      , s_te0, s_te1, s_te2, s_te3, s_te4
    #endif
  );
  
  if (gid >= GID_CNT) return;

  for (int i = 0; i < 2; i++) username[i] = salt_bufs[SALT_POS_HOST].salt_buf_pc[i];
  for (int i = 0; i < 4; i++) salt_buf[i] = salt_bufs[SALT_POS_HOST].salt_buf_pc[2 + i];
  for (int i = 0; i < 4; i++) pw[i] = pws[gid].i[i];

  u32 pw_len = pws[gid].pw_len;
  const u32 pw0l = pw[0];

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };
  
  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    pw[0] = pw0l | words_buf_r[il_pos / VECT_SIZE];
    
    racf_kdfaes(username, salt_buf, pw, digest, s_SPtrans, s_skb
      #ifdef REAL_SHM
        , s_te0, s_te1, s_te2, s_te3, s_te4
      #endif
    );

    const u32 r0 = digest[0], r1 = digest[1], r2 = digest[2], r3 = digest[3];
    #include COMPARE_S
  }
}
