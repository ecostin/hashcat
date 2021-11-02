#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_scalar.cl"
#include "inc_hash_sha1.cl"
#endif

KERNEL_FQ void m08503_mxx (KERN_ATTR_BASIC ())
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  sha1_ctx_t ctx0;
  sha1_init (&ctx0);
  sha1_update_global_utf16be_swap (&ctx0, salt_bufs[SALT_POS].salt_buf_pc, salt_bufs[SALT_POS].salt_len_pc);
  sha1_update_global_utf16be_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha1_ctx_t ctx = ctx0;

    sha1_update_global_utf16be_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    sha1_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m08503_sxx (KERN_ATTR_BASIC ())
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R3]
  };

  sha1_ctx_t ctx0;
  sha1_init (&ctx0);
  sha1_update_global_utf16be_swap (&ctx0, salt_bufs[SALT_POS].salt_buf_pc, salt_bufs[SALT_POS].salt_len_pc);
  sha1_update_global_utf16be_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha1_ctx_t ctx = ctx0;
    sha1_update_global_utf16be_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);
    sha1_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
