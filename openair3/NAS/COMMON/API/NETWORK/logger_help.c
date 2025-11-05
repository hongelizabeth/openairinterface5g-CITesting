// Language: C
#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include "nr_nas_msg.h"
#include "common/utils/LOG/log.h"


/* Helper printers */
static const char *fgs_mm_state_str(fgs_mm_state_t s) {
  switch (s) {
    case FGS_DEREGISTERED: return "FGS_DEREGISTERED";
    case FGS_DEREGISTERED_INITIATED: return "FGS_DEREGISTERED_INITIATED";
    case FGS_REGISTERED_INITIATED: return "FGS_REGISTERED_INITIATED";
    case FGS_REGISTERED: return "FGS_REGISTERED";
    case FGS_SERVICE_REQUEST_INITIATED: return "FGS_SERVICE_REQUEST_INITIATED";
    default: return "UNKNOWN_FGS_MM_STATE";
  }
}

static const char *fgs_mm_mode_str(fgs_mm_mode_t m) {
  switch (m) {
    case FGS_NOT_CONNECTED: return "FGS_NOT_CONNECTED";
    case FGS_IDLE: return "FGS_IDLE";
    case FGS_CONNECTED: return "FGS_CONNECTED";
    default: return "UNKNOWN_FGS_MM_MODE";
  }
}

/* Convert binary buffer to space separated hex string (out must have size >= 3*len+1) */
static void buf_to_hexstr(const uint8_t *buf, size_t len, char *out, size_t outlen) {
  if (!buf || outlen == 0) {
    if (out && outlen) out[0] = '\0';
    return;
  }
  size_t pos = 0;
  for (size_t i = 0; i < len && pos + 3 < outlen; ++i) {
    int written = snprintf(out + pos, outlen - pos, "%02x", buf[i]);
    if (written < 0) break;
    pos += (size_t)written;
    if (i + 1 < len && pos + 2 < outlen) {
      out[pos++] = ' ';
      out[pos] = '\0';
    }
  }
  if (pos < outlen) out[pos] = '\0';
}

/* Main logger using LOG_E (component NAS) */
void log_nr_ue_nas(const nr_ue_nas_t *n) {
  if (!n) {
    LOG_E(NAS, "nr_ue_nas_t: NULL");
    return;
  }

  LOG_E(NAS, "nr_ue_nas_t @ %p", (const void*)n);
  LOG_E(NAS, "  fiveGMM_state: %s (%d)", fgs_mm_state_str(n->fiveGMM_state), (int)n->fiveGMM_state);
  LOG_E(NAS, "  fiveGMM_mode:  %s (%d)", fgs_mm_mode_str(n->fiveGMM_mode), (int)n->fiveGMM_mode);
  LOG_E(NAS, "  uicc: %p", (const void*)n->uicc);

  /* Security keys: allocate enough room for largest field (32 bytes -> 3*32+1) */
  char hexbuf[3 * 32 + 1];
  buf_to_hexstr(n->security.kausf, 32, hexbuf, sizeof(hexbuf));
  LOG_E(NAS, "  security.kausf: %s\n", hexbuf);
  buf_to_hexstr(n->security.kseaf, 32, hexbuf, sizeof(hexbuf));
  LOG_E(NAS, "  security.kseaf: %s\n", hexbuf);
  buf_to_hexstr(n->security.kamf, 32, hexbuf, sizeof(hexbuf));
  LOG_E(NAS, "  security.kamf: %s\n", hexbuf);

  /* 16 byte fields */
  char hexbuf16[3 * 16 + 1];
  buf_to_hexstr(n->security.knas_int, 16, hexbuf16, sizeof(hexbuf16));
  LOG_E(NAS, "  security.knas_int: %s\n", hexbuf16);
  buf_to_hexstr(n->security.knas_enc, 16, hexbuf16, sizeof(hexbuf16));
  LOG_E(NAS, "  security.knas_enc: %s\n", hexbuf16);
  buf_to_hexstr(n->security.res, 16, hexbuf16, sizeof(hexbuf16));
  LOG_E(NAS, "  security.res: %s\n", hexbuf16);
  buf_to_hexstr(n->security.rand, 16, hexbuf16, sizeof(hexbuf16));
  LOG_E(NAS, "  security.rand: %s\n", hexbuf16);

  buf_to_hexstr(n->security.kgnb, 32, hexbuf, sizeof(hexbuf));
  LOG_E(NAS, "  security.kgnb: %s\n", hexbuf);
  LOG_E(NAS, "  security.nas_count_ul: %" PRIu32 "\n", n->security.nas_count_ul);
  LOG_E(NAS, "  security.nas_count_dl: %" PRIu32 "\n", n->security.nas_count_dl);

  LOG_E(NAS, "  security_container: %p\n", (const void*)n->security_container);
  LOG_E(NAS, "  guti: %p\n", (const void*)n->guti);
  LOG_E(NAS, "  termination_procedure: %s\n", n->termination_procedure ? "true" : "false");
  LOG_E(NAS, "  UE_id: %d\n", (int)n->UE_id);
  LOG_E(NAS, "  is_rrc_inactive: %s\n", n->is_rrc_inactive ? "true" : "false");
  LOG_E(NAS, "  t3512: %d\n", n->t3512);
  LOG_E(NAS, "  t3448: %d\n", n->t3448);
  LOG_E(NAS, "  t3446: %d\n", n->t3446);
  LOG_E(NAS, "  ksi: %p\n", (const void*)n->ksi);
  if (n->ksi) {
    LOG_E(NAS, "    first byte of ksi: 0x%02x\n", (unsigned)(*n->ksi));
  }
}