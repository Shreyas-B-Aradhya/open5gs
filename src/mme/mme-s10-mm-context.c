/*
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * MM Context IE (TS 29.274 clause 8.38), "EPS Security Context and
 * Quadruplets" form, Figure 8.38-7. The IE header (type/length/instance)
 * is handled by the TLV layer; this file covers the value part, which
 * starts at octet 5 of the figure:
 *
 *   5      Security Mode(3) | NHI | DRXI | KSI_ASME(3)
 *   6      Nr of Quintuplets(3) | Nr of Quadruplets(3) | UAMBRI | OSCI
 *   7      SAMBRI | Used NAS integrity alg(3) | Used NAS cipher(4)
 *   8-10   NAS Downlink Count
 *   11-13  NAS Uplink Count
 *   14-45  KASME
 *          Authentication Quadruplets / Quintuplets      (none sent)
 *          DRX parameter (2)                             if DRXI
 *          NH (32), spare(5) | NCC(3)                    if NHI
 *          UL/DL Subscribed UE-AMBR (4+4)                if SAMBRI
 *          UL/DL Used UE-AMBR (4+4)                      if UAMBRI
 *          Length + UE Network Capability
 *          Length + MS Network Capability
 *          Length + MEI
 *          ECNA|NBNA|HNNA|ENA|INA|GANA|GENA|UNA
 *          (old EPS security context etc.: not sent, ignored on receive)
 */

#include "mme-s10-mm-context.h"

#define PUT8(__v) do { \
    if (n + 1 > buf_len) return -1; \
    buf[n++] = (uint8_t)(__v); \
} while (0)
#define PUT24(__v) do { \
    if (n + 3 > buf_len) return -1; \
    buf[n++] = (uint8_t)((__v) >> 16); \
    buf[n++] = (uint8_t)((__v) >> 8); \
    buf[n++] = (uint8_t)(__v); \
} while (0)
#define PUT32(__v) do { \
    if (n + 4 > buf_len) return -1; \
    buf[n++] = (uint8_t)((__v) >> 24); \
    buf[n++] = (uint8_t)((__v) >> 16); \
    buf[n++] = (uint8_t)((__v) >> 8); \
    buf[n++] = (uint8_t)(__v); \
} while (0)
#define PUTN(__p, __l) do { \
    if (n + (int)(__l) > buf_len) return -1; \
    memcpy(buf + n, (__p), (__l)); \
    n += (__l); \
} while (0)

int mme_s10_encode_mm_context(
        const mme_s10_mm_context_t *ctx, uint8_t *buf, int buf_len)
{
    int n = 0;
    uint8_t len;

    if (!ctx || !buf)
        return -1;

    PUT8((MME_S10_MM_CONTEXT_SECURITY_MODE_EPS << 5) |
         (ctx->nhi ? 0x10 : 0) | (ctx->drxi ? 0x08 : 0) |
         (ctx->ksi_asme & 0x07));
    /* no quintuplets, no quadruplets, no old security context */
    PUT8(ctx->uambri ? 0x02 : 0);
    PUT8((ctx->sambri ? 0x80 : 0) |
         ((ctx->nas_int_alg & 0x07) << 4) | (ctx->nas_enc_alg & 0x0f));
    PUT24(ctx->nas_dl_count & 0xffffff);
    PUT24(ctx->nas_ul_count & 0xffffff);
    PUTN(ctx->kasme, OGS_SHA256_DIGEST_SIZE);

    if (ctx->drxi)
        PUTN(ctx->drx, 2);

    if (ctx->nhi) {
        PUTN(ctx->nh, OGS_SHA256_DIGEST_SIZE);
        PUT8(ctx->ncc & 0x07);
    }

    if (ctx->sambri) {
        PUT32(ctx->sub_ue_ambr_ul);
        PUT32(ctx->sub_ue_ambr_dl);
    }
    if (ctx->uambri) {
        PUT32(ctx->used_ue_ambr_ul);
        PUT32(ctx->used_ue_ambr_dl);
    }

    len = ctx->ue_network_capability.length;
    if (len > sizeof(ctx->ue_network_capability) - 1)
        return -1;
    PUT8(len);
    PUTN(((const uint8_t *)&ctx->ue_network_capability) + 1, len);

    len = ctx->ms_network_capability.length;
    if (len > sizeof(ctx->ms_network_capability) - 1)
        return -1;
    PUT8(len);
    PUTN(((const uint8_t *)&ctx->ms_network_capability) + 1, len);

    if (ctx->mei_len > MME_S10_MEI_MAX_LEN)
        return -1;
    PUT8(ctx->mei_len);
    PUTN(ctx->mei, ctx->mei_len);

    PUT8(ctx->access_restriction);

    return n;
}

#define NEED(__l) do { if (n + (int)(__l) > len) return -1; } while (0)

int mme_s10_decode_mm_context(
        mme_s10_mm_context_t *ctx, const uint8_t *buf, int len)
{
    int n = 0;
    uint8_t mode, n_quin, n_quad, l;
    int i;

    if (!ctx || !buf)
        return -1;
    memset(ctx, 0, sizeof(*ctx));

    NEED(3);
    mode = buf[0] >> 5;
    if (mode != MME_S10_MM_CONTEXT_SECURITY_MODE_EPS)
        return -1;
    ctx->nhi = (buf[0] & 0x10) != 0;
    ctx->drxi = (buf[0] & 0x08) != 0;
    ctx->ksi_asme = buf[0] & 0x07;
    n_quin = buf[1] >> 5;
    n_quad = (buf[1] >> 2) & 0x07;
    ctx->uambri = (buf[1] & 0x02) != 0;
    ctx->sambri = (buf[2] & 0x80) != 0;
    ctx->nas_int_alg = (buf[2] >> 4) & 0x07;
    ctx->nas_enc_alg = buf[2] & 0x0f;
    n = 3;

    NEED(6 + OGS_SHA256_DIGEST_SIZE);
    ctx->nas_dl_count = (buf[n] << 16) | (buf[n+1] << 8) | buf[n+2];
    n += 3;
    ctx->nas_ul_count = (buf[n] << 16) | (buf[n+1] << 8) | buf[n+2];
    n += 3;
    memcpy(ctx->kasme, buf + n, OGS_SHA256_DIGEST_SIZE);
    n += OGS_SHA256_DIGEST_SIZE;

    /*
     * Quadruplet: RAND(16) XRES-len(1) XRES AUTN-len(1) AUTN KASME(32)
     * Quintuplet: RAND(16) XRES-len XRES CK(16) IK(16) AUTN-len AUTN
     * Not used by the handover; skipped.
     */
    for (i = 0; i < n_quad; i++) {
        NEED(17); n += 16; l = buf[n++];
        NEED(l + 1); n += l; l = buf[n++];
        NEED(l + 32); n += l + 32;
    }
    for (i = 0; i < n_quin; i++) {
        NEED(17); n += 16; l = buf[n++];
        NEED(l + 33); n += l + 32; l = buf[n++];
        NEED(l); n += l;
    }

    if (ctx->drxi) {
        NEED(2);
        memcpy(ctx->drx, buf + n, 2);
        n += 2;
    }

    if (ctx->nhi) {
        NEED(OGS_SHA256_DIGEST_SIZE + 1);
        memcpy(ctx->nh, buf + n, OGS_SHA256_DIGEST_SIZE);
        n += OGS_SHA256_DIGEST_SIZE;
        ctx->ncc = buf[n++] & 0x07;
    }

#define GET32(__v) do { \
    NEED(4); \
    (__v) = ((uint32_t)buf[n] << 24) | ((uint32_t)buf[n+1] << 16) | \
            ((uint32_t)buf[n+2] << 8) | buf[n+3]; \
    n += 4; \
} while (0)
    if (ctx->sambri) {
        GET32(ctx->sub_ue_ambr_ul);
        GET32(ctx->sub_ue_ambr_dl);
    }
    if (ctx->uambri) {
        GET32(ctx->used_ue_ambr_ul);
        GET32(ctx->used_ue_ambr_dl);
    }

    NEED(1);
    l = buf[n++];
    if (l > sizeof(ctx->ue_network_capability) - 1)
        return -1;
    NEED(l);
    ctx->ue_network_capability.length = l;
    memcpy(((uint8_t *)&ctx->ue_network_capability) + 1, buf + n, l);
    n += l;

    /* The fields below are optional on the wire: stop at the end */
    if (n == len)
        return n;
    l = buf[n++];
    if (l > sizeof(ctx->ms_network_capability) - 1)
        return -1;
    NEED(l);
    ctx->ms_network_capability.length = l;
    memcpy(((uint8_t *)&ctx->ms_network_capability) + 1, buf + n, l);
    n += l;

    if (n == len)
        return n;
    l = buf[n++];
    NEED(l);
    if (l <= MME_S10_MEI_MAX_LEN) {
        ctx->mei_len = l;
        memcpy(ctx->mei, buf + n, l);
    }
    n += l;

    if (n == len)
        return n;
    ctx->access_restriction = buf[n++];

    /* Old EPS security context, VDN preference etc. are ignored */
    return len;
}
