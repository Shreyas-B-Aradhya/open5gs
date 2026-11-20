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

#ifndef MME_S10_MM_CONTEXT_H
#define MME_S10_MM_CONTEXT_H

#include "ogs-nas-eps.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * MM Context IE, "EPS Security Context and Quadruplets" form
 * (TS 29.274 clause 8.38, Figure 8.38-7, Security Mode 4).
 *
 * Only what an S1 handover needs is carried: no authentication vectors
 * (number of quadruplets/quintuplets is 0), no old security context.
 */
#define MME_S10_MM_CONTEXT_SECURITY_MODE_EPS    4
#define MME_S10_MM_CONTEXT_MAX_LEN              256
#define MME_S10_MEI_MAX_LEN                     8

typedef struct mme_s10_mm_context_s {
    uint8_t     ksi_asme;               /* 3 bits */
    uint8_t     nas_int_alg;            /* 0 = EIA0 .. 3 = EIA3 */
    uint8_t     nas_enc_alg;            /* 0 = EEA0 .. 3 = EEA3 */
    uint32_t    nas_dl_count;           /* 24 bits */
    uint32_t    nas_ul_count;           /* 24 bits */
    uint8_t     kasme[OGS_SHA256_DIGEST_SIZE];

    bool        nhi;                    /* NH and NCC present */
    uint8_t     nh[OGS_SHA256_DIGEST_SIZE];
    uint8_t     ncc;                    /* 3 bits */

    bool        drxi;
    uint8_t     drx[2];

    bool        sambri;                 /* subscribed UE-AMBR, kbps */
    uint32_t    sub_ue_ambr_ul, sub_ue_ambr_dl;
    bool        uambri;                 /* used UE-AMBR, kbps */
    uint32_t    used_ue_ambr_ul, used_ue_ambr_dl;

    ogs_nas_ue_network_capability_t ue_network_capability;
    ogs_nas_ms_network_capability_t ms_network_capability;

    uint8_t     mei_len;
    uint8_t     mei[MME_S10_MEI_MAX_LEN];

    uint8_t     access_restriction;     /* ECNA..UNA flags octet */
} mme_s10_mm_context_t;

/* Returns the number of octets written into buf, or -1 */
int mme_s10_encode_mm_context(
        const mme_s10_mm_context_t *ctx, uint8_t *buf, int buf_len);

/* Returns the number of octets consumed, or -1 if malformed/unsupported */
int mme_s10_decode_mm_context(
        mme_s10_mm_context_t *ctx, const uint8_t *buf, int len);

#ifdef __cplusplus
}
#endif

#endif /* MME_S10_MM_CONTEXT_H */
