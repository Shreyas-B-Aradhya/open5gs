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

#include "mme-context.h"
#include "s1ap-path.h"
#include "mme-s10-build.h"
#include "mme-s10-handler.h"
#include "mme-s10-mm-context.h"
#include "mme-gtp-path.h"
#include "mme-timer.h"
#include "mme-sm.h"
#include "s1ap-build.h"

static const char *ip_to_str(const ogs_ip_t *ip, char *buf, int len)
{
    buf[0] = 0;
    if (ip->ipv4)
        inet_ntop(AF_INET, &ip->addr, buf, len);
    else if (ip->ipv6)
        inet_ntop(AF_INET6, ip->addr6, buf, len);
    return buf;
}

void mme_s10_log_pdn_connections(ogs_gtp2_forward_relocation_request_t *req)
{
    int i, j, count = 0;
    char b1[OGS_ADDRSTRLEN], b2[OGS_ADDRSTRLEN], b3[OGS_ADDRSTRLEN];

    ogs_assert(req);

    for (i = 0; i < OGS_MAX_NUM_OF_SESS; i++) {
        ogs_gtp2_tlv_pdn_connection_t *pdn =
            &req->mme_sgsn_amf_ue_eps_pdn_connections[i];
        char apn[OGS_MAX_APN_LEN+1] = "";
        char ue_ip[OGS_ADDRSTRLEN] = "";
        char pgw_c[OGS_ADDRSTRLEN] = "";
        uint32_t pgw_c_teid = 0, ambr_ul = 0, ambr_dl = 0;
        int bearers = 0;

        if (!pdn->presence)
            continue;
        count++;

        if (pdn->apn.presence && pdn->apn.data &&
            pdn->apn.len && pdn->apn.len <= OGS_MAX_APN_LEN)
            ogs_fqdn_parse(apn, pdn->apn.data, pdn->apn.len);

        if (pdn->ipv4_address.presence && pdn->ipv4_address.data &&
            pdn->ipv4_address.len == OGS_IPV4_LEN)
            inet_ntop(AF_INET, pdn->ipv4_address.data, ue_ip, sizeof(ue_ip));

        if (pdn->pgw_s5_s8_ip_address_for_control_plane_or_pmip.presence &&
            pdn->pgw_s5_s8_ip_address_for_control_plane_or_pmip.data) {
            ogs_gtp2_f_teid_t *f =
                pdn->pgw_s5_s8_ip_address_for_control_plane_or_pmip.data;
            ogs_ip_t ip;
            pgw_c_teid = be32toh(f->teid);
            memset(&ip, 0, sizeof(ip));
            if (ogs_gtp2_f_teid_to_ip(f, &ip) == OGS_OK)
                ip_to_str(&ip, pgw_c, sizeof(pgw_c));
        }

        if (pdn->aggregate_maximum_bit_rate.presence &&
            pdn->aggregate_maximum_bit_rate.data &&
            pdn->aggregate_maximum_bit_rate.len >= sizeof(ogs_gtp2_ambr_t)) {
            ogs_gtp2_ambr_t *a = pdn->aggregate_maximum_bit_rate.data;
            ambr_ul = be32toh(a->uplink);
            ambr_dl = be32toh(a->downlink);
        }

        for (j = 0; j < OGS_BEARER_PER_UE; j++)
            if (pdn->bearer_contexts[j].presence)
                bearers++;

        ogs_info("  PDN[%d] APN[%s] linked-EBI[%d] UE-IPv4[%s] "
                "PGW-S5C[%s teid 0x%x] APN-AMBR[ul %u dl %u kbps] "
                "bearers[%d]", i, apn,
                pdn->linked_eps_bearer_id.presence ?
                    pdn->linked_eps_bearer_id.u8 : 0,
                ue_ip, pgw_c, pgw_c_teid, ambr_ul, ambr_dl, bearers);

        for (j = 0; j < OGS_BEARER_PER_UE; j++) {
            ogs_gtp2_tlv_bearer_context_t *bc = &pdn->bearer_contexts[j];
            ogs_gtp2_bearer_qos_t qos;
            ogs_ip_t ip;
            uint32_t sgw_u_teid = 0, pgw_u_teid = 0;

            if (!bc->presence)
                continue;

            b1[0] = b2[0] = b3[0] = 0;
            memset(&qos, 0, sizeof(qos));
            if (bc->bearer_level_qos.presence && bc->bearer_level_qos.data)
                ogs_gtp2_parse_bearer_qos(&qos, &bc->bearer_level_qos);

            if (bc->s1_u_enodeb_f_teid.presence &&
                bc->s1_u_enodeb_f_teid.data) {
                ogs_gtp2_f_teid_t *f = bc->s1_u_enodeb_f_teid.data;
                sgw_u_teid = be32toh(f->teid);
                memset(&ip, 0, sizeof(ip));
                if (ogs_gtp2_f_teid_to_ip(f, &ip) == OGS_OK)
                    ip_to_str(&ip, b1, sizeof(b1));
            }
            if (bc->s4_u_sgsn_f_teid.presence && bc->s4_u_sgsn_f_teid.data) {
                ogs_gtp2_f_teid_t *f = bc->s4_u_sgsn_f_teid.data;
                pgw_u_teid = be32toh(f->teid);
                memset(&ip, 0, sizeof(ip));
                if (ogs_gtp2_f_teid_to_ip(f, &ip) == OGS_OK)
                    ip_to_str(&ip, b2, sizeof(b2));
            }

            ogs_info("    bearer EBI[%d] QCI[%d] ARP[%d] "
                    "SGW-S1U[%s teid 0x%x] PGW-S5U[%s teid 0x%x]",
                    bc->eps_bearer_id.presence ? bc->eps_bearer_id.u8 : 0,
                    qos.qci, qos.priority_level,
                    b1, sgw_u_teid, b2, pgw_u_teid);
        }
    }

    if (!count)
        ogs_info("  no PDN Connections in the request");
}

#define S10_EBI_MIN 5
#define S10_EBI_MAX 15

int mme_s10_parse_relocation_pdns(
        ogs_gtp2_forward_relocation_request_t *req,
        mme_s10_reloc_pdn_t *out, int max)
{
    int i, j, n = 0;
    uint16_t ebi_used = 0;

    ogs_assert(req);
    ogs_assert(out);

    for (i = 0; i < OGS_MAX_NUM_OF_SESS; i++) {
        ogs_gtp2_tlv_pdn_connection_t *pdn =
            &req->mme_sgsn_amf_ue_eps_pdn_connections[i];
        ogs_gtp2_tlv_bearer_context_t *bc = NULL;
        ogs_gtp2_bearer_qos_t qos;
        ogs_gtp2_f_teid_t *f = NULL;
        mme_s10_reloc_pdn_t *o = NULL;
        uint8_t ebi;
        int bearers = 0;

        if (!pdn->presence)
            continue;

        if (n >= max) {
            ogs_warn("Too many PDN connections");
            return -1;
        }
        o = &out[n];
        memset(o, 0, sizeof(*o));

        /* APN */
        if (!pdn->apn.presence || !pdn->apn.data ||
            !pdn->apn.len || pdn->apn.len > OGS_MAX_APN_LEN) {
            ogs_warn("PDN[%d]: missing or invalid APN", i);
            return -1;
        }
        ogs_fqdn_parse(o->apn, pdn->apn.data, pdn->apn.len);

        /* EBI of the default bearer: kept as is, the UE keeps it too */
        if (!pdn->linked_eps_bearer_id.presence) {
            ogs_warn("PDN[%d] APN[%s]: no Linked EPS Bearer ID", i, o->apn);
            return -1;
        }
        ebi = pdn->linked_eps_bearer_id.u8;
        if (ebi < S10_EBI_MIN || ebi > S10_EBI_MAX) {
            ogs_warn("PDN[%d] APN[%s]: EBI[%d] out of range", i, o->apn, ebi);
            return -1;
        }
        if (ebi_used & (1 << ebi)) {
            ogs_warn("PDN[%d] APN[%s]: EBI[%d] used twice", i, o->apn, ebi);
            return -1;
        }
        ebi_used |= (1 << ebi);
        o->ebi = ebi;

        /*
         * The default bearer (EBI = linked EBI) and any dedicated bearers,
         * e.g. the QCI 1 bearer of a VoLTE call in progress.
         */
        for (j = 0; j < OGS_BEARER_PER_UE; j++) {
            ogs_gtp2_tlv_bearer_context_t *b = &pdn->bearer_contexts[j];
            mme_s10_reloc_bearer_t *d = NULL;
            uint8_t bebi;

            if (!b->presence)
                continue;
            bearers++;
            if (!b->eps_bearer_id.presence) {
                ogs_warn("PDN[%d] APN[%s]: bearer without EBI", i, o->apn);
                return -1;
            }
            bebi = b->eps_bearer_id.u8;
            if (bebi == ebi) {
                bc = b;
                continue;
            }

            if (bebi < S10_EBI_MIN || bebi > S10_EBI_MAX ||
                (ebi_used & (1 << bebi))) {
                ogs_warn("PDN[%d] APN[%s]: dedicated EBI[%d] invalid or used "
                        "twice", i, o->apn, bebi);
                return -1;
            }
            if (o->num_dedicated >= MME_S10_MAX_DEDICATED) {
                ogs_warn("PDN[%d] APN[%s]: too many bearers", i, o->apn);
                return -1;
            }
            ebi_used |= (1 << bebi);

            d = &o->dedicated[o->num_dedicated];
            memset(d, 0, sizeof(*d));
            d->ebi = bebi;

            memset(&qos, 0, sizeof(qos));
            if (!b->bearer_level_qos.presence || !b->bearer_level_qos.data ||
                ogs_gtp2_parse_bearer_qos(&qos, &b->bearer_level_qos) <= 0) {
                ogs_warn("PDN[%d] APN[%s]: EBI[%d] without Bearer Level QoS",
                        i, o->apn, bebi);
                return -1;
            }
            d->qos.index = qos.qci;
            d->qos.arp.priority_level = qos.priority_level;
            d->qos.arp.pre_emption_capability = qos.pre_emption_capability;
            d->qos.arp.pre_emption_vulnerability =
                qos.pre_emption_vulnerability;
            d->qos.mbr.uplink = qos.ul_mbr;
            d->qos.mbr.downlink = qos.dl_mbr;
            d->qos.gbr.uplink = qos.ul_gbr;
            d->qos.gbr.downlink = qos.dl_gbr;

            /* A GBR bearer needs all four rates for the Handover Request */
            if ((d->qos.mbr.uplink || d->qos.mbr.downlink ||
                 d->qos.gbr.uplink || d->qos.gbr.downlink) &&
                (!d->qos.mbr.uplink || !d->qos.mbr.downlink ||
                 !d->qos.gbr.uplink || !d->qos.gbr.downlink ||
                 d->qos.mbr.uplink > OGS_MAX_BITRATE_S1AP ||
                 d->qos.mbr.downlink > OGS_MAX_BITRATE_S1AP ||
                 d->qos.gbr.uplink > OGS_MAX_BITRATE_S1AP ||
                 d->qos.gbr.downlink > OGS_MAX_BITRATE_S1AP)) {
                ogs_warn("PDN[%d] APN[%s]: EBI[%d] QCI[%d] incomplete "
                        "MBR/GBR", i, o->apn, bebi, qos.qci);
                return -1;
            }

            if (b->s1_u_enodeb_f_teid.presence && b->s1_u_enodeb_f_teid.data) {
                f = b->s1_u_enodeb_f_teid.data;
                d->sgw_s1u_teid = be32toh(f->teid);
                d->have_sgw_s1u =
                    (ogs_gtp2_f_teid_to_ip(f, &d->sgw_s1u_ip) == OGS_OK);
            }
            if (b->s4_u_sgsn_f_teid.presence && b->s4_u_sgsn_f_teid.data) {
                f = b->s4_u_sgsn_f_teid.data;
                d->pgw_s5u_teid = be32toh(f->teid);
                d->have_pgw_s5u =
                    (ogs_gtp2_f_teid_to_ip(f, &d->pgw_s5u_ip) == OGS_OK);
            }
            if (!d->have_pgw_s5u) {
                ogs_warn("PDN[%d] APN[%s]: EBI[%d] without PGW S5/S8-U F-TEID",
                        i, o->apn, bebi);
                return -1;
            }
            if (b->tft.presence && b->tft.data && b->tft.len > 0 &&
                b->tft.len <= OGS_GTP2_MAX_TRAFFIC_FLOW_TEMPLATE) {
                memcpy(d->tft, b->tft.data, b->tft.len);
                d->tft_len = b->tft.len;
            }

            o->num_dedicated++;
        }
        if (!bc) {
            ogs_warn("PDN[%d] APN[%s]: no default bearer (EBI[%d]) among "
                    "bearers[%d]", i, o->apn, ebi, bearers);
            return -1;
        }

        /* UE IPv4 address: kept as is, the UE keeps it too */
        if (!pdn->ipv4_address.presence || !pdn->ipv4_address.data ||
            pdn->ipv4_address.len != OGS_IPV4_LEN) {
            ogs_warn("PDN[%d] APN[%s]: no UE IPv4 address in the request "
                    "(IPv6-only sessions are not supported yet)", i, o->apn);
            return -1;
        }
        memcpy(&o->ue_ipv4, pdn->ipv4_address.data, OGS_IPV4_LEN);

        /* Bearer QoS */
        memset(&qos, 0, sizeof(qos));
        if (!bc->bearer_level_qos.presence || !bc->bearer_level_qos.data ||
            ogs_gtp2_parse_bearer_qos(&qos, &bc->bearer_level_qos) <= 0) {
            ogs_warn("PDN[%d] APN[%s]: no Bearer Level QoS", i, o->apn);
            return -1;
        }
        o->qci = qos.qci;
        o->arp = qos.priority_level;
        o->pre_emption_capability = qos.pre_emption_capability;
        o->pre_emption_vulnerability = qos.pre_emption_vulnerability;

        /* APN-AMBR (kbps) */
        if (pdn->aggregate_maximum_bit_rate.presence &&
            pdn->aggregate_maximum_bit_rate.data &&
            pdn->aggregate_maximum_bit_rate.len >= sizeof(ogs_gtp2_ambr_t)) {
            ogs_gtp2_ambr_t *a = pdn->aggregate_maximum_bit_rate.data;
            o->ambr_ul_kbps = be32toh(a->uplink);
            o->ambr_dl_kbps = be32toh(a->downlink);
        }

        /* Identifiers on the source side: for the map only */
        if (pdn->pgw_s5_s8_ip_address_for_control_plane_or_pmip.presence &&
            pdn->pgw_s5_s8_ip_address_for_control_plane_or_pmip.data) {
            f = pdn->pgw_s5_s8_ip_address_for_control_plane_or_pmip.data;
            o->pgw_s5c_teid = be32toh(f->teid);
            o->have_pgw_s5c = (ogs_gtp2_f_teid_to_ip(f, &o->pgw_s5c_ip) == OGS_OK);
        }
        if (bc->s1_u_enodeb_f_teid.presence && bc->s1_u_enodeb_f_teid.data) {
            f = bc->s1_u_enodeb_f_teid.data;
            o->sgw_s1u_teid = be32toh(f->teid);
            o->have_sgw_s1u = (ogs_gtp2_f_teid_to_ip(f, &o->sgw_s1u_ip) == OGS_OK);
        }
        if (bc->s4_u_sgsn_f_teid.presence && bc->s4_u_sgsn_f_teid.data) {
            f = bc->s4_u_sgsn_f_teid.data;
            o->pgw_s5u_teid = be32toh(f->teid);
            o->have_pgw_s5u = (ogs_gtp2_f_teid_to_ip(f, &o->pgw_s5u_ip) == OGS_OK);
        }

        n++;
    }

    return n;
}

/*
 * ---------------------------------------------------------------------
 * Target MME side (TS 23.401 5.5.1.2.2 steps 3 to 7)
 *
 *   3  Forward Relocation Request   source MME -> this MME
 *   4  Create Session Request       this MME   -> (target) SGW, per PDN
 *   4a Create Session Response
 *   5  Handover Request             this MME   -> target eNB
 *   5a Handover Request Acknowledge
 *   7  Forward Relocation Response  this MME   -> source MME
 *
 * The Forward Relocation Request transaction is kept open between 3 and
 * 7; retransmissions from the source are absorbed by the xact layer.
 * The PGW is not touched in this phase: the target SGW-C answers the
 * Create Session Request without signalling on S5 (see sgwc), the S5
 * path is switched later by the Modify Bearer Request (step 16).
 * ---------------------------------------------------------------------
 */

static void send_forward_relocation_reject(
        ogs_gtp_xact_t *xact, uint32_t teid, uint8_t cause_value)
{
    int rv;
    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(xact);

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_FORWARD_RELOCATION_RESPONSE_TYPE;
    h.teid = teid;

    pkbuf = mme_s10_build_forward_relocation_response(h.type, cause_value);
    if (!pkbuf) {
        ogs_error("mme_s10_build_forward_relocation_response() failed");
        return;
    }

    rv = ogs_gtp_xact_update_tx(xact, &h, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp_xact_update_tx() failed");
        return;
    }

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);
}

/* Answer the pending Forward Relocation Request with pkbuf (consumed) */
static int reply_pending_request(mme_ue_t *mme_ue, ogs_pkbuf_t *pkbuf)
{
    int rv;
    ogs_gtp2_header_t h;
    ogs_gtp_xact_t *xact = NULL;

    ogs_assert(mme_ue);
    ogs_assert(pkbuf);

    xact = ogs_gtp_xact_find_by_id(mme_ue->s10.xact_id);
    mme_ue->s10.xact_id = OGS_INVALID_POOL_ID;
    /*
     * The remote transaction lives for the GTP holding time only; once it
     * is gone its pool id may belong to another transaction.
     */
    if (xact && (xact->org != OGS_GTP_REMOTE_ORIGINATOR ||
                xact->seq[0].type != OGS_GTP2_FORWARD_RELOCATION_REQUEST_TYPE))
        xact = NULL;
    if (!xact) {
        ogs_error("[%s] Forward Relocation Request transaction is gone",
                mme_ue->imsi_bcd);
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_FORWARD_RELOCATION_RESPONSE_TYPE;
    h.teid = mme_ue->s10.peer_teid;

    rv = ogs_gtp_xact_update_tx(xact, &h, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp_xact_update_tx() failed");
        return OGS_ERROR;
    }

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);
    return rv;
}

static void apply_mm_context(mme_ue_t *mme_ue, const mme_s10_mm_context_t *ctx)
{
    ogs_assert(mme_ue);
    ogs_assert(ctx);

    mme_ue->nas_eps.mme.ksi = ctx->ksi_asme;
    mme_ue->nas_eps.ue.ksi = ctx->ksi_asme;
    mme_ue->selected_int_algorithm = ctx->nas_int_alg;
    mme_ue->selected_enc_algorithm = ctx->nas_enc_alg;
    mme_ue->dl_count = ctx->nas_dl_count;
    mme_ue->ul_count.i32 = ctx->nas_ul_count;
    memcpy(mme_ue->kasme, ctx->kasme, sizeof(mme_ue->kasme));

    /* NAS keys are derived from KASME and the algorithms in use */
    ogs_kdf_nas_eps(OGS_KDF_NAS_INT_ALG, mme_ue->selected_int_algorithm,
            mme_ue->kasme, mme_ue->knas_int);
    ogs_kdf_nas_eps(OGS_KDF_NAS_ENC_ALG, mme_ue->selected_enc_algorithm,
            mme_ue->kasme, mme_ue->knas_enc);

    /* {NH, NCC} for the Handover Request Security Context */
    memcpy(mme_ue->nh, ctx->nh, sizeof(mme_ue->nh));
    mme_ue->nhcc = ctx->ncc;

    if (ctx->sambri) {
        mme_ue->ambr.uplink = (uint64_t)ctx->sub_ue_ambr_ul * 1000;
        mme_ue->ambr.downlink = (uint64_t)ctx->sub_ue_ambr_dl * 1000;
    } else if (ctx->uambri) {
        mme_ue->ambr.uplink = (uint64_t)ctx->used_ue_ambr_ul * 1000;
        mme_ue->ambr.downlink = (uint64_t)ctx->used_ue_ambr_dl * 1000;
    }

    memcpy(&mme_ue->ue_network_capability, &ctx->ue_network_capability,
            sizeof(mme_ue->ue_network_capability));
    memcpy(&mme_ue->ms_network_capability, &ctx->ms_network_capability,
            sizeof(mme_ue->ms_network_capability));

    if (ctx->mei_len == OGS_MAX_IMEISV_LEN) {
        memcpy(mme_ue->imeisv, ctx->mei, ctx->mei_len);
        mme_ue->imeisv_len = ctx->mei_len;
        ogs_buffer_to_bcd(mme_ue->imeisv, mme_ue->imeisv_len,
                mme_ue->imeisv_bcd);
        ogs_nas_imeisv_bcd_to_buffer(mme_ue->imeisv_bcd,
                mme_ue->masked_imeisv, &mme_ue->masked_imeisv_len);
        mme_ue->masked_imeisv[5] = 0xff;
        mme_ue->masked_imeisv[6] = 0xff;
    }

    mme_ue->security_context_available = 1;
    mme_ue->mac_failed = 0;
}

static void s1ap_cause_from_f_cause(
        S1AP_Cause_t *cause, const ogs_gtp2_f_cause_t *f_cause)
{
    memset(cause, 0, sizeof(*cause));
    switch (f_cause->cause_type) {
    case OGS_GTP2_F_CAUSE_TYPE_RADIO_NETWORK_LAYER:
        cause->present = S1AP_Cause_PR_radioNetwork;
        cause->choice.radioNetwork = f_cause->value;
        break;
    case OGS_GTP2_F_CAUSE_TYPE_TRANSPORT_LAYER:
        cause->present = S1AP_Cause_PR_transport;
        cause->choice.transport = f_cause->value;
        break;
    case OGS_GTP2_F_CAUSE_TYPE_NAS:
        cause->present = S1AP_Cause_PR_nas;
        cause->choice.nas = f_cause->value;
        break;
    case OGS_GTP2_F_CAUSE_TYPE_PROTOCOL:
        cause->present = S1AP_Cause_PR_protocol;
        cause->choice.protocol = f_cause->value;
        break;
    default:
        cause->present = S1AP_Cause_PR_misc;
        cause->choice.misc = f_cause->value;
        break;
    }
}

/*
 * Build the target context from the decoded PDN connections. Everything
 * the UE keeps (APN, EBI, UE IP, QoS, AMBR) and the source PGW F-TEIDs
 * are taken over: the PGW stays the anchor.
 */
static int build_sessions(mme_ue_t *mme_ue, mme_s10_reloc_pdn_t *pdn, int n)
{
    int i;
    char b1[OGS_ADDRSTRLEN], b2[OGS_ADDRSTRLEN];

    for (i = 0; i < n; i++) {
        mme_s10_reloc_pdn_t *p = &pdn[i];
        ogs_session_t *session = NULL;
        mme_sess_t *sess = NULL;
        mme_bearer_t *bearer = NULL;

        if (!p->have_pgw_s5c || !p->have_pgw_s5u) {
            ogs_error("APN[%s]: no PGW S5/S8 F-TEID in the request", p->apn);
            return OGS_ERROR;
        }

        session = mme_session_add_allow_duplicate_apn(
                mme_ue, p->apn, OGS_PDU_SESSION_TYPE_IPV4);
        if (!session) {
            ogs_error("Could not add session for APN[%s]", p->apn);
            return OGS_ERROR;
        }
        session->session_type = OGS_PDU_SESSION_TYPE_IPV4;
        session->ue_ip.ipv4 = true;
        session->ue_ip.addr = p->ue_ipv4;
        session->ue_ip.len = OGS_IPV4_LEN;
        session->qos.index = p->qci;
        session->qos.arp.priority_level = p->arp;
        session->qos.arp.pre_emption_capability = p->pre_emption_capability;
        session->qos.arp.pre_emption_vulnerability =
            p->pre_emption_vulnerability;
        session->ambr.uplink = (uint64_t)p->ambr_ul_kbps * 1000;
        session->ambr.downlink = (uint64_t)p->ambr_dl_kbps * 1000;
        /* PGW-C of the source side: mme_s11_build_create_session_request()
         * puts smf_ip + sess->pgw_s5c_teid into the PGW S5/S8 F-TEID */
        session->smf_ip = p->pgw_s5c_ip;

        /* mme_sess_add() needs a non-zero PTI; none is in progress */
        sess = mme_sess_add(mme_ue, (uint8_t)(i + 1));
        if (!sess) {
            ogs_error("mme_sess_add() failed");
            return OGS_ERROR;
        }
        sess->session = session;
        sess->ue_request_type.type = OGS_PDU_SESSION_TYPE_IPV4;
        sess->pgw_s5c_teid = p->pgw_s5c_teid;
        sess->pgw_s5c_ip = p->pgw_s5c_ip;

        sess->src.relocated = true;
        sess->src.pgw_s5c_ip = p->pgw_s5c_ip;
        sess->src.pgw_s5c_teid = p->pgw_s5c_teid;

        bearer = mme_default_bearer_in_sess(sess);
        ogs_assert(bearer);

        /* The UE keeps its EBI: give back the one just allocated */
        if (bearer->ebi != p->ebi) {
            mme_ebi_free(mme_ue, bearer->ebi);
            if (mme_ebi_reserve(mme_ue, p->ebi) != OGS_OK) {
                ogs_error("APN[%s]: EBI[%d] cannot be reserved",
                        p->apn, p->ebi);
                return OGS_ERROR;
            }
            bearer->ebi = p->ebi;
        }

        bearer->qos = session->qos;
        bearer->pgw_s5u_teid = p->pgw_s5u_teid;
        bearer->pgw_s5u_ip = p->pgw_s5u_ip;

        bearer->src.ebi = p->ebi;
        bearer->src.sgw_s1u_teid = p->sgw_s1u_teid;
        bearer->src.sgw_s1u_ip = p->sgw_s1u_ip;
        bearer->src.pgw_s5u_teid = p->pgw_s5u_teid;
        bearer->src.pgw_s5u_ip = p->pgw_s5u_ip;

        /* An established bearer: s1ap_build_handover_request() skips
         * bearers that are not active */
        OGS_FSM_TRAN(&bearer->sm, esm_state_active);

        /* Dedicated bearers of this PDN connection (e.g. QCI 1 voice) */
        {
            int k;
            for (k = 0; k < p->num_dedicated; k++) {
                mme_s10_reloc_bearer_t *d = &p->dedicated[k];
                mme_bearer_t *ded = mme_bearer_add(sess);

                if (!ded) {
                    ogs_error("APN[%s]: mme_bearer_add() failed", p->apn);
                    return OGS_ERROR;
                }
                if (ded->ebi != d->ebi) {
                    mme_ebi_free(mme_ue, ded->ebi);
                    if (mme_ebi_reserve(mme_ue, d->ebi) != OGS_OK) {
                        ogs_error("APN[%s]: EBI[%d] cannot be reserved",
                                p->apn, d->ebi);
                        return OGS_ERROR;
                    }
                    ded->ebi = d->ebi;
                }
                ded->qos = d->qos;
                ded->pgw_s5u_teid = d->pgw_s5u_teid;
                ded->pgw_s5u_ip = d->pgw_s5u_ip;
                ded->src.ebi = d->ebi;
                ded->src.sgw_s1u_teid = d->sgw_s1u_teid;
                ded->src.sgw_s1u_ip = d->sgw_s1u_ip;
                ded->src.pgw_s5u_teid = d->pgw_s5u_teid;
                ded->src.pgw_s5u_ip = d->pgw_s5u_ip;
                if (d->tft_len) {
                    /* freed with the bearer (OGS_TLV_CLEAR_DATA) */
                    ded->tft.data = ogs_memdup(d->tft, d->tft_len);
                    ogs_assert(ded->tft.data);
                    ded->tft.len = d->tft_len;
                }
                OGS_FSM_TRAN(&ded->sm, esm_state_active);

                ogs_info("    dedicated bearer EBI[%d] QCI[%d] ARP[%d] "
                        "MBR[%lld/%lld] GBR[%lld/%lld] TFT[%d octets]",
                        ded->ebi, ded->qos.index,
                        ded->qos.arp.priority_level,
                        (long long)ded->qos.mbr.uplink,
                        (long long)ded->qos.mbr.downlink,
                        (long long)ded->qos.gbr.uplink,
                        (long long)ded->qos.gbr.downlink, d->tft_len);
            }
        }

        ogs_info("  session APN[%s] EBI[%d] UE-IPv4 kept, PGW-C[%s teid "
                "0x%x] PGW-U[%s teid 0x%x]", session->name, bearer->ebi,
                ip_to_str(&p->pgw_s5c_ip, b1, sizeof(b1)), p->pgw_s5c_teid,
                ip_to_str(&p->pgw_s5u_ip, b2, sizeof(b2)), p->pgw_s5u_teid);
    }

    return OGS_OK;
}

/*
 * Step 4 is run one PDN connection at a time. Only the first Create
 * Session Request may carry TEID 0 in its header: the SGW-C treats every
 * TEID-0 request for a known IMSI as a fresh UE and removes the context
 * it already has (TS 29.274 7.2.1), so a second parallel request would
 * wipe out the first. The next request goes out once the SGW S11 TEID is
 * known from the previous response.
 *
 * Returns true if a request was sent, false if none is left or sending
 * failed (mme_ue->s10.state tells which).
 */
static bool send_next_create_session(enb_ue_t *target_ue, mme_ue_t *mme_ue)
{
    mme_sess_t *sess = NULL;

    ogs_list_for_each(&mme_ue->sess_list, sess) {
        mme_bearer_t *bearer = mme_default_bearer_in_sess(sess);
        if (!bearer || bearer->sgw_s1u_teid)
            continue;               /* already created on the target SGW */

        if (mme_gtp_send_create_session_request(target_ue, sess,
                    OGS_GTP_CREATE_IN_S10_HANDOVER) != OGS_OK) {
            ogs_error("[%s] Create Session Request for APN[%s] failed",
                    mme_ue->imsi_bcd,
                    sess->session ? sess->session->name : "?");
            return false;
        }
        return true;
    }
    return false;
}

void mme_s10_handle_forward_relocation_request(
        ogs_gtp_xact_t *xact, ogs_gtp2_forward_relocation_request_t *req)
{
    int n, r;
    char buf[OGS_ADDRSTRLEN];
    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1] = "";
    uint32_t teid = 0;
    ogs_ip_t peer_ip;
    bool have_peer = false;
    uint8_t cause_value = OGS_GTP2_CAUSE_RELOCATION_FAILURE;
    const char *reason = NULL;

    ogs_gtp2_target_identification_t target;
    ogs_gtp2_f_container_t container;
    ogs_gtp2_f_cause_t f_cause;
    mme_s10_mm_context_t mm_ctx;
    mme_s10_reloc_pdn_t pdn[OGS_MAX_NUM_OF_SESS];

    mme_enb_t *target_enb = NULL;
    enb_ue_t *target_ue = NULL;
    mme_ue_t *mme_ue = NULL, *old_mme_ue = NULL;

    ogs_assert(xact);
    ogs_assert(req);

    ogs_debug("Forward Relocation Request");

    memset(&peer_ip, 0, sizeof(peer_ip));
    memset(&target, 0, sizeof(target));

    if (req->imsi.presence && req->imsi.data && req->imsi.len)
        ogs_buffer_to_bcd(req->imsi.data, req->imsi.len, imsi_bcd);

    /* The response header carries the TEID the source MME gave us */
    if (req->sender_s_f_teid_for_control_plane.presence &&
        req->sender_s_f_teid_for_control_plane.data &&
        req->sender_s_f_teid_for_control_plane.len >=
            OGS_GTP2_F_TEID_HDR_LEN) {
        ogs_gtp2_f_teid_t *f = req->sender_s_f_teid_for_control_plane.data;
        teid = be32toh(f->teid);
        have_peer = (ogs_gtp2_f_teid_to_ip(f, &peer_ip) == OGS_OK);
    }

    ogs_info("S10 Forward Relocation Request from peer MME[%s]: IMSI[%s]",
            OGS_ADDR(&xact->gnode->addr, buf), imsi_bcd);
    mme_s10_log_pdn_connections(req);

    if (!imsi_bcd[0]) {
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
        reason = "no IMSI";
        goto reject;
    }
    if (!have_peer) {
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
        reason = "no Sender F-TEID for Control Plane";
        goto reject;
    }

    /* Target Identification -> target eNB */
    if (!req->target_identification.presence ||
        !req->target_identification.data ||
        ogs_gtp2_parse_target_identification(
            &target, &req->target_identification) <= 0) {
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
        reason = "no usable Target Identification";
        goto reject;
    }
    target_enb = mme_enb_find_by_enb_id(target.enodeb_id);
    if (!target_enb) {
        reason = "target eNB is not connected to this MME";
        goto reject;
    }

    /* MM Context: security context, UE-AMBR, UE capabilities */
    if (!req->mme_sgsn_amf_ue_mm_context.presence ||
        !req->mme_sgsn_amf_ue_mm_context.data ||
        !req->mme_sgsn_amf_ue_mm_context.len) {
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
        reason = "no MM Context";
        goto reject;
    }
    if (mme_s10_decode_mm_context(&mm_ctx,
                req->mme_sgsn_amf_ue_mm_context.data,
                req->mme_sgsn_amf_ue_mm_context.len) < 0) {
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
        reason = "MM Context is not an EPS security context";
        goto reject;
    }
    if (!mm_ctx.nhi) {
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
        reason = "MM Context carries no {NH, NCC}";
        goto reject;
    }

    /* E-UTRAN Transparent Container (Source to Target) */
    memset(&container, 0, sizeof(container));
    if (!req->e_utran_transparent_container.presence ||
        ogs_gtp2_parse_f_container(&container,
            &req->e_utran_transparent_container) <= 0 ||
        container.container_type !=
            OGS_GTP2_F_CONTAINER_TYPE_E_UTRAN_TRANSPARENT_CONTAINER ||
        !container.data || !container.len) {
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
        reason = "no E-UTRAN Transparent Container";
        goto reject;
    }

    /* S1-AP Cause, default: handover desirable for radio reasons */
    memset(&f_cause, 0, sizeof(f_cause));
    f_cause.cause_type = OGS_GTP2_F_CAUSE_TYPE_RADIO_NETWORK_LAYER;
    f_cause.value =
        S1AP_CauseRadioNetwork_handover_desirable_for_radio_reason;
    if (req->s1_ap_cause.presence && req->s1_ap_cause.data &&
        ogs_gtp2_parse_f_cause(&f_cause, &req->s1_ap_cause) <= 0)
        ogs_warn("Invalid S1-AP Cause, using the default");

    n = mme_s10_parse_relocation_pdns(req, pdn, OGS_MAX_NUM_OF_SESS);
    if (n <= 0) {
        reason = "no usable PDN Connections";
        goto reject;
    }

    /*
     * A context for the IMSI on this MME is stale: the UE is attached
     * at the source MME. Detach it and refuse this attempt; the source
     * eNB retries the handover and the next attempt finds a clean MME.
     */
    old_mme_ue = mme_ue_find_by_imsi_bcd(imsi_bcd);
    if (old_mme_ue) {
        if (MME_S10_IS_TARGET(old_mme_ue)) {
            reason = "a relocation for this IMSI is already in progress";
            goto reject;
        }
        if (MME_S10_IS_SOURCE(old_mme_ue)) {
            /*
             * This MME relocated the UE away and never got the Forward
             * Relocation Complete Notification. The UE is at the peer now:
             * finish the source side (sessions removed on the SGW only,
             * the PGW session is in use) instead of a detach.
             */
            enb_ue_t *old_enb_ue = enb_ue_find_by_id(old_mme_ue->enb_ue_id);

            if (old_mme_ue->s10.state != MME_S10_SRC_COMPLETING) {
                ogs_warn("[%s] Earlier relocation to the peer not "
                        "completed: releasing the source side", imsi_bcd);
                old_mme_ue->s10.state = MME_S10_SRC_COMPLETING;
                if (old_enb_ue) {
                    r = s1ap_send_ue_context_release_command(old_enb_ue,
                            S1AP_Cause_PR_radioNetwork,
                            S1AP_CauseRadioNetwork_successful_handover,
                            S1AP_UE_CTX_REL_S1_REMOVE_AND_UNLINK, 0);
                    ogs_expect(r == OGS_OK);
                } else {
                    mme_s10_source_release_sessions(old_mme_ue);
                }
            }
            reason = "the source side of an earlier relocation is being "
                "released";
            goto reject;
        }
        if (OGS_FSM_CHECK(&old_mme_ue->sm, emm_state_registered) &&
            mme_sess_count(old_mme_ue) > 0) {
            ogs_warn("[%s] Stale context on this MME: implicit detach",
                    imsi_bcd);
            mme_timer_implicit_detach_expire(
                    OGS_UINT_TO_POINTER(old_mme_ue->id));
        } else if (mme_sess_count(old_mme_ue) == 0) {
            /*
             * Already detached (no session left), but the context is still
             * held, typically by an S1 context the UE left behind (e.g. the
             * source side of an earlier relocation). Remove it now rather
             * than waiting for an implicit S1 release.
             */
            enb_ue_t *old_enb_ue = enb_ue_find_by_id(old_mme_ue->enb_ue_id);

            ogs_warn("[%s] Stale context without sessions: removed", imsi_bcd);
            if (old_enb_ue) {
                r = s1ap_send_ue_context_release_command(old_enb_ue,
                        S1AP_Cause_PR_nas, S1AP_CauseNas_normal_release,
                        S1AP_UE_CTX_REL_UE_CONTEXT_REMOVE, 0);
                ogs_expect(r == OGS_OK);
            } else {
                mme_ue_remove(old_mme_ue);
            }
        }
        reason = "a stale context for this IMSI exists (being detached)";
        goto reject;
    }

    /* The UE gets an S1 context on the target eNB, as in an S1 handover */
    target_ue = enb_ue_add(target_enb, INVALID_UE_S1AP_ID);
    if (!target_ue) {
        cause_value = OGS_GTP2_CAUSE_NO_RESOURCES_AVAILABLE;
        reason = "enb_ue_add() failed";
        goto reject;
    }
    mme_ue = mme_ue_add(target_ue);
    if (!mme_ue) {
        enb_ue_remove(target_ue);
        cause_value = OGS_GTP2_CAUSE_NO_RESOURCES_AVAILABLE;
        reason = "mme_ue_add() failed";
        goto reject;
    }
    enb_ue_associate_mme_ue(target_ue, mme_ue);
    mme_ue_set_imsi(mme_ue, imsi_bcd);

    apply_mm_context(mme_ue, &mm_ctx);

    /* Location: target TAI; the cell is learnt from Handover Notify */
    ogs_nas_to_plmn_id(&mme_ue->tai.plmn_id, &target.nas_plmn_id);
    mme_ue->tai.tac = target.tac;
    memcpy(&mme_ue->e_cgi.plmn_id, &mme_ue->tai.plmn_id,
            sizeof(mme_ue->e_cgi.plmn_id));
    mme_ue->e_cgi.cell_id = target.enodeb_id << 8;

    if (build_sessions(mme_ue, pdn, n) != OGS_OK) {
        mme_ue_remove(mme_ue);
        enb_ue_remove(target_ue);
        reason = "could not build the sessions";
        goto reject;
    }

    mme_ue->s10.state = MME_S10_TGT_CREATING;
    mme_ue->s10.gnode = xact->gnode;
    mme_ue->s10.xact_id = xact->id;
    mme_ue->s10.peer_teid = teid;
    mme_ue->s10.peer_ip = peer_ip;
    mme_ue->s10.target_enb_id = target.enodeb_id;
    mme_ue->s10.s1ap_cause = f_cause;
    /*
     * Direct Forwarding Indication (TS 29.274 8.12): set by the source MME
     * when the source eNB reported a direct forwarding path. Without it,
     * data forwarding goes through the SGWs (indirect, steps 6 and 8).
     */
    mme_ue->s10.direct_forwarding = false;
    if (req->indication_flags.presence && req->indication_flags.data &&
        req->indication_flags.len >= 1) {
        ogs_gtp2_indication_t *indication = req->indication_flags.data;
        mme_ue->s10.direct_forwarding =
            indication->direct_forwarding_indication;
    }
    OGS_ASN_CLEAR_DATA(&mme_ue->s10.container);
    ogs_s1ap_buffer_to_OCTET_STRING(
            container.data, container.len, &mme_ue->s10.container);

    ogs_info("[%s] S10 relocation accepted for preparation: target "
            "eNB-id[0x%x] TAC[%d], %d session(s) -> Create Session Request",
            imsi_bcd, target.enodeb_id, target.tac, n);

    /* Step 4: Create Session Requests, one PDN connection at a time */
    if (!send_next_create_session(target_ue, mme_ue))
        mme_s10_target_fail(mme_ue, OGS_GTP2_CAUSE_SYSTEM_FAILURE,
                "Create Session Request could not be sent");
    return;

reject:
    ogs_warn("[%s] S10 Forward Relocation Request rejected: %s [cause:%d]",
            imsi_bcd, reason ? reason : "-", cause_value);
    send_forward_relocation_reject(xact, teid, cause_value);
}

/* Step 4a for one PDN: next Create Session Request, or step 5 */
void mme_s10_target_session_created(enb_ue_t *target_ue, mme_ue_t *mme_ue)
{
    mme_sess_t *sess = NULL;

    ogs_assert(mme_ue);

    if (mme_ue->s10.state != MME_S10_TGT_CREATING) {
        ogs_warn("[%s] Create Session Response in S10 state[%d]: ignored",
                mme_ue->imsi_bcd, mme_ue->s10.state);
        return;
    }
    if (!target_ue) {
        mme_s10_target_fail(mme_ue, OGS_GTP2_CAUSE_SYSTEM_FAILURE,
                "target S1 context is gone");
        return;
    }

    ogs_list_for_each(&mme_ue->sess_list, sess) {
        mme_bearer_t *bearer = mme_default_bearer_in_sess(sess);
        if (bearer && !bearer->sgw_s1u_teid) {
            if (!send_next_create_session(target_ue, mme_ue))
                mme_s10_target_fail(mme_ue, OGS_GTP2_CAUSE_SYSTEM_FAILURE,
                        "Create Session Request could not be sent");
            return;
        }
    }

    mme_s10_target_sessions_created(target_ue, mme_ue);
}

/* Step 4a done for every PDN: step 5, Handover Request to the target eNB */
void mme_s10_target_sessions_created(enb_ue_t *target_ue, mme_ue_t *mme_ue)
{
    int r;
    ogs_pkbuf_t *s1apbuf = NULL;
    S1AP_HandoverType_t handover_type = S1AP_HandoverType_intralte;
    S1AP_Cause_t cause;

    ogs_assert(mme_ue);

    if (mme_ue->s10.state != MME_S10_TGT_CREATING) {
        ogs_warn("[%s] Create Session Response in S10 state[%d]: ignored",
                mme_ue->imsi_bcd, mme_ue->s10.state);
        return;
    }
    if (!target_ue) {
        mme_s10_target_fail(mme_ue, OGS_GTP2_CAUSE_SYSTEM_FAILURE,
                "target S1 context is gone");
        return;
    }

    s1ap_cause_from_f_cause(&cause, &mme_ue->s10.s1ap_cause);

    ogs_info("[%s] S10: sessions created on the target SGW, "
            "HandoverRequest to target eNB-id[0x%x]",
            mme_ue->imsi_bcd, mme_ue->s10.target_enb_id);
    ogs_info("    Target : ENB_UE_S1AP_ID[Unknown] MME_UE_S1AP_ID[%d]",
            target_ue->mme_ue_s1ap_id);

    target_ue->handover_type = handover_type;
    s1apbuf = s1ap_build_handover_request(target_ue,
            &handover_type, &cause, &mme_ue->s10.container);
    if (!s1apbuf) {
        mme_s10_target_fail(mme_ue, OGS_GTP2_CAUSE_SYSTEM_FAILURE,
                "s1ap_build_handover_request() failed");
        return;
    }

    mme_ue->s10.state = MME_S10_TGT_HO_REQUEST;

    r = s1ap_send_to_enb_ue(target_ue, s1apbuf);
    if (r != OGS_OK) {
        mme_s10_target_fail(mme_ue, OGS_GTP2_CAUSE_SYSTEM_FAILURE,
                "Handover Request could not be sent");
        return;
    }
}

/* Step 7: positive Forward Relocation Response to the source MME */
static void send_forward_relocation_accept(mme_ue_t *mme_ue)
{
    ogs_pkbuf_t *pkbuf = NULL;

    pkbuf = mme_s10_build_forward_relocation_response_accept(
            OGS_GTP2_FORWARD_RELOCATION_RESPONSE_TYPE, mme_ue);
    if (!pkbuf) {
        mme_s10_target_fail(mme_ue, OGS_GTP2_CAUSE_SYSTEM_FAILURE,
                "mme_s10_build_forward_relocation_response_accept() failed");
        return;
    }

    if (reply_pending_request(mme_ue, pkbuf) != OGS_OK) {
        /* The source cannot be told any more: drop the preparation */
        mme_s10_target_fail(mme_ue, OGS_GTP2_CAUSE_SYSTEM_FAILURE,
                "Forward Relocation Response could not be sent");
        return;
    }

    mme_ue->s10.state = MME_S10_TGT_PREPARED;
    ogs_info("[%s] S10 relocation prepared: Forward Relocation Response "
            "(accepted, %s forwarding) sent", mme_ue->imsi_bcd,
            mme_ue->s10.direct_forwarding ? "direct" :
            mme_ue_have_indirect_tunnel(mme_ue) ? "indirect" : "no");
}

/* Step 5a: the target eNB admitted the UE -> step 6 or 7 */
bool mme_s10_handle_handover_request_ack(
        enb_ue_t *target_ue, uint32_t enb_ue_s1ap_id,
        S1AP_E_RABAdmittedList_t *E_RABAdmittedList,
        S1AP_Target_ToSource_TransparentContainer_t *container)
{
    int i, admitted = 0;
    mme_ue_t *mme_ue = NULL;

    ogs_assert(target_ue);

    mme_ue = mme_ue_find_by_id(target_ue->mme_ue_id);
    if (!MME_S10_IS_TARGET(mme_ue))
        return false;

    if (mme_ue->s10.state != MME_S10_TGT_HO_REQUEST) {
        ogs_warn("[%s] HandoverRequestAcknowledge in S10 state[%d]: ignored",
                mme_ue->imsi_bcd, mme_ue->s10.state);
        return true;
    }

    /* The target eNB's S1AP id for this UE */
    target_ue->enb_ue_s1ap_id = enb_ue_s1ap_id;

    if (!E_RABAdmittedList || !container || !container->buf) {
        mme_s10_target_fail(mme_ue, OGS_GTP2_CAUSE_RELOCATION_FAILURE,
                "HandoverRequestAcknowledge without E-RABs or container");
        return true;
    }

    for (i = 0; i < E_RABAdmittedList->list.count; i++) {
        S1AP_E_RABAdmittedItemIEs_t *item = (S1AP_E_RABAdmittedItemIEs_t *)
            E_RABAdmittedList->list.array[i];
        S1AP_E_RABAdmittedItem_t *e_rab = NULL;
        mme_bearer_t *bearer = NULL;

        if (!item)
            continue;
        e_rab = &item->value.choice.E_RABAdmittedItem;

        bearer = mme_bearer_find_by_ue_ebi(mme_ue, e_rab->e_RAB_ID);
        if (!bearer) {
            ogs_warn("[%s] Unknown E-RAB-ID[%d] admitted",
                    mme_ue->imsi_bcd, (int)e_rab->e_RAB_ID);
            continue;
        }
        if (e_rab->gTP_TEID.size != sizeof(bearer->enb_s1u_teid)) {
            ogs_warn("[%s] E-RAB-ID[%d]: invalid GTP-TEID size",
                    mme_ue->imsi_bcd, (int)e_rab->e_RAB_ID);
            continue;
        }
        /* Target eNB S1-U F-TEID: used by the Modify Bearer Request
         * towards the target SGW after Handover Notify (step 16) */
        memcpy(&bearer->enb_s1u_teid, e_rab->gTP_TEID.buf,
                sizeof(bearer->enb_s1u_teid));
        bearer->enb_s1u_teid = be32toh(bearer->enb_s1u_teid);
        if (ogs_asn_BIT_STRING_to_ip(&e_rab->transportLayerAddress,
                    &bearer->enb_s1u_ip) != OGS_OK) {
            ogs_warn("[%s] E-RAB-ID[%d]: invalid transport address",
                    mme_ue->imsi_bcd, (int)e_rab->e_RAB_ID);
            bearer->enb_s1u_teid = 0;
            continue;
        }
        admitted++;

        /* Target eNB F-TEIDs for DL/UL data forwarding, if it offers any */
        CLEAR_INDIRECT_TUNNEL(bearer);
        if (e_rab->dL_transportLayerAddress && e_rab->dL_gTP_TEID &&
            e_rab->dL_gTP_TEID->size == sizeof(bearer->enb_dl_teid)) {
            memcpy(&bearer->enb_dl_teid, e_rab->dL_gTP_TEID->buf,
                    sizeof(bearer->enb_dl_teid));
            bearer->enb_dl_teid = be32toh(bearer->enb_dl_teid);
            if (ogs_asn_BIT_STRING_to_ip(e_rab->dL_transportLayerAddress,
                        &bearer->enb_dl_ip) != OGS_OK)
                bearer->enb_dl_teid = 0;
        }
        if (e_rab->uL_TransportLayerAddress && e_rab->uL_GTP_TEID &&
            e_rab->uL_GTP_TEID->size == sizeof(bearer->enb_ul_teid)) {
            memcpy(&bearer->enb_ul_teid, e_rab->uL_GTP_TEID->buf,
                    sizeof(bearer->enb_ul_teid));
            bearer->enb_ul_teid = be32toh(bearer->enb_ul_teid);
            if (ogs_asn_BIT_STRING_to_ip(e_rab->uL_TransportLayerAddress,
                        &bearer->enb_ul_ip) != OGS_OK)
                bearer->enb_ul_teid = 0;
        }

        ogs_info("    admitted EBI[%d] ENB-S1U-TEID[0x%x] "
                "DL-FWD-TEID[0x%x] UL-FWD-TEID[0x%x]",
                bearer->ebi, bearer->enb_s1u_teid,
                bearer->enb_dl_teid, bearer->enb_ul_teid);
    }

    if (!admitted) {
        mme_s10_target_fail(mme_ue, OGS_GTP2_CAUSE_RELOCATION_FAILURE,
                "target eNB admitted no E-RAB");
        return true;
    }

    OGS_ASN_STORE_DATA(&mme_ue->container, container);

    ogs_info("[%s] S10: %d E-RAB(s) admitted by the target eNB",
            mme_ue->imsi_bcd, admitted);

    /*
     * Step 6 (TS 23.401 5.5.1.2.2): with indirect forwarding and a
     * relocated SGW, the target SGW gets tunnels towards the target eNB's
     * forwarding F-TEIDs. Its own F-TEIDs for those tunnels go to the
     * source MME in the Forward Relocation Response (step 7).
     */
    if (!mme_ue->s10.direct_forwarding &&
        mme_ue_have_indirect_tunnel(mme_ue) == true) {
        mme_ue->s10.state = MME_S10_TGT_FORWARDING;
        ogs_info("[%s] S10: Create Indirect Data Forwarding Tunnel Request "
                "to the target SGW", mme_ue->imsi_bcd);
        if (mme_gtp_send_create_indirect_data_forwarding_tunnel_request(
                    target_ue, mme_ue) != OGS_OK)
            mme_s10_target_fail(mme_ue, OGS_GTP2_CAUSE_SYSTEM_FAILURE,
                    "Create Indirect Data Forwarding Tunnel Request "
                    "could not be sent");
        return true;
    }

    send_forward_relocation_accept(mme_ue);
    return true;
}

/*
 * Step 6a: the target SGW created the indirect forwarding tunnels.
 * The SGW F-TEIDs are stored per bearer (sgw_dl/ul), then step 7.
 */
void mme_s10_handle_create_indirect_data_forwarding_tunnel_response(
        mme_ue_t *mme_ue, mme_ue_t *mme_ue_from_teid,
        ogs_gtp2_create_indirect_data_forwarding_tunnel_response_t *rsp)
{
    int i, n = 0;
    uint8_t cause_value = OGS_GTP2_CAUSE_UNDEFINED_VALUE;
    mme_bearer_t *bearer = NULL;
    ogs_gtp2_f_teid_t *teid = NULL;
    char buf1[OGS_ADDRSTRLEN], buf2[OGS_ADDRSTRLEN];

    ogs_assert(mme_ue);
    ogs_assert(rsp);

    if (mme_ue->s10.state != MME_S10_TGT_FORWARDING) {
        ogs_warn("[%s] Create Indirect Data Forwarding Tunnel Response in "
                "S10 state[%d]: ignored", mme_ue->imsi_bcd, mme_ue->s10.state);
        return;
    }

    if (rsp->cause.presence && rsp->cause.data) {
        ogs_gtp2_cause_t *cause = rsp->cause.data;
        cause_value = cause->value;
    }
    if (!mme_ue_from_teid ||
        cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        ogs_error("[%s] Create Indirect Data Forwarding Tunnel Response: "
                "cause[%d]%s", mme_ue->imsi_bcd, cause_value,
                mme_ue_from_teid ? "" : " (no context in TEID)");
        mme_s10_target_fail(mme_ue, OGS_GTP2_CAUSE_RELOCATION_FAILURE,
                "indirect forwarding tunnels not created on the target SGW");
        return;
    }

    for (i = 0; i < OGS_BEARER_PER_UE && rsp->bearer_contexts[i].presence;
            i++) {
        if (!rsp->bearer_contexts[i].eps_bearer_id.presence) {
            ogs_error("[%s] Bearer Context without EBI", mme_ue->imsi_bcd);
            continue;
        }
        bearer = mme_bearer_find_by_ue_ebi(mme_ue,
                rsp->bearer_contexts[i].eps_bearer_id.u8);
        if (!bearer) {
            ogs_error("[%s] Unknown EBI[%d]", mme_ue->imsi_bcd,
                    rsp->bearer_contexts[i].eps_bearer_id.u8);
            continue;
        }
        /* Same IE instances as the intra-MME path in mme-s11-handler.c */
        if (rsp->bearer_contexts[i].s4_u_sgsn_f_teid.presence &&
            rsp->bearer_contexts[i].s4_u_sgsn_f_teid.data) {
            teid = rsp->bearer_contexts[i].s4_u_sgsn_f_teid.data;
            bearer->sgw_dl_teid = be32toh(teid->teid);
            if (ogs_gtp2_f_teid_to_ip(teid, &bearer->sgw_dl_ip) != OGS_OK)
                bearer->sgw_dl_teid = 0;
        }
        if (rsp->bearer_contexts[i].s2b_u_epdg_f_teid_5.presence &&
            rsp->bearer_contexts[i].s2b_u_epdg_f_teid_5.data) {
            teid = rsp->bearer_contexts[i].s2b_u_epdg_f_teid_5.data;
            bearer->sgw_ul_teid = be32toh(teid->teid);
            if (ogs_gtp2_f_teid_to_ip(teid, &bearer->sgw_ul_ip) != OGS_OK)
                bearer->sgw_ul_teid = 0;
        }
        if (bearer->sgw_dl_teid || bearer->sgw_ul_teid)
            n++;
        ogs_info("    EBI[%d] SGW DL-FWD[%s teid 0x%x] UL-FWD[%s teid 0x%x]",
                bearer->ebi,
                ip_to_str(&bearer->sgw_dl_ip, buf1, sizeof(buf1)),
                bearer->sgw_dl_teid,
                ip_to_str(&bearer->sgw_ul_ip, buf2, sizeof(buf2)),
                bearer->sgw_ul_teid);
    }

    if (!n) {
        mme_s10_target_fail(mme_ue, OGS_GTP2_CAUSE_RELOCATION_FAILURE,
                "target SGW returned no forwarding F-TEID");
        return;
    }

    send_forward_relocation_accept(mme_ue);
}

/* Step 5a negative: the target eNB refused the handover */
bool mme_s10_handle_handover_failure(enb_ue_t *target_ue)
{
    mme_ue_t *mme_ue = NULL;

    ogs_assert(target_ue);

    mme_ue = mme_ue_find_by_id(target_ue->mme_ue_id);
    if (!MME_S10_IS_TARGET(mme_ue))
        return false;

    mme_s10_target_fail(mme_ue, OGS_GTP2_CAUSE_RELOCATION_FAILURE,
            "HandoverFailure from the target eNB");
    return true;
}

/*
 * Steps 13 to 16 (TS 23.401 5.5.1.2.2): the UE arrived on the target eNB.
 *   14  Forward Relocation Complete Notification to the source MME
 *   15  Modify Bearer Request to the target SGW with the target eNB F-TEIDs;
 *   16  the target SGW switches the S5 path at the PGW (sgwc)
 */
bool mme_s10_handle_handover_notify(enb_ue_t *target_ue,
        S1AP_TAI_t *TAI, S1AP_EUTRAN_CGI_t *EUTRAN_CGI)
{
    int r;
    mme_ue_t *mme_ue = NULL;
    mme_sess_t *sess = NULL;
    mme_bearer_t *bearer = NULL;

    ogs_assert(target_ue);

    mme_ue = mme_ue_find_by_id(target_ue->mme_ue_id);
    if (!MME_S10_IS_TARGET(mme_ue))
        return false;

    ogs_info("[%s] S10: HandoverNotify, UE is on target eNB-id[0x%x] "
            "ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            mme_ue->imsi_bcd, mme_ue->s10.target_enb_id,
            target_ue->enb_ue_s1ap_id, target_ue->mme_ue_s1ap_id);

    if (mme_ue->s10.state != MME_S10_TGT_PREPARED) {
        ogs_warn("[%s] HandoverNotify in S10 state[%d]: ignored",
                mme_ue->imsi_bcd, mme_ue->s10.state);
        return true;
    }

    /* Location of the UE now */
    if (TAI && TAI->pLMNidentity.size == OGS_PLMN_ID_LEN &&
        TAI->tAC.size == sizeof(uint16_t)) {
        memcpy(&mme_ue->tai.plmn_id, TAI->pLMNidentity.buf, OGS_PLMN_ID_LEN);
        memcpy(&mme_ue->tai.tac, TAI->tAC.buf, sizeof(uint16_t));
        mme_ue->tai.tac = be16toh(mme_ue->tai.tac);
    }
    if (EUTRAN_CGI && EUTRAN_CGI->pLMNidentity.size == OGS_PLMN_ID_LEN &&
        EUTRAN_CGI->cell_ID.size == sizeof(uint32_t)) {
        memcpy(&mme_ue->e_cgi.plmn_id, EUTRAN_CGI->pLMNidentity.buf,
                OGS_PLMN_ID_LEN);
        memcpy(&mme_ue->e_cgi.cell_id, EUTRAN_CGI->cell_ID.buf,
                sizeof(uint32_t));
        mme_ue->e_cgi.cell_id = be32toh(mme_ue->e_cgi.cell_id) >> 4;
    }
    mme_ue->enb_ostream_id = target_ue->enb_ostream_id;
    mme_ue->ue_location_timestamp = ogs_time_now();
    ogs_info("    TAI[PLMN_ID:%06x,TAC:%d] E_CGI[CELL_ID:0x%x]",
            ogs_plmn_id_hexdump(&mme_ue->tai.plmn_id), mme_ue->tai.tac,
            mme_ue->e_cgi.cell_id);

    mme_ue->s10.state = MME_S10_TGT_NOTIFIED;

    /* Step 14: the source MME releases its side */
    r = mme_gtp_send_forward_relocation_complete_notification(
            target_ue, mme_ue);
    ogs_expect(r == OGS_OK);

    /* Step 15: Modify Bearer Request to the target SGW */
    ogs_list_init(&mme_ue->bearer_to_modify_list);
    ogs_list_for_each(&mme_ue->sess_list, sess) {
        ogs_list_for_each(&sess->bearer_list, bearer) {
            if (!bearer->enb_s1u_teid)
                continue;           /* not admitted by the target eNB */
            ogs_list_add(&mme_ue->bearer_to_modify_list,
                    &bearer->to_modify_node);
        }
    }
    if (!ogs_list_count(&mme_ue->bearer_to_modify_list)) {
        ogs_error("[%s] No bearer to modify after the handover",
                mme_ue->imsi_bcd);
        return true;
    }

    ogs_info("[%s] S10: Modify Bearer Request to the target SGW "
            "(%d bearer(s)), the PGW path follows",
            mme_ue->imsi_bcd, ogs_list_count(&mme_ue->bearer_to_modify_list));
    r = mme_gtp_send_modify_bearer_request(
            target_ue, mme_ue, 1, OGS_GTP_MODIFY_IN_S10_HANDOVER);
    ogs_expect(r == OGS_OK);

    return true;
}

/*
 * Step 16 done: the target SGW and the PGW serve the UE. The context is
 * now an ordinary one on this MME.
 */
void mme_s10_target_handover_complete(enb_ue_t *target_ue, mme_ue_t *mme_ue)
{
    int r;
    mme_sess_t *sess = NULL;

    ogs_assert(mme_ue);

    if (mme_ue->s10.state != MME_S10_TGT_NOTIFIED) {
        ogs_warn("[%s] Modify Bearer Response in S10 state[%d]",
                mme_ue->imsi_bcd, mme_ue->s10.state);
        return;
    }

    /* The PGW now points at the target SGW: deletions go to the PGW again */
    ogs_list_for_each(&mme_ue->sess_list, sess)
        sess->src.relocated = false;

    mme_ue->s10.state = MME_S10_NONE;
    mme_ue->s10.xact_id = OGS_INVALID_POOL_ID;

    /* Registered on this MME from now on (TAU, Service Request, Detach) */
    OGS_FSM_TRAN(&mme_ue->sm, &emm_state_registered);

    ogs_info("[%s] S10 relocation complete: S5 path switched to the target "
            "SGW, UE registered on this MME", mme_ue->imsi_bcd);

    /* Data forwarding is over: remove the indirect tunnels on the SGW */
    if (target_ue && mme_ue_have_indirect_tunnel(mme_ue) == true) {
        r = mme_gtp_send_delete_indirect_data_forwarding_tunnel_request(
                target_ue, mme_ue, OGS_GTP_DELETE_INDIRECT_HANDOVER_COMPLETE);
        ogs_expect(r == OGS_OK);
    } else {
        mme_ue_clear_indirect_tunnel(mme_ue);
    }
}

/*
 * Target side failure at any point before the UE moved: tell the source
 * MME (if it still waits) and remove what was built here. The sessions
 * on the target SGW are deleted with Scope Indication only, so that the
 * SGW-C does not forward the deletion to the PGW, which still serves the
 * UE through the source side.
 */
void mme_s10_target_fail(mme_ue_t *mme_ue, uint8_t cause_value,
        const char *reason)
{
    int n = 0;
    ogs_pkbuf_t *pkbuf = NULL;
    sgw_ue_t *sgw_ue = NULL;
    enb_ue_t *target_ue = NULL;
    mme_sess_t *sess = NULL;

    ogs_assert(mme_ue);

    if (mme_ue->s10.state == MME_S10_TGT_CLEANUP)
        return;

    ogs_error("[%s] S10 relocation failed in state[%d]: %s",
            mme_ue->imsi_bcd, mme_ue->s10.state, reason ? reason : "-");

    if (mme_ue->s10.xact_id != OGS_INVALID_POOL_ID) {
        pkbuf = mme_s10_build_forward_relocation_response(
                OGS_GTP2_FORWARD_RELOCATION_RESPONSE_TYPE, cause_value);
        if (pkbuf)
            reply_pending_request(mme_ue, pkbuf);
        else
            mme_ue->s10.xact_id = OGS_INVALID_POOL_ID;
    }

    mme_ue->s10.state = MME_S10_TGT_CLEANUP;

    sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    target_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);

    GTP_COUNTER_CLEAR(mme_ue, GTP_COUNTER_DELETE_SESSION_BY_S10_HANDOVER);
    if (sgw_ue && sgw_ue->sgw_s11_teid) {
        ogs_list_for_each(&mme_ue->sess_list, sess) {
            mme_bearer_t *bearer = mme_default_bearer_in_sess(sess);
            if (!bearer || !bearer->sgw_s1u_teid)
                continue;           /* never created on the SGW */
            GTP_COUNTER_INCREMENT(
                    mme_ue, GTP_COUNTER_DELETE_SESSION_BY_S10_HANDOVER);
            if (mme_gtp_send_delete_session_request(target_ue, sgw_ue,
                        sess, OGS_GTP_DELETE_IN_S10_HANDOVER) == OGS_OK)
                n++;
        }
    }

    if (!n)
        mme_s10_target_cleanup_done(mme_ue);
}

/* All target sessions are gone: remove the UE and its S1 context */
void mme_s10_target_cleanup_done(mme_ue_t *mme_ue)
{
    enb_ue_t *target_ue = NULL;

    ogs_assert(mme_ue);

    ogs_info("[%s] S10 relocation: context removed",
            mme_ue->imsi_bcd);

    target_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
    mme_ue_remove(mme_ue);
    if (target_ue)
        enb_ue_remove(target_ue);
}

/*
 * Source MME: copy the target SGW's forwarding F-TEIDs into the bearer's
 * indirect tunnel far ends. Returns true if at least one bearer needs a
 * tunnel on the source SGW. Direct forwarding (target eNB F-TEIDs) is not
 * used: this source MME never sets the Direct Forwarding Indication.
 */
static bool source_forwarding_setup(mme_ue_t *mme_ue)
{
    bool any = false;
    mme_sess_t *sess = NULL;
    mme_bearer_t *bearer = NULL;

    ogs_list_for_each(&mme_ue->sess_list, sess) {
        ogs_list_for_each(&sess->bearer_list, bearer) {
            CLEAR_INDIRECT_TUNNEL(bearer);
            if (!bearer->s10_fwd.indirect)
                continue;
            if (bearer->s10_fwd.dl_teid) {
                bearer->enb_dl_teid = bearer->s10_fwd.dl_teid;
                bearer->enb_dl_ip = bearer->s10_fwd.dl_ip;
                any = true;
            }
            if (bearer->s10_fwd.ul_teid) {
                bearer->enb_ul_teid = bearer->s10_fwd.ul_teid;
                bearer->enb_ul_ip = bearer->s10_fwd.ul_ip;
                any = true;
            }
        }
    }
    return any;
}

/*
 * Source MME, step 8a: the source SGW created the indirect forwarding
 * tunnels towards the target SGW. Its F-TEIDs go to the source eNB in
 * the E-RABs Subject to Forwarding of the Handover Command (step 9).
 */
void mme_s10_source_handle_create_indirect_data_forwarding_tunnel_response(
        enb_ue_t *source_ue, mme_ue_t *mme_ue, mme_ue_t *mme_ue_from_teid,
        ogs_gtp2_create_indirect_data_forwarding_tunnel_response_t *rsp)
{
    int i, r, n = 0;
    uint8_t cause_value = OGS_GTP2_CAUSE_UNDEFINED_VALUE;
    mme_bearer_t *bearer = NULL;
    ogs_gtp2_f_teid_t *teid = NULL;
    char buf1[OGS_ADDRSTRLEN], buf2[OGS_ADDRSTRLEN];

    ogs_assert(mme_ue);
    ogs_assert(rsp);

    if (mme_ue->s10.state != MME_S10_SRC_FORWARDING) {
        ogs_warn("[%s] Create Indirect Data Forwarding Tunnel Response in "
                "S10 state[%d]: ignored", mme_ue->imsi_bcd, mme_ue->s10.state);
        return;
    }
    if (!source_ue) {
        ogs_error("[%s] Source S1 context is gone", mme_ue->imsi_bcd);
        mme_ue->s10.state = MME_S10_NONE;
        return;
    }

    if (rsp->cause.presence && rsp->cause.data) {
        ogs_gtp2_cause_t *cause = rsp->cause.data;
        cause_value = cause->value;
    }
    if (!mme_ue_from_teid ||
        cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        ogs_error("[%s] Create Indirect Data Forwarding Tunnel Response "
                "from the source SGW: cause[%d]%s", mme_ue->imsi_bcd,
                cause_value, mme_ue_from_teid ? "" : " (no context in TEID)");
        goto failure;
    }

    for (i = 0; i < OGS_BEARER_PER_UE && rsp->bearer_contexts[i].presence;
            i++) {
        if (!rsp->bearer_contexts[i].eps_bearer_id.presence)
            continue;
        bearer = mme_bearer_find_by_ue_ebi(mme_ue,
                rsp->bearer_contexts[i].eps_bearer_id.u8);
        if (!bearer)
            continue;
        /* Same IE instances as the intra-MME path in mme-s11-handler.c */
        if (rsp->bearer_contexts[i].s4_u_sgsn_f_teid.presence &&
            rsp->bearer_contexts[i].s4_u_sgsn_f_teid.data) {
            teid = rsp->bearer_contexts[i].s4_u_sgsn_f_teid.data;
            bearer->sgw_dl_teid = be32toh(teid->teid);
            if (ogs_gtp2_f_teid_to_ip(teid, &bearer->sgw_dl_ip) != OGS_OK)
                bearer->sgw_dl_teid = 0;
        }
        if (rsp->bearer_contexts[i].s2b_u_epdg_f_teid_5.presence &&
            rsp->bearer_contexts[i].s2b_u_epdg_f_teid_5.data) {
            teid = rsp->bearer_contexts[i].s2b_u_epdg_f_teid_5.data;
            bearer->sgw_ul_teid = be32toh(teid->teid);
            if (ogs_gtp2_f_teid_to_ip(teid, &bearer->sgw_ul_ip) != OGS_OK)
                bearer->sgw_ul_teid = 0;
        }
        if (bearer->sgw_dl_teid || bearer->sgw_ul_teid)
            n++;
        ogs_info("    EBI[%d] source SGW DL-FWD[%s teid 0x%x] "
                "UL-FWD[%s teid 0x%x] -> target SGW DL[0x%x] UL[0x%x]",
                bearer->ebi,
                ip_to_str(&bearer->sgw_dl_ip, buf1, sizeof(buf1)),
                bearer->sgw_dl_teid,
                ip_to_str(&bearer->sgw_ul_ip, buf2, sizeof(buf2)),
                bearer->sgw_ul_teid,
                bearer->enb_dl_teid, bearer->enb_ul_teid);
    }

    if (!n) {
        ogs_error("[%s] Source SGW returned no forwarding F-TEID",
                mme_ue->imsi_bcd);
        goto failure;
    }

    mme_ue->s10.state = MME_S10_SRC_PREPARED;
    ogs_info("[%s] S10: indirect forwarding ready on the source SGW, "
            "HandoverCommand to the source eNB", mme_ue->imsi_bcd);
    r = s1ap_send_handover_command(source_ue);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);
    return;

failure:
    /*
     * Keep enb_dl/ul set: if the SGW did create tunnels, the next UE
     * context release deletes them. The target MME keeps its prepared
     * context until Relocation Cancel is implemented.
     */
    mme_ue->s10.state = MME_S10_NONE;
    r = s1ap_send_handover_preparation_failure(source_ue,
            S1AP_Cause_PR_radioNetwork,
            S1AP_CauseRadioNetwork_ho_failure_in_target_EPC_eNB_or_target_system);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);
}

/*
 * Source MME side: the target MME answered our Forward Relocation
 * Request (step 7). Accepted -> Handover Command to the source eNB
 * (step 8). Anything else -> Handover Preparation Failure.
 */
void mme_s10_handle_forward_relocation_response(
        ogs_gtp_xact_t *xact, ogs_gtp2_forward_relocation_response_t *rsp)
{
    int r, rv;
    char buf[OGS_ADDRSTRLEN];
    uint8_t cause_value = OGS_GTP2_CAUSE_UNDEFINED_VALUE;
    mme_ue_t *mme_ue = NULL;
    enb_ue_t *enb_ue = NULL;
    ogs_gtp2_f_container_t container;

    ogs_assert(xact);
    ogs_assert(rsp);

    ogs_debug("Forward Relocation Response");

    mme_ue = mme_ue_find_by_id(OGS_POINTER_TO_UINT(xact->data));
    enb_ue = enb_ue_find_by_id(xact->enb_ue_id);

    rv = ogs_gtp_xact_commit(xact);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp_xact_commit() failed");
        return;
    }

    if (rsp->cause.presence && rsp->cause.data &&
        rsp->cause.len >= sizeof(uint8_t)) {
        ogs_gtp2_cause_t *cause = rsp->cause.data;
        cause_value = cause->value;
    } else
        ogs_error("No Cause in Forward Relocation Response");

    ogs_info("S10 Forward Relocation Response from peer MME[%s]: cause[%d]",
            OGS_ADDR(&xact->gnode->addr, buf), cause_value);

    if (!mme_ue) {
        ogs_warn("MME-UE Context has already been removed");
        return;
    }
    if (!enb_ue) {
        ogs_warn("No S1 Context");
        return;
    }

    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED &&
        cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED_PARTIALLY)
        goto failure;

    /* Target MME S10 control TEID, for the rest of the procedure */
    if (rsp->sender_s_f_teid_for_control_plane.presence &&
        rsp->sender_s_f_teid_for_control_plane.data &&
        rsp->sender_s_f_teid_for_control_plane.len >=
            OGS_GTP2_F_TEID_HDR_LEN) {
        ogs_gtp2_f_teid_t *f = rsp->sender_s_f_teid_for_control_plane.data;
        mme_ue->s10.peer_teid = be32toh(f->teid);
        ogs_gtp2_f_teid_to_ip(f, &mme_ue->s10.peer_ip);
        mme_ue->s10.gnode = xact->gnode;
    } else {
        ogs_error("[%s] Accepted, but no Sender F-TEID", mme_ue->imsi_bcd);
        goto failure;
    }

    memset(&container, 0, sizeof(container));
    if (!rsp->e_utran_transparent_container.presence ||
        ogs_gtp2_parse_f_container(&container,
            &rsp->e_utran_transparent_container) <= 0 ||
        container.container_type !=
            OGS_GTP2_F_CONTAINER_TYPE_E_UTRAN_TRANSPARENT_CONTAINER ||
        !container.data || !container.len) {
        ogs_error("[%s] Accepted, but no E-UTRAN Transparent Container",
                mme_ue->imsi_bcd);
        goto failure;
    }

    /*
     * Data forwarding F-TEIDs per bearer (target SGW for indirect, target
     * eNB for direct forwarding), told apart by their interface type.
     * Used by step 8 (Create Indirect Data Forwarding Tunnel Request to
     * the source SGW), which is the next step to implement.
     */
    {
        int i;
        char b1[OGS_ADDRSTRLEN], b2[OGS_ADDRSTRLEN];

        for (i = 0; i < OGS_BEARER_PER_UE &&
                rsp->list_of_set_up_bearers[i].presence; i++) {
            ogs_gtp2_tlv_bearer_context_t *bc =
                &rsp->list_of_set_up_bearers[i];
            ogs_gtp2_tlv_f_teid_t *slot[2];
            mme_bearer_t *bearer = NULL;
            int k;

            if (!bc->eps_bearer_id.presence)
                continue;
            bearer = mme_bearer_find_by_ue_ebi(mme_ue, bc->eps_bearer_id.u8);
            if (!bearer)
                continue;
            memset(&bearer->s10_fwd, 0, sizeof(bearer->s10_fwd));

            slot[0] = &bc->s1_u_enodeb_f_teid;  /* instance 0 */
            slot[1] = &bc->s4_u_sgsn_f_teid;    /* instance 1 */
            for (k = 0; k < 2; k++) {
                ogs_gtp2_f_teid_t *f = slot[k]->data;
                if (!slot[k]->presence || !f)
                    continue;
                switch (f->interface_type) {
                case OGS_GTP2_F_TEID_SGW_GTP_U_FOR_DL_DATA_FORWARDING:
                    bearer->s10_fwd.indirect = true;
                    OGS_GNUC_FALLTHROUGH;
                case OGS_GTP2_F_TEID_ENODEB_GTP_U_FOR_DL_DATA_FORWARDING:
                    bearer->s10_fwd.dl_teid = be32toh(f->teid);
                    ogs_gtp2_f_teid_to_ip(f, &bearer->s10_fwd.dl_ip);
                    break;
                case OGS_GTP2_F_TEID_SGW_GTP_U_FOR_UL_DATA_FORWARDING:
                    bearer->s10_fwd.indirect = true;
                    OGS_GNUC_FALLTHROUGH;
                case OGS_GTP2_F_TEID_ENODEB_GTP_U_FOR_UL_DATA_FORWARDING:
                    bearer->s10_fwd.ul_teid = be32toh(f->teid);
                    ogs_gtp2_f_teid_to_ip(f, &bearer->s10_fwd.ul_ip);
                    break;
                default:
                    ogs_warn("[%s] EBI[%d]: F-TEID interface type[%d] "
                            "ignored", mme_ue->imsi_bcd, bearer->ebi,
                            f->interface_type);
                    break;
                }
            }
            ogs_info("    set-up EBI[%d] DL-FWD[%s teid 0x%x] "
                    "UL-FWD[%s teid 0x%x]", bearer->ebi,
                    ip_to_str(&bearer->s10_fwd.dl_ip, b1, sizeof(b1)),
                    bearer->s10_fwd.dl_teid,
                    ip_to_str(&bearer->s10_fwd.ul_ip, b2, sizeof(b2)),
                    bearer->s10_fwd.ul_teid);
        }
    }

    /* s1ap_build_handover_command() takes the container from here */
    OGS_ASN_CLEAR_DATA(&mme_ue->container);
    ogs_s1ap_buffer_to_OCTET_STRING(
            container.data, container.len, &mme_ue->container);

    /*
     * Step 8 (TS 23.401 5.5.1.2.2): indirect forwarding, the target SGW
     * gave its forwarding F-TEIDs. The source SGW gets tunnels towards
     * them; its own forwarding F-TEIDs (step 8a) go to the source eNB in
     * the Handover Command. The bearer's enb_dl/ul F-TEIDs are what
     * mme_s11_build_create_indirect_data_forwarding_tunnel_request() uses
     * as the far end, and what the release procedures later delete.
     */
    if (source_forwarding_setup(mme_ue)) {
        mme_ue->s10.state = MME_S10_SRC_FORWARDING;
        ogs_info("[%s] S10 relocation accepted by the target MME: "
                "Create Indirect Data Forwarding Tunnel Request to the "
                "source SGW", mme_ue->imsi_bcd);
        if (mme_gtp_send_create_indirect_data_forwarding_tunnel_request(
                    enb_ue, mme_ue) == OGS_OK)
            return;
        ogs_error("[%s] Create Indirect Data Forwarding Tunnel Request "
                "could not be sent", mme_ue->imsi_bcd);
        mme_ue_clear_indirect_tunnel(mme_ue);
        mme_ue->s10.state = MME_S10_NONE;
        goto failure;
    }

    mme_ue->s10.state = MME_S10_SRC_PREPARED;

    ogs_info("[%s] S10 relocation accepted by the target MME: "
            "HandoverCommand to the source eNB (no data forwarding)",
            mme_ue->imsi_bcd);
    r = s1ap_send_handover_command(enb_ue);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);
    return;

failure:
    /*
     * NOTE: if the target accepted but we fail here, the target keeps its
     * prepared context until Relocation Cancel is implemented.
     */
    r = s1ap_send_handover_preparation_failure(enb_ue,
            S1AP_Cause_PR_radioNetwork,
            S1AP_CauseRadioNetwork_ho_failure_in_target_EPC_eNB_or_target_system);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);
}

/*
 * Source MME, step 10 (TS 23.401 5.5.1.2.2): the source eNB sent eNB
 * Status Transfer. Its transparent container (PDCP SN / HFN status per
 * E-RAB) goes to the target MME in a Forward Access Context Notification.
 * Returns true if the UE is in an S10 relocation (the message is handled
 * here), false otherwise.
 */
bool mme_s10_handle_enb_status_transfer(enb_ue_t *source_ue,
        S1AP_ENB_StatusTransfer_TransparentContainer_t *container)
{
    int rv;
    mme_ue_t *mme_ue = NULL;
    ogs_pkbuf_t *encoded = NULL;

    ogs_assert(source_ue);

    mme_ue = mme_ue_find_by_id(source_ue->mme_ue_id);
    if (!mme_ue || mme_ue->s10.state != MME_S10_SRC_PREPARED)
        return false;

    if (!container) {
        ogs_error("[%s] eNB Status Transfer without container",
                mme_ue->imsi_bcd);
        return true;
    }

    encoded = ogs_asn_encode(
            &asn_DEF_S1AP_ENB_StatusTransfer_TransparentContainer, container);
    if (!encoded) {
        ogs_error("[%s] Cannot encode eNB Status Transfer container",
                mme_ue->imsi_bcd);
        return true;
    }

    ogs_info("[%s] S10: eNB Status Transfer -> Forward Access Context "
            "Notification to the target MME (%d octets)",
            mme_ue->imsi_bcd, encoded->len);

    rv = mme_gtp_send_forward_access_context_notification(
            source_ue, mme_ue, encoded->data, encoded->len);
    ogs_expect(rv == OGS_OK);
    ogs_pkbuf_free(encoded);

    return true;
}

/* Source MME: the target MME acknowledged the Forward Access Context */
void mme_s10_handle_forward_access_context_acknowledge(
        ogs_gtp_xact_t *xact, ogs_gtp2_forward_access_context_acknowledge_t *rsp)
{
    int rv;
    uint8_t cause_value = OGS_GTP2_CAUSE_UNDEFINED_VALUE;
    mme_ue_t *mme_ue = NULL;

    ogs_assert(xact);
    ogs_assert(rsp);

    mme_ue = mme_ue_find_by_id(OGS_POINTER_TO_UINT(xact->data));

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    if (rsp->cause.presence && rsp->cause.data) {
        ogs_gtp2_cause_t *cause = rsp->cause.data;
        cause_value = cause->value;
    }

    if (cause_value == OGS_GTP2_CAUSE_REQUEST_ACCEPTED)
        ogs_info("[%s] S10 Forward Access Context Acknowledge",
                mme_ue ? mme_ue->imsi_bcd : "?");
    else
        ogs_error("[%s] S10 Forward Access Context Acknowledge: cause[%d]",
                mme_ue ? mme_ue->imsi_bcd : "?", cause_value);
}

/*
 * Target MME, step 10: acknowledge, then MME Status Transfer to the
 * target eNB with the source eNB's PDCP status.
 */
void mme_s10_handle_forward_access_context_notification(
        ogs_gtp_xact_t *xact, uint32_t teid,
        ogs_gtp2_forward_access_context_notification_t *req)
{
    int rv, r;
    uint8_t cause_value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;
    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_pkbuf_t *asnbuf = NULL;
    mme_ue_t *mme_ue = NULL;
    enb_ue_t *target_ue = NULL;
    ogs_gtp2_f_container_t container;
    S1AP_ENB_StatusTransfer_TransparentContainer_t status;
    bool decoded = false;

    ogs_assert(xact);
    ogs_assert(req);

    memset(&status, 0, sizeof(status));

    mme_ue = mme_ue_find_by_s11_local_teid(teid);
    if (!mme_ue ||
        (mme_ue->s10.state != MME_S10_TGT_PREPARED &&
         mme_ue->s10.state != MME_S10_TGT_NOTIFIED)) {
        ogs_error("Forward Access Context Notification: no relocation for "
                "TEID[0x%x]", teid);
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
        goto respond;
    }
    target_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
    if (!target_ue) {
        ogs_error("[%s] Forward Access Context Notification: target S1 "
                "context is gone", mme_ue->imsi_bcd);
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
        goto respond;
    }

    memset(&container, 0, sizeof(container));
    if (!req->e_utran_transparent_container.presence ||
        ogs_gtp2_parse_f_container(&container,
            &req->e_utran_transparent_container) <= 0 ||
        !container.data || !container.len) {
        ogs_error("[%s] Forward Access Context Notification without "
                "E-UTRAN Transparent Container", mme_ue->imsi_bcd);
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
        goto respond;
    }

    asnbuf = ogs_pkbuf_alloc(NULL, container.len);
    ogs_assert(asnbuf);
    ogs_pkbuf_put_data(asnbuf, container.data, container.len);
    rv = ogs_asn_decode(&asn_DEF_S1AP_ENB_StatusTransfer_TransparentContainer,
            &status, sizeof(status), asnbuf);
    ogs_pkbuf_free(asnbuf);
    if (rv != OGS_OK) {
        ogs_error("[%s] Cannot decode eNB Status Transfer container",
                mme_ue->imsi_bcd);
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
        goto respond;
    }
    decoded = true;

respond:
    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_FORWARD_ACCESS_CONTEXT_ACKNOWLEDGE_TYPE;
    h.teid = mme_ue ? mme_ue->s10.peer_teid : 0;

    pkbuf = mme_s10_build_forward_access_context_acknowledge(
            h.type, cause_value);
    if (pkbuf) {
        rv = ogs_gtp_xact_update_tx(xact, &h, pkbuf);
        if (rv == OGS_OK) {
            rv = ogs_gtp_xact_commit(xact);
            ogs_expect(rv == OGS_OK);
        } else
            ogs_error("ogs_gtp_xact_update_tx() failed");
    }

    if (decoded) {
        ogs_info("[%s] S10 Forward Access Context Notification: "
                "MME Status Transfer to the target eNB", mme_ue->imsi_bcd);
        ogs_info("    Target : ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
                target_ue->enb_ue_s1ap_id, target_ue->mme_ue_s1ap_id);
        r = s1ap_send_mme_status_transfer(target_ue, &status);
        ogs_expect(r == OGS_OK);
        ogs_asn_free(&asn_DEF_S1AP_ENB_StatusTransfer_TransparentContainer,
                &status);
    }
}

/*
 * Source MME, steps 14/14a: the UE is on the target side. Acknowledge,
 * release the source eNB (after the handover timer, so data forwarding can
 * finish), then remove the sessions on the source SGW.
 */
void mme_s10_handle_forward_relocation_complete_notification(
        ogs_gtp_xact_t *xact, uint32_t teid,
        ogs_gtp2_forward_relocation_complete_notification_t *req)
{
    int rv, r;
    uint8_t cause_value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;
    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;
    mme_ue_t *mme_ue = NULL;
    enb_ue_t *source_ue = NULL;

    ogs_assert(xact);

    mme_ue = mme_ue_find_by_s11_local_teid(teid);
    if (!mme_ue || mme_ue->s10.state != MME_S10_SRC_PREPARED) {
        ogs_error("Forward Relocation Complete Notification: no relocation "
                "for TEID[0x%x]%s", teid,
                mme_ue ? " (wrong state)" : "");
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
    }

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_FORWARD_RELOCATION_COMPLETE_ACKNOWLEDGE_TYPE;
    h.teid = mme_ue ? mme_ue->s10.peer_teid : 0;
    pkbuf = mme_s10_build_forward_relocation_complete_acknowledge(
            h.type, cause_value);
    if (pkbuf) {
        rv = ogs_gtp_xact_update_tx(xact, &h, pkbuf);
        if (rv == OGS_OK) {
            rv = ogs_gtp_xact_commit(xact);
            ogs_expect(rv == OGS_OK);
        } else
            ogs_error("ogs_gtp_xact_update_tx() failed");
    }

    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED)
        return;

    ogs_info("[%s] S10 Forward Relocation Complete Notification: the UE "
            "is on the target side, releasing the source", mme_ue->imsi_bcd);

    mme_ue->s10.state = MME_S10_SRC_COMPLETING;

    source_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
    if (source_ue) {
        /* Sessions go once the eNB has released (see release complete) */
        r = s1ap_send_ue_context_release_command(source_ue,
                S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_successful_handover,
                S1AP_UE_CTX_REL_S1_REMOVE_AND_UNLINK,
                ogs_local_conf()->time.handover.duration);
        ogs_expect(r == OGS_OK);
    } else {
        mme_s10_source_release_sessions(mme_ue);
    }
}

/*
 * Source MME: remove the sessions on the source SGW (indirect tunnels
 * included). Scope Indication only: the PGW serves the UE through the
 * target SGW now (TS 23.401 step 19, Operation Indication not set).
 * The context goes when the last session is deleted.
 */
void mme_s10_source_release_sessions(mme_ue_t *mme_ue)
{
    int n = 0;
    sgw_ue_t *sgw_ue = NULL;
    mme_sess_t *sess = NULL;

    ogs_assert(mme_ue);

    if (mme_ue->s10.state != MME_S10_SRC_COMPLETING)
        return;

    ogs_info("[%s] S10: removing the source sessions (local to the source "
            "SGW)", mme_ue->imsi_bcd);

    /* Indirect tunnels go with the sessions */
    mme_ue_clear_indirect_tunnel(mme_ue);

    sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    GTP_COUNTER_CLEAR(mme_ue, GTP_COUNTER_DELETE_SESSION_BY_S10_HANDOVER);
    if (sgw_ue && sgw_ue->sgw_s11_teid) {
        ogs_list_for_each(&mme_ue->sess_list, sess) {
            GTP_COUNTER_INCREMENT(
                    mme_ue, GTP_COUNTER_DELETE_SESSION_BY_S10_HANDOVER);
            if (mme_gtp_send_delete_session_request(NULL, sgw_ue, sess,
                        OGS_GTP_DELETE_IN_S10_HANDOVER) == OGS_OK)
                n++;
        }
    }

    if (!n)
        mme_s10_target_cleanup_done(mme_ue);
}

/* Target MME: the source MME acknowledged step 14 */
void mme_s10_handle_forward_relocation_complete_acknowledge(
        ogs_gtp_xact_t *xact,
        ogs_gtp2_forward_relocation_complete_acknowledge_t *rsp)
{
    int rv;
    uint8_t cause_value = OGS_GTP2_CAUSE_UNDEFINED_VALUE;
    mme_ue_t *mme_ue = NULL;

    ogs_assert(xact);
    ogs_assert(rsp);

    mme_ue = mme_ue_find_by_id(OGS_POINTER_TO_UINT(xact->data));

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    if (rsp->cause.presence && rsp->cause.data) {
        ogs_gtp2_cause_t *cause = rsp->cause.data;
        cause_value = cause->value;
    }
    if (cause_value == OGS_GTP2_CAUSE_REQUEST_ACCEPTED)
        ogs_info("[%s] S10 Forward Relocation Complete Acknowledge",
                mme_ue ? mme_ue->imsi_bcd : "?");
    else
        ogs_error("[%s] S10 Forward Relocation Complete Acknowledge: "
                "cause[%d]", mme_ue ? mme_ue->imsi_bcd : "?", cause_value);
}
