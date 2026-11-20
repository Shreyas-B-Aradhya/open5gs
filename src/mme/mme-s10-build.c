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

#include "mme-s10-build.h"
#include "mme-s10-mm-context.h"
#include "mme-sm.h"

#define S10_TARGET_ID_BUF_LEN   16
#define S10_F_CAUSE_BUF_LEN     8
#define S10_BEARER_QOS_BUF_LEN  22

/*
 * Fill the MM Context from the UE's current EPS security context.
 * The {NH, NCC} pair is the fresh one computed on Handover Required
 * (TS 33.401 7.2.8.4.3): the target MME hands it to the target eNB.
 */
static void fill_mm_context(mme_s10_mm_context_t *ctx, mme_ue_t *mme_ue)
{
    memset(ctx, 0, sizeof(*ctx));

    ctx->ksi_asme = mme_ue->nas_eps.mme.ksi & 0x07;
    ctx->nas_int_alg = mme_ue->selected_int_algorithm;
    ctx->nas_enc_alg = mme_ue->selected_enc_algorithm;
    ctx->nas_dl_count = mme_ue->dl_count & 0xffffff;
    ctx->nas_ul_count = mme_ue->ul_count.i32 & 0xffffff;
    memcpy(ctx->kasme, mme_ue->kasme, sizeof(ctx->kasme));

    ctx->nhi = true;
    memcpy(ctx->nh, mme_ue->nh, sizeof(ctx->nh));
    ctx->ncc = mme_ue->nhcc;

    /* UE-AMBR in kbps */
    if (mme_ue->ambr.uplink || mme_ue->ambr.downlink) {
        ctx->sambri = true;
        ctx->sub_ue_ambr_ul = mme_ue->ambr.uplink / 1000;
        ctx->sub_ue_ambr_dl = mme_ue->ambr.downlink / 1000;
    }

    memcpy(&ctx->ue_network_capability, &mme_ue->ue_network_capability,
            sizeof(ctx->ue_network_capability));
    memcpy(&ctx->ms_network_capability, &mme_ue->ms_network_capability,
            sizeof(ctx->ms_network_capability));

    if (mme_ue->imeisv_len > 0 && mme_ue->imeisv_len <= MME_S10_MEI_MAX_LEN) {
        ctx->mei_len = mme_ue->imeisv_len;
        memcpy(ctx->mei, mme_ue->imeisv, mme_ue->imeisv_len);
    }
}

ogs_pkbuf_t *mme_s10_build_forward_relocation_request(
        uint8_t type, mme_ue_t *mme_ue, sgw_ue_t *sgw_ue,
        ogs_gtp2_target_identification_t *target,
        ogs_gtp2_f_cause_t *s1ap_cause,
        const uint8_t *container, uint16_t container_len)
{
    int rv, len;
    int16_t size;
    ogs_gtp2_message_t gtp_message;
    ogs_gtp2_forward_relocation_request_t *req =
        &gtp_message.forward_relocation_request;

    ogs_gtp2_f_teid_t mme_s10_teid, sgw_s11_teid;
    ogs_gtp2_f_container_t f_container;
    uint8_t f_container_buf[OGS_MAX_SDU_LEN];
    uint8_t target_id_buf[S10_TARGET_ID_BUF_LEN];
    uint8_t f_cause_buf[S10_F_CAUSE_BUF_LEN];
    mme_s10_mm_context_t mm_ctx;
    uint8_t mm_ctx_buf[MME_S10_MM_CONTEXT_MAX_LEN];

    /* PDN Connections: storage referenced by the IEs until the message is built */
    int i, j;
    mme_sess_t *sess = NULL;
    mme_bearer_t *bearer = NULL;
    char apn[OGS_MAX_NUM_OF_SESS][OGS_MAX_APN_LEN+1];
    uint32_t ue_ipv4[OGS_MAX_NUM_OF_SESS];
    ogs_gtp2_ambr_t ambr[OGS_MAX_NUM_OF_SESS];
    ogs_gtp2_f_teid_t pgw_s5c_teid[OGS_MAX_NUM_OF_SESS];
    int pgw_s5c_len[OGS_MAX_NUM_OF_SESS];
    ogs_gtp2_f_teid_t sgw_s1u_teid[OGS_MAX_NUM_OF_SESS][OGS_BEARER_PER_UE];
    int sgw_s1u_len[OGS_MAX_NUM_OF_SESS][OGS_BEARER_PER_UE];
    ogs_gtp2_f_teid_t pgw_s5u_teid[OGS_MAX_NUM_OF_SESS][OGS_BEARER_PER_UE];
    int pgw_s5u_len[OGS_MAX_NUM_OF_SESS][OGS_BEARER_PER_UE];
    ogs_gtp2_bearer_qos_t bearer_qos[OGS_MAX_NUM_OF_SESS][OGS_BEARER_PER_UE];
    uint8_t bearer_qos_buf[OGS_MAX_NUM_OF_SESS][OGS_BEARER_PER_UE]
                          [S10_BEARER_QOS_BUF_LEN];

    ogs_assert(mme_ue);
    ogs_assert(sgw_ue);
    ogs_assert(sgw_ue->gnode);
    ogs_assert(target);
    ogs_assert(s1ap_cause);
    ogs_assert(container);

    if (!mme_ue->imsi_len) {
        ogs_error("No IMSI");
        return NULL;
    }

    /* 1 octet container type + container */
    if ((size_t)container_len + 1 > sizeof(f_container_buf)) {
        ogs_error("Transparent container too large [%d]", container_len);
        return NULL;
    }

    ogs_debug("Forward Relocation Request");

    memset(&gtp_message, 0, sizeof(ogs_gtp2_message_t));

    /* IMSI */
    req->imsi.presence = 1;
    req->imsi.data = mme_ue->imsi;
    req->imsi.len = mme_ue->imsi_len;

    /*
     * Sender F-TEID for Control Plane (S10 MME GTP-C).
     *
     * NOTE: For now the local TEID reuses mme_ue->mme_s11_teid, which is
     * unique per UE and already indexed for lookup. A dedicated S10 TEID
     * is a later decision.
     */
    memset(&mme_s10_teid, 0, sizeof(ogs_gtp2_f_teid_t));
    mme_s10_teid.interface_type = OGS_GTP2_F_TEID_S10_MME_GTP_C;
    mme_s10_teid.teid = htobe32(mme_ue->mme_s11_teid);
    rv = ogs_gtp2_sockaddr_to_f_teid(
            ogs_gtp_self()->gtpc_addr, ogs_gtp_self()->gtpc_addr6,
            &mme_s10_teid, &len);
    if (rv != OGS_OK) {
        ogs_error("No local GTP-C address for the Sender F-TEID");
        return NULL;
    }
    req->sender_s_f_teid_for_control_plane.presence = 1;
    req->sender_s_f_teid_for_control_plane.data = &mme_s10_teid;
    req->sender_s_f_teid_for_control_plane.len = len;

    /* SGW S11/S4 IP address and TEID for Control Plane */
    memset(&sgw_s11_teid, 0, sizeof(ogs_gtp2_f_teid_t));
    sgw_s11_teid.interface_type = OGS_GTP2_F_TEID_S11_S4_SGW_GTP_C;
    sgw_s11_teid.teid = htobe32(sgw_ue->sgw_s11_teid);
    if (sgw_ue->gnode->addr.ogs_sa_family == AF_INET6)
        rv = ogs_gtp2_sockaddr_to_f_teid(
                NULL, &sgw_ue->gnode->addr, &sgw_s11_teid, &len);
    else
        rv = ogs_gtp2_sockaddr_to_f_teid(
                &sgw_ue->gnode->addr, NULL, &sgw_s11_teid, &len);
    if (rv != OGS_OK) {
        ogs_error("No SGW address for the S11 F-TEID");
        return NULL;
    }
    req->sgw_s11_s4_ip_address_and_teid_for_control_plane.presence = 1;
    req->sgw_s11_s4_ip_address_and_teid_for_control_plane.data =
        &sgw_s11_teid;
    req->sgw_s11_s4_ip_address_and_teid_for_control_plane.len = len;

    /*
     * MME/SGSN/AMF UE EPS PDN Connections (TS 29.274 Table 7.3.1-2): one
     * grouped IE per session with its APN, default bearer, PGW S5/S8 control
     * F-TEID, AMBR and bearer contexts (EBI, SGW S1-U F-TEID, PGW S5/S8-U
     * F-TEID, bearer QoS).
     *
     * Not carried yet: the TFT of dedicated bearers and the UE IPv6 address.
     */
    i = 0;
    ogs_list_for_each(&mme_ue->sess_list, sess) {
        ogs_session_t *session = sess->session;
        mme_bearer_t *default_bearer = mme_default_bearer_in_sess(sess);
        ogs_gtp2_tlv_pdn_connection_t *pdn = NULL;

        if (!session || !session->name || !default_bearer) {
            ogs_error("Session without APN or default bearer");
            return NULL;
        }
        /*
         * A PDN connection being released (e.g. UE-requested PDN
         * disconnect in progress) is not relocated: its SGW session may
         * already be gone, which would fail the indirect forwarding setup.
         */
        if (!OGS_FSM_CHECK(&default_bearer->sm, esm_state_active)) {
            ogs_warn("[%s] APN[%s] not active, not relocated",
                    mme_ue->imsi_bcd, session->name);
            continue;
        }
        if (i >= OGS_MAX_NUM_OF_SESS) {
            ogs_error("Too many sessions");
            return NULL;
        }

        pdn = &req->mme_sgsn_amf_ue_eps_pdn_connections[i];
        pdn->presence = 1;

        /* APN */
        pdn->apn.presence = 1;
        pdn->apn.len = ogs_fqdn_build(
                apn[i], session->name, strlen(session->name));
        pdn->apn.data = apn[i];

        /* Selection Mode */
        pdn->selection_mode.presence = 1;
        pdn->selection_mode.u8 =
            OGS_GTP2_SELECTION_MODE_MS_OR_NETWORK_PROVIDED_APN;

        /*
         * UE IPv4 Address. The address the PGW assigned is kept in sess->paa
         * (session->ue_ip is deliberately left alone after the Create
         * Session Response: it only holds the subscribed static address).
         * So read sess->paa first and fall back to the static address.
         */
        {
            ogs_ip_t ue_ip;

            memset(&ue_ip, 0, sizeof(ue_ip));
            if (sess->paa.session_type != OGS_PDU_SESSION_TYPE_IPV4 &&
                sess->paa.session_type != OGS_PDU_SESSION_TYPE_IPV4V6)
                ue_ip = session->ue_ip;
            else if (ogs_paa_to_ip(&sess->paa, &ue_ip) != OGS_OK)
                ue_ip = session->ue_ip;

            if (ue_ip.ipv4) {
                ue_ipv4[i] = ue_ip.addr;
                pdn->ipv4_address.presence = 1;
                pdn->ipv4_address.data = &ue_ipv4[i];
                pdn->ipv4_address.len = OGS_IPV4_LEN;
            }
        }

        /* Linked EPS Bearer ID */
        pdn->linked_eps_bearer_id.presence = 1;
        pdn->linked_eps_bearer_id.u8 = default_bearer->ebi;

        /* PGW S5/S8 Address for Control Plane (F-TEID, instance 0) */
        memset(&pgw_s5c_teid[i], 0, sizeof(ogs_gtp2_f_teid_t));
        pgw_s5c_teid[i].interface_type = OGS_GTP2_F_TEID_S5_S8_PGW_GTP_C;
        pgw_s5c_teid[i].teid = htobe32(sess->pgw_s5c_teid);
        if (ogs_gtp2_ip_to_f_teid(&sess->pgw_s5c_ip,
                    &pgw_s5c_teid[i], &pgw_s5c_len[i]) != OGS_OK) {
            ogs_error("No PGW S5/S8 control address for APN[%s]",
                    session->name);
            return NULL;
        }
        pdn->pgw_s5_s8_ip_address_for_control_plane_or_pmip.presence = 1;
        pdn->pgw_s5_s8_ip_address_for_control_plane_or_pmip.data =
            &pgw_s5c_teid[i];
        pdn->pgw_s5_s8_ip_address_for_control_plane_or_pmip.len =
            pgw_s5c_len[i];

        /* APN-AMBR (kbps) */
        if (session->ambr.uplink || session->ambr.downlink) {
            memset(&ambr[i], 0, sizeof(ogs_gtp2_ambr_t));
            ambr[i].uplink = htobe32(session->ambr.uplink / 1000);
            ambr[i].downlink = htobe32(session->ambr.downlink / 1000);
            pdn->aggregate_maximum_bit_rate.presence = 1;
            pdn->aggregate_maximum_bit_rate.data = &ambr[i];
            pdn->aggregate_maximum_bit_rate.len = sizeof(ambr[i]);
        }

        /* Bearer Contexts */
        j = 0;
        ogs_list_for_each(&sess->bearer_list, bearer) {
            ogs_gtp2_tlv_bearer_context_t *bc = NULL;
            ogs_qos_t *qos = NULL;

            if (j >= OGS_BEARER_PER_UE) {
                ogs_error("Too many bearers");
                return NULL;
            }
            if (!OGS_FSM_CHECK(&bearer->sm, esm_state_active))
                continue;

            bc = &pdn->bearer_contexts[j];
            bc->presence = 1;
            bc->eps_bearer_id.presence = 1;
            bc->eps_bearer_id.u8 = bearer->ebi;

            /* SGW S1/S4/S12 Address and TEID for user plane (instance 0) */
            memset(&sgw_s1u_teid[i][j], 0, sizeof(ogs_gtp2_f_teid_t));
            sgw_s1u_teid[i][j].interface_type =
                OGS_GTP2_F_TEID_S1_U_SGW_GTP_U;
            sgw_s1u_teid[i][j].teid = htobe32(bearer->sgw_s1u_teid);
            if (ogs_gtp2_ip_to_f_teid(&bearer->sgw_s1u_ip,
                        &sgw_s1u_teid[i][j], &sgw_s1u_len[i][j]) == OGS_OK) {
                bc->s1_u_enodeb_f_teid.presence = 1;
                bc->s1_u_enodeb_f_teid.data = &sgw_s1u_teid[i][j];
                bc->s1_u_enodeb_f_teid.len = sgw_s1u_len[i][j];
            }

            /* PGW S5/S8 Address and TEID for user plane (instance 1) */
            memset(&pgw_s5u_teid[i][j], 0, sizeof(ogs_gtp2_f_teid_t));
            pgw_s5u_teid[i][j].interface_type =
                OGS_GTP2_F_TEID_S5_S8_PGW_GTP_U;
            pgw_s5u_teid[i][j].teid = htobe32(bearer->pgw_s5u_teid);
            if (ogs_gtp2_ip_to_f_teid(&bearer->pgw_s5u_ip,
                        &pgw_s5u_teid[i][j], &pgw_s5u_len[i][j]) == OGS_OK) {
                bc->s4_u_sgsn_f_teid.presence = 1;
                bc->s4_u_sgsn_f_teid.data = &pgw_s5u_teid[i][j];
                bc->s4_u_sgsn_f_teid.len = pgw_s5u_len[i][j];
            }

            /* Bearer Level QoS: the default bearer uses the session QoS */
            qos = (bearer == default_bearer) ? &session->qos : &bearer->qos;
            memset(&bearer_qos[i][j], 0, sizeof(ogs_gtp2_bearer_qos_t));
            bearer_qos[i][j].qci = qos->index;
            bearer_qos[i][j].priority_level = qos->arp.priority_level;
            bearer_qos[i][j].pre_emption_capability =
                qos->arp.pre_emption_capability;
            bearer_qos[i][j].pre_emption_vulnerability =
                qos->arp.pre_emption_vulnerability;
            if (bearer != default_bearer) {
                bearer_qos[i][j].ul_mbr = qos->mbr.uplink;
                bearer_qos[i][j].dl_mbr = qos->mbr.downlink;
                bearer_qos[i][j].ul_gbr = qos->gbr.uplink;
                bearer_qos[i][j].dl_gbr = qos->gbr.downlink;
            }
            bc->bearer_level_qos.presence = 1;
            ogs_gtp2_build_bearer_qos(&bc->bearer_level_qos,
                    &bearer_qos[i][j], bearer_qos_buf[i][j],
                    S10_BEARER_QOS_BUF_LEN);

            /* TFT of a dedicated bearer (the packet filters of the call) */
            if (bearer != default_bearer &&
                bearer->tft.data && bearer->tft.len) {
                bc->tft.presence = 1;
                bc->tft.data = bearer->tft.data;
                bc->tft.len = bearer->tft.len;
            }

            j++;
        }

        i++;
    }

    /* E-UTRAN Transparent Container (Source to Target, TS 36.413) */
    memset(&f_container, 0, sizeof(f_container));
    f_container.container_type =
        OGS_GTP2_F_CONTAINER_TYPE_E_UTRAN_TRANSPARENT_CONTAINER;
    f_container.data = (uint8_t *)container;
    f_container.len = container_len;
    req->e_utran_transparent_container.presence = 1;
    size = ogs_gtp2_build_f_container(&req->e_utran_transparent_container,
            &f_container, f_container_buf, sizeof(f_container_buf));
    if (size <= 0) {
        ogs_error("ogs_gtp2_build_f_container() failed");
        return NULL;
    }

    /* Target Identification */
    req->target_identification.presence = 1;
    size = ogs_gtp2_build_target_identification(&req->target_identification,
            target, target_id_buf, sizeof(target_id_buf));
    if (size <= 0) {
        ogs_error("ogs_gtp2_build_target_identification() failed");
        return NULL;
    }

    /* MME/SGSN/AMF UE MM Context (mandatory, TS 29.274 Table 7.3.1-1) */
    fill_mm_context(&mm_ctx, mme_ue);
    len = mme_s10_encode_mm_context(&mm_ctx, mm_ctx_buf, sizeof(mm_ctx_buf));
    if (len <= 0) {
        ogs_error("mme_s10_encode_mm_context() failed");
        return NULL;
    }
    req->mme_sgsn_amf_ue_mm_context.presence = 1;
    req->mme_sgsn_amf_ue_mm_context.data = mm_ctx_buf;
    req->mme_sgsn_amf_ue_mm_context.len = len;

    /* S1-AP Cause */
    req->s1_ap_cause.presence = 1;
    size = ogs_gtp2_build_f_cause(&req->s1_ap_cause,
            s1ap_cause, f_cause_buf, sizeof(f_cause_buf));
    if (size <= 0) {
        ogs_error("ogs_gtp2_build_f_cause() failed");
        return NULL;
    }

    gtp_message.h.type = type;
    return ogs_gtp2_build_msg(&gtp_message);
}

ogs_pkbuf_t *mme_s10_build_forward_relocation_response(
        uint8_t type, uint8_t cause_value)
{
    ogs_gtp2_message_t gtp_message;
    ogs_gtp2_forward_relocation_response_t *rsp =
        &gtp_message.forward_relocation_response;
    ogs_gtp2_cause_t cause;

    ogs_debug("Forward Relocation Response");

    memset(&gtp_message, 0, sizeof(ogs_gtp2_message_t));
    memset(&cause, 0, sizeof(cause));

    /* Cause is the only mandatory IE of a rejection */
    cause.value = cause_value;
    rsp->cause.presence = 1;
    rsp->cause.len = sizeof(cause);
    rsp->cause.data = &cause;

    gtp_message.h.type = type;
    return ogs_gtp2_build_msg(&gtp_message);
}

/*
 * Target MME: positive Forward Relocation Response (TS 23.401 5.5.1.2.2
 * step 7, TS 29.274 Table 7.3.2-1). Sent once the target eNB has
 * acknowledged the Handover Request.
 */
ogs_pkbuf_t *mme_s10_build_forward_relocation_response_accept(
        uint8_t type, mme_ue_t *mme_ue)
{
    int rv, len, i;
    int16_t size;
    ogs_gtp2_message_t gtp_message;
    ogs_gtp2_forward_relocation_response_t *rsp =
        &gtp_message.forward_relocation_response;
    ogs_gtp2_cause_t cause;
    ogs_gtp2_f_teid_t mme_s10_teid;
    ogs_gtp2_f_container_t f_container;
    uint8_t f_container_buf[OGS_MAX_SDU_LEN];
    ogs_gtp2_f_cause_t f_cause;
    uint8_t f_cause_buf[S10_F_CAUSE_BUF_LEN];
    mme_sess_t *sess = NULL;
    mme_bearer_t *bearer = NULL;
    ogs_gtp2_f_teid_t dl_fwd[OGS_BEARER_PER_UE], ul_fwd[OGS_BEARER_PER_UE];
    int dl_len, ul_len;

    ogs_assert(mme_ue);

    if (!mme_ue->container.buf || !mme_ue->container.size) {
        ogs_error("No Target to Source Transparent Container");
        return NULL;
    }
    if (mme_ue->container.size + 1 > sizeof(f_container_buf)) {
        ogs_error("Transparent container too large [%d]",
                (int)mme_ue->container.size);
        return NULL;
    }

    memset(&gtp_message, 0, sizeof(ogs_gtp2_message_t));

    /* Cause */
    memset(&cause, 0, sizeof(cause));
    cause.value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;
    rsp->cause.presence = 1;
    rsp->cause.len = sizeof(cause);
    rsp->cause.data = &cause;

    /* Sender F-TEID for Control Plane: our S10 TEID for this UE */
    memset(&mme_s10_teid, 0, sizeof(ogs_gtp2_f_teid_t));
    mme_s10_teid.interface_type = OGS_GTP2_F_TEID_S10_MME_GTP_C;
    mme_s10_teid.teid = htobe32(mme_ue->mme_s11_teid);
    rv = ogs_gtp2_sockaddr_to_f_teid(
            ogs_gtp_self()->gtpc_addr, ogs_gtp_self()->gtpc_addr6,
            &mme_s10_teid, &len);
    if (rv != OGS_OK) {
        ogs_error("No local GTP-C address for the Sender F-TEID");
        return NULL;
    }
    rsp->sender_s_f_teid_for_control_plane.presence = 1;
    rsp->sender_s_f_teid_for_control_plane.data = &mme_s10_teid;
    rsp->sender_s_f_teid_for_control_plane.len = len;

    /*
     * List of Set-up Bearers: the EBIs the target eNB admitted, each with
     * the F-TEIDs the source side forwards data to:
     *   indirect forwarding: target SGW tunnels from step 6a
     *   direct forwarding:   the target eNB's forwarding F-TEIDs
     * Instance 0 carries the DL, instance 1 the UL forwarding F-TEID; the
     * interface type says which node it is.
     */
    i = 0;
    ogs_list_for_each(&mme_ue->sess_list, sess) {
        ogs_list_for_each(&sess->bearer_list, bearer) {
            uint32_t dl_teid = 0, ul_teid = 0;
            ogs_ip_t *dl_ip = NULL, *ul_ip = NULL;
            uint8_t dl_if = 0, ul_if = 0;

            if (!bearer->enb_s1u_teid)
                continue;               /* not admitted */
            if (i >= OGS_BEARER_PER_UE)
                break;
            rsp->list_of_set_up_bearers[i].presence = 1;
            rsp->list_of_set_up_bearers[i].eps_bearer_id.presence = 1;
            rsp->list_of_set_up_bearers[i].eps_bearer_id.u8 = bearer->ebi;

            if (mme_ue->s10.direct_forwarding) {
                dl_teid = bearer->enb_dl_teid; dl_ip = &bearer->enb_dl_ip;
                dl_if = OGS_GTP2_F_TEID_ENODEB_GTP_U_FOR_DL_DATA_FORWARDING;
                ul_teid = bearer->enb_ul_teid; ul_ip = &bearer->enb_ul_ip;
                ul_if = OGS_GTP2_F_TEID_ENODEB_GTP_U_FOR_UL_DATA_FORWARDING;
            } else {
                dl_teid = bearer->sgw_dl_teid; dl_ip = &bearer->sgw_dl_ip;
                dl_if = OGS_GTP2_F_TEID_SGW_GTP_U_FOR_DL_DATA_FORWARDING;
                ul_teid = bearer->sgw_ul_teid; ul_ip = &bearer->sgw_ul_ip;
                ul_if = OGS_GTP2_F_TEID_SGW_GTP_U_FOR_UL_DATA_FORWARDING;
            }

            if (dl_teid) {
                memset(&dl_fwd[i], 0, sizeof(dl_fwd[i]));
                dl_fwd[i].interface_type = dl_if;
                dl_fwd[i].teid = htobe32(dl_teid);
                if (ogs_gtp2_ip_to_f_teid(dl_ip, &dl_fwd[i], &dl_len) ==
                        OGS_OK) {
                    rsp->list_of_set_up_bearers[i].
                        s1_u_enodeb_f_teid.presence = 1;
                    rsp->list_of_set_up_bearers[i].
                        s1_u_enodeb_f_teid.data = &dl_fwd[i];
                    rsp->list_of_set_up_bearers[i].
                        s1_u_enodeb_f_teid.len = dl_len;
                }
            }
            if (ul_teid) {
                memset(&ul_fwd[i], 0, sizeof(ul_fwd[i]));
                ul_fwd[i].interface_type = ul_if;
                ul_fwd[i].teid = htobe32(ul_teid);
                if (ogs_gtp2_ip_to_f_teid(ul_ip, &ul_fwd[i], &ul_len) ==
                        OGS_OK) {
                    rsp->list_of_set_up_bearers[i].
                        s4_u_sgsn_f_teid.presence = 1;
                    rsp->list_of_set_up_bearers[i].
                        s4_u_sgsn_f_teid.data = &ul_fwd[i];
                    rsp->list_of_set_up_bearers[i].
                        s4_u_sgsn_f_teid.len = ul_len;
                }
            }
            i++;
        }
    }

    /* S1-AP Cause: echoed back */
    memset(&f_cause, 0, sizeof(f_cause));
    f_cause = mme_ue->s10.s1ap_cause;
    rsp->s1_ap_cause.presence = 1;
    size = ogs_gtp2_build_f_cause(&rsp->s1_ap_cause,
            &f_cause, f_cause_buf, sizeof(f_cause_buf));
    if (size <= 0) {
        ogs_error("ogs_gtp2_build_f_cause() failed");
        return NULL;
    }

    /* E-UTRAN Transparent Container (Target to Source) */
    memset(&f_container, 0, sizeof(f_container));
    f_container.container_type =
        OGS_GTP2_F_CONTAINER_TYPE_E_UTRAN_TRANSPARENT_CONTAINER;
    f_container.data = mme_ue->container.buf;
    f_container.len = mme_ue->container.size;
    rsp->e_utran_transparent_container.presence = 1;
    size = ogs_gtp2_build_f_container(&rsp->e_utran_transparent_container,
            &f_container, f_container_buf, sizeof(f_container_buf));
    if (size <= 0) {
        ogs_error("ogs_gtp2_build_f_container() failed");
        return NULL;
    }

    gtp_message.h.type = type;
    return ogs_gtp2_build_msg(&gtp_message);
}

/*
 * Source MME -> target MME, TS 23.401 5.5.1.2.2 step 10 / TS 29.274 7.3.5:
 * the eNB Status Transfer Transparent Container (TS 36.413, APER encoded)
 * in an E-UTRAN Transparent Container F-Container.
 */
ogs_pkbuf_t *mme_s10_build_forward_access_context_notification(
        uint8_t type, const uint8_t *container, int container_len)
{
    int16_t size;
    ogs_gtp2_message_t gtp_message;
    ogs_gtp2_forward_access_context_notification_t *req =
        &gtp_message.forward_access_context_notification;
    ogs_gtp2_f_container_t f_container;
    uint8_t f_container_buf[OGS_MAX_SDU_LEN];

    ogs_assert(container);

    if (container_len <= 0 || container_len + 1 > sizeof(f_container_buf)) {
        ogs_error("Invalid eNB Status Transfer container length [%d]",
                container_len);
        return NULL;
    }

    memset(&gtp_message, 0, sizeof(ogs_gtp2_message_t));

    memset(&f_container, 0, sizeof(f_container));
    f_container.container_type =
        OGS_GTP2_F_CONTAINER_TYPE_E_UTRAN_TRANSPARENT_CONTAINER;
    f_container.data = (uint8_t *)container;
    f_container.len = container_len;
    req->e_utran_transparent_container.presence = 1;
    size = ogs_gtp2_build_f_container(&req->e_utran_transparent_container,
            &f_container, f_container_buf, sizeof(f_container_buf));
    if (size <= 0) {
        ogs_error("ogs_gtp2_build_f_container() failed");
        return NULL;
    }

    gtp_message.h.type = type;
    return ogs_gtp2_build_msg(&gtp_message);
}

ogs_pkbuf_t *mme_s10_build_forward_access_context_acknowledge(
        uint8_t type, uint8_t cause_value)
{
    ogs_gtp2_message_t gtp_message;
    ogs_gtp2_forward_access_context_acknowledge_t *rsp =
        &gtp_message.forward_access_context_acknowledge;
    ogs_gtp2_cause_t cause;

    memset(&gtp_message, 0, sizeof(ogs_gtp2_message_t));

    memset(&cause, 0, sizeof(cause));
    cause.value = cause_value;
    rsp->cause.presence = 1;
    rsp->cause.len = sizeof(cause);
    rsp->cause.data = &cause;

    gtp_message.h.type = type;
    return ogs_gtp2_build_msg(&gtp_message);
}

/* Target MME -> source MME, step 14 (TS 29.274 7.3.3): no mandatory IE */
ogs_pkbuf_t *mme_s10_build_forward_relocation_complete_notification(
        uint8_t type)
{
    ogs_gtp2_message_t gtp_message;
    ogs_gtp2_forward_relocation_complete_notification_t *req =
        &gtp_message.forward_relocation_complete_notification;
    ogs_gtp2_indication_t indication;

    memset(&gtp_message, 0, sizeof(ogs_gtp2_message_t));

    /*
     * Indication is the message's only (optional) IE; the TLV encoder
     * cannot build a message without any IE, so send it with no flag set.
     */
    memset(&indication, 0, sizeof(indication));
    req->indication_flags.presence = 1;
    req->indication_flags.data = &indication;
    req->indication_flags.len = sizeof(indication);

    gtp_message.h.type = type;
    return ogs_gtp2_build_msg(&gtp_message);
}

ogs_pkbuf_t *mme_s10_build_forward_relocation_complete_acknowledge(
        uint8_t type, uint8_t cause_value)
{
    ogs_gtp2_message_t gtp_message;
    ogs_gtp2_forward_relocation_complete_acknowledge_t *rsp =
        &gtp_message.forward_relocation_complete_acknowledge;
    ogs_gtp2_cause_t cause;

    memset(&gtp_message, 0, sizeof(ogs_gtp2_message_t));

    memset(&cause, 0, sizeof(cause));
    cause.value = cause_value;
    rsp->cause.presence = 1;
    rsp->cause.len = sizeof(cause);
    rsp->cause.data = &cause;

    gtp_message.h.type = type;
    return ogs_gtp2_build_msg(&gtp_message);
}
