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

#ifndef MME_S10_HANDLER_H
#define MME_S10_HANDLER_H

#include "mme-context.h"

#ifdef __cplusplus
extern "C" {
#endif

/* One PDN connection of a Forward Relocation Request, validated and decoded */
/* A dedicated bearer of a relocated PDN connection (e.g. QCI 1 for voice) */
typedef struct mme_s10_reloc_bearer_s {
    uint8_t     ebi;
    ogs_qos_t   qos;                    /* QCI, ARP, MBR/GBR in bps */
    bool        have_sgw_s1u, have_pgw_s5u;
    ogs_ip_t    sgw_s1u_ip, pgw_s5u_ip;
    uint32_t    sgw_s1u_teid, pgw_s5u_teid;
    uint8_t     tft[OGS_GTP2_MAX_TRAFFIC_FLOW_TEMPLATE];
    int         tft_len;
} mme_s10_reloc_bearer_t;

#define MME_S10_MAX_DEDICATED   (OGS_BEARER_PER_UE - 1)

typedef struct mme_s10_reloc_pdn_s {
    char        apn[OGS_MAX_APN_LEN+1];
    uint8_t     ebi;                    /* default bearer EBI, kept as is */
    uint8_t     qci, arp, pre_emption_capability, pre_emption_vulnerability;
    uint32_t    ambr_ul_kbps, ambr_dl_kbps;
    uint32_t    ue_ipv4;                /* network byte order, kept as is */
    /* identifiers on the source side, for the map only */
    bool        have_pgw_s5c, have_sgw_s1u, have_pgw_s5u;
    ogs_ip_t    pgw_s5c_ip, sgw_s1u_ip, pgw_s5u_ip;
    uint32_t    pgw_s5c_teid, sgw_s1u_teid, pgw_s5u_teid;

    /* dedicated bearers of this PDN connection */
    int         num_dedicated;
    mme_s10_reloc_bearer_t dedicated[MME_S10_MAX_DEDICATED];
} mme_s10_reloc_pdn_t;

/*
 * Validate and decode the PDN Connections of a Forward Relocation Request.
 * Returns the number of PDN connections, or -1 if the request cannot be
 * served (the reason is logged). EBIs, APN, UE IP and QoS are taken over
 * unchanged, dedicated bearers (EBI, QoS, TFT) included. IPv6-only
 * sessions are not supported yet.
 */
int mme_s10_parse_relocation_pdns(
        ogs_gtp2_forward_relocation_request_t *req,
        mme_s10_reloc_pdn_t *out, int max);

/* Target MME: a peer MME asks to relocate a UE to one of our eNBs */
void mme_s10_handle_forward_relocation_request(
        ogs_gtp_xact_t *xact, ogs_gtp2_forward_relocation_request_t *req);

/* Decode and log the PDN Connections carried by a Forward Relocation Request */
void mme_s10_log_pdn_connections(ogs_gtp2_forward_relocation_request_t *req);

/* Source MME: answer from the target MME to our request */
void mme_s10_handle_forward_relocation_response(
        ogs_gtp_xact_t *xact, ogs_gtp2_forward_relocation_response_t *rsp);

/* Target MME: steps 4a to 7, and failure handling */
void mme_s10_target_session_created(enb_ue_t *target_ue, mme_ue_t *mme_ue);
void mme_s10_target_sessions_created(enb_ue_t *target_ue, mme_ue_t *mme_ue);
bool mme_s10_handle_handover_request_ack(
        enb_ue_t *target_ue, uint32_t enb_ue_s1ap_id,
        S1AP_E_RABAdmittedList_t *E_RABAdmittedList,
        S1AP_Target_ToSource_TransparentContainer_t *container);
bool mme_s10_handle_handover_failure(enb_ue_t *target_ue);
bool mme_s10_handle_handover_notify(enb_ue_t *target_ue,
        S1AP_TAI_t *TAI, S1AP_EUTRAN_CGI_t *EUTRAN_CGI);
void mme_s10_target_handover_complete(enb_ue_t *target_ue, mme_ue_t *mme_ue);
void mme_s10_handle_forward_relocation_complete_notification(
        ogs_gtp_xact_t *xact, uint32_t teid,
        ogs_gtp2_forward_relocation_complete_notification_t *req);
void mme_s10_handle_forward_relocation_complete_acknowledge(
        ogs_gtp_xact_t *xact,
        ogs_gtp2_forward_relocation_complete_acknowledge_t *rsp);
void mme_s10_source_release_sessions(mme_ue_t *mme_ue);
void mme_s10_target_fail(mme_ue_t *mme_ue, uint8_t cause_value,
        const char *reason);
void mme_s10_target_cleanup_done(mme_ue_t *mme_ue);

/* Step 10: eNB Status Transfer over S10 */
bool mme_s10_handle_enb_status_transfer(enb_ue_t *source_ue,
        S1AP_ENB_StatusTransfer_TransparentContainer_t *container);
void mme_s10_handle_forward_access_context_notification(
        ogs_gtp_xact_t *xact, uint32_t teid,
        ogs_gtp2_forward_access_context_notification_t *req);
void mme_s10_handle_forward_access_context_acknowledge(
        ogs_gtp_xact_t *xact, ogs_gtp2_forward_access_context_acknowledge_t *rsp);
void mme_s10_source_handle_create_indirect_data_forwarding_tunnel_response(
        enb_ue_t *source_ue, mme_ue_t *mme_ue, mme_ue_t *mme_ue_from_teid,
        ogs_gtp2_create_indirect_data_forwarding_tunnel_response_t *rsp);
void mme_s10_handle_create_indirect_data_forwarding_tunnel_response(
        mme_ue_t *mme_ue, mme_ue_t *mme_ue_from_teid,
        ogs_gtp2_create_indirect_data_forwarding_tunnel_response_t *rsp);

#ifdef __cplusplus
}
#endif

#endif /* MME_S10_HANDLER_H */
