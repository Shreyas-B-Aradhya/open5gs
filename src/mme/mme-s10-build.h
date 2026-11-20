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

#ifndef MME_S10_BUILD_H
#define MME_S10_BUILD_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Forward Relocation Request (TS 29.274 clause 7.3.1), source MME -> target MME.
 *
 * Carries IMSI, Sender F-TEID (S10), SGW S11 F-TEID, the PDN Connections
 * (one per session), E-UTRAN Transparent Container, Target Identification
 * and S1-AP Cause. The MM Context IE is mandatory in the specification but
 * is not built yet.
 */
ogs_pkbuf_t *mme_s10_build_forward_relocation_request(
        uint8_t type, mme_ue_t *mme_ue, sgw_ue_t *sgw_ue,
        ogs_gtp2_target_identification_t *target,
        ogs_gtp2_f_cause_t *s1ap_cause,
        const uint8_t *container, uint16_t container_len);

/*
 * Forward Relocation Response (TS 29.274 clause 7.3.2) carrying only a Cause.
 * Used by the target MME to reject a relocation.
 */
ogs_pkbuf_t *mme_s10_build_forward_relocation_response(
        uint8_t type, uint8_t cause_value);

ogs_pkbuf_t *mme_s10_build_forward_relocation_response_accept(
        uint8_t type, mme_ue_t *mme_ue);

ogs_pkbuf_t *mme_s10_build_forward_access_context_notification(
        uint8_t type, const uint8_t *container, int container_len);
ogs_pkbuf_t *mme_s10_build_forward_access_context_acknowledge(
        uint8_t type, uint8_t cause_value);
ogs_pkbuf_t *mme_s10_build_forward_relocation_complete_notification(
        uint8_t type);
ogs_pkbuf_t *mme_s10_build_forward_relocation_complete_acknowledge(
        uint8_t type, uint8_t cause_value);

#ifdef __cplusplus
}
#endif

#endif /* MME_S10_BUILD_H */
