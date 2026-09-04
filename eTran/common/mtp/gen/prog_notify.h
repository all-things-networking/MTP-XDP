/* GENERATED from /tmp/claude-11465/-home-mtahmasb-mtp-xdp-session-tmp-mtp-pass/ef347694-90cd-4c3c-80ee-6c5e3721d8a4/scratchpad/src/tcp-newconv.mtp by the MTP compiler's XDP backend.
 * Do not edit: regenerate. The target runtime this is compiled against
 * (mtp_target.h, mtp_target_bpf.h) is NOT generated and is not touched.
 */

#pragma once

/* Every condition this program notifies with. See instrCall. */
enum mtp_notify_cond {
    MTP_NOTIFY_ACCEPTED,
    MTP_NOTIFY_BOUND,
    MTP_NOTIFY_CLOSED,
    MTP_NOTIFY_CONNECTING,
    MTP_NOTIFY_CONN_OPEN_OK,
    MTP_NOTIFY_LISTENING,
    MTP_NOTIFY_NEW_CONN,
    MTP_NOTIFY_PEER_RESET,
};
