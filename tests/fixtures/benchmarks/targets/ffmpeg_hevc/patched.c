/*
 * FFmpeg HEVC Out-of-Bounds Read Patched — CVE-2022-3341 fix
 *
 * Fix: Validate slice_segment_address before use.
 */
#include "hevc.h"

static int hevc_parse_slice_header_patched(HEVCContext *s, HEVCNAL *nal) {
    SliceHeader *sh = &s->sh;
    sh->slice_segment_address = get_ue_golomb(&s->HEVClc->gb);
    /* FIX: bounds check against picture CTU count */
    int ctb_count = s->ps.sps->ctb_width * s->ps.sps->ctb_height;
    if (sh->slice_segment_address >= ctb_count) {
        av_log(s->avctx, AV_LOG_ERROR,
               "slice_segment_address %d out of range [0, %d)\n",
               sh->slice_segment_address, ctb_count);
        return AVERROR_INVALIDDATA;
    }
    sh->dependent_slice_segment_flag = s->pps->dependent_slice_segments_enabled_flag;
    return 0;
}
