/*
 * FFmpeg HEVC Out-of-Bounds Read — CVE-2022-3341
 * Vulnerable version: FFmpeg 5.1
 *
 * Root cause: hevc_parse_slice_header() does not validate NAL unit
 * slice_segment_address against the number of CTUs in the picture,
 * causing an OOB read when the value exceeds the picture boundary.
 */
#include "hevc.h"

static int hevc_parse_slice_header_vulnerable(HEVCContext *s, HEVCNAL *nal) {
    SliceHeader *sh = &s->sh;
    /* VULNERABILITY: no upper-bound check on slice_segment_address */
    sh->slice_segment_address = get_ue_golomb(&s->HEVClc->gb);
    /* OOB: if slice_segment_address >= s->ps.sps->ctb_width * ctb_height */
    sh->dependent_slice_segment_flag = s->pps->dependent_slice_segments_enabled_flag;
    return 0;
}
