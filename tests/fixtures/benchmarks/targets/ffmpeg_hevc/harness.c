/*
 * LibFuzzer harness for CVE-2022-3341 — FFmpeg HEVC OOB read
 */
#include <stdint.h>
#include <stddef.h>
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    AVCodecContext *ctx = avcodec_alloc_context3(avcodec_find_decoder(AV_CODEC_ID_HEVC));
    if (!ctx) return 0;
    if (avcodec_open2(ctx, avcodec_find_decoder(AV_CODEC_ID_HEVC), NULL) < 0) {
        avcodec_free_context(&ctx);
        return 0;
    }
    AVPacket *pkt = av_packet_alloc();
    av_packet_from_data(pkt, (uint8_t*)data, (int)size);
    AVFrame *frame = av_frame_alloc();
    int got = 0;
    avcodec_decode_video2(ctx, frame, &got, pkt);
    av_frame_free(&frame);
    av_packet_free(&pkt);
    avcodec_free_context(&ctx);
    return 0;
}
