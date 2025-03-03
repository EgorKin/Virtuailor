import idc
import idautils


def get_segment_ranges(segment_names):
    segment_ranges = []
    for s in idautils.Segments():
        if idc.SegName(s) in segment_names:
            segment_ranges.append((idc.SegStart(s), idc.SegEnd(s)))
    return segment_ranges
