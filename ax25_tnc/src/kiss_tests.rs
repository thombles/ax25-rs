use super::*;

#[test]
fn test_normal_frame() {
    let mut rx = vec![FEND, 0x01, 0x02, FEND];
    assert_eq!(make_frame_from_buffer(&mut rx), Some(vec![0x01, 0x02]));
    assert_eq!(rx, vec![FEND]);
}

#[test]
fn test_trailing_data() {
    let mut rx = vec![FEND, 0x01, 0x02, FEND, 0x03, 0x04];
    assert_eq!(make_frame_from_buffer(&mut rx), Some(vec![0x01, 0x02]));
    assert_eq!(rx, vec![FEND, 0x03, 0x04]);
}

#[test]
fn test_leading_data() {
    let mut rx = vec![0x03, 0x04, FEND, 0x01, 0x02, FEND];
    assert_eq!(make_frame_from_buffer(&mut rx), Some(vec![0x01, 0x02]));
    assert_eq!(rx, vec![FEND]);
}

#[test]
fn test_consecutive_marker() {
    let mut rx = vec![FEND, FEND, FEND, 0x01, 0x02, FEND];
    assert_eq!(make_frame_from_buffer(&mut rx), Some(vec![0x01, 0x02]));
    assert_eq!(rx, vec![FEND]);
}

#[test]
fn test_escapes() {
    let mut rx = vec![FEND, 0x01, FESC, TFESC, 0x02, FESC, TFEND, 0x03, FEND];
    assert_eq!(
        make_frame_from_buffer(&mut rx),
        Some(vec![0x01, FESC, 0x02, FEND, 0x03])
    );
    assert_eq!(rx, vec![FEND]);
}

#[test]
fn test_incorrect_escape_skipped() {
    let mut rx = vec![
        FEND, 0x01, FESC, 0x04, TFESC, /* passes normally without leading FESC */
        0x02, FEND,
    ];
    assert_eq!(
        make_frame_from_buffer(&mut rx),
        Some(vec![0x01, TFESC, 0x02])
    );
    assert_eq!(rx, vec![FEND]);
}

#[test]
fn test_two_frames_single_fend() {
    let mut rx = vec![FEND, 0x01, 0x02, FEND, 0x03, 0x04, FEND];
    assert_eq!(make_frame_from_buffer(&mut rx), Some(vec![0x01, 0x02]));
    assert_eq!(make_frame_from_buffer(&mut rx), Some(vec![0x03, 0x04]));
    assert_eq!(rx, vec![FEND]);
}

#[test]
fn test_two_frames_double_fend() {
    let mut rx = vec![FEND, 0x01, 0x02, FEND, FEND, 0x03, 0x04, FEND];
    assert_eq!(make_frame_from_buffer(&mut rx), Some(vec![0x01, 0x02]));
    assert_eq!(make_frame_from_buffer(&mut rx), Some(vec![0x03, 0x04]));
    assert_eq!(rx, vec![FEND]);
}

#[test]
fn test_empty_frame_handling() {
    // [empty_frame_handling](ca://s?q=Generate_empty_frame_handling_test)
    // Two FENDs in a row → zero-length frame → should be ignored.
    let mut rx = vec![FEND, FEND];
    assert_eq!(make_frame_from_buffer(&mut rx), None);
    assert_eq!(rx, vec![FEND, FEND]);
}

#[test]
fn test_frame_with_only_escape_sequence() {
    // [frame_with_only_escape_sequence](ca://s?q=Generate_frame_with_only_escape_sequence_test)
    // FEND, FESC, TFEND, FEND → frame = [FEND]
    let mut rx = vec![FEND, FESC, TFEND, FEND];
    assert_eq!(make_frame_from_buffer(&mut rx), Some(vec![FEND]));
    assert_eq!(rx, vec![FEND]);
}

#[test]
fn test_unterminated_escape_at_end() {
    // [unterminated_escape_at_end](ca://s?q=Generate_unterminated_escape_at_end_test)
    // Escape at end should not panic and should wait for more data.
    let mut rx = vec![FEND, 0x01, FESC];
    assert_eq!(make_frame_from_buffer(&mut rx), None);
    assert_eq!(rx, vec![FEND, 0x01, FESC]);
}

#[test]
fn test_unterminated_frame() {
    // [unterminated_frame](ca://s?q=Generate_unterminated_frame_test)
    // No closing FEND → no frame returned.
    let mut rx = vec![FEND, 0x01, 0x02];
    assert_eq!(make_frame_from_buffer(&mut rx), None);
    assert_eq!(rx, vec![FEND, 0x01, 0x02]);
}

#[test]
fn test_back_to_back_frames_no_gap() {
    // [multiple_frames_back_to_back_no_gap](ca://s?q=Generate_back_to_back_frames_test)
    let mut rx = vec![FEND, 1, FEND, FEND, 2, FEND];
    assert_eq!(make_frame_from_buffer(&mut rx), Some(vec![1]));
    assert_eq!(make_frame_from_buffer(&mut rx), Some(vec![2]));
    assert_eq!(rx, vec![FEND]);
}

#[test]
fn test_garbage_between_frames() {
    let mut rx = vec![FEND, 1, FEND, 0x99, 0x88, FEND, 2, FEND];
    assert_eq!(make_frame_from_buffer(&mut rx), Some(vec![1]));
    // The parser processes the garbage block next if it's bounded by FEND
    assert_eq!(make_frame_from_buffer(&mut rx), Some(vec![0x99, 0x88]));
    assert_eq!(make_frame_from_buffer(&mut rx), Some(vec![2]));
    assert_eq!(rx, vec![FEND]);
}

#[test]
fn test_escape_followed_by_fend() {
    // [escape_followed_by_fend](ca://s?q=Generate_escape_followed_by_fend_test)
    // FESC + FEND inside frame ends frame if possible_frame is non-empty.
    let mut rx = vec![FEND, 0x01, FESC, FEND];
    assert_eq!(make_frame_from_buffer(&mut rx), Some(vec![0x01]));
    assert_eq!(rx, vec![FEND]);
}

#[test]
fn test_buffer_drain_correctness() {
    // [buffer_drain_correctness](ca://s?q=Generate_buffer_drain_correctness_test)
    let mut rx = vec![FEND, 1, 2, FEND, 0xAA, 0xBB];
    assert_eq!(make_frame_from_buffer(&mut rx), Some(vec![1, 2]));
    assert_eq!(rx, vec![FEND, 0xAA, 0xBB]);
}

#[test]
fn test_large_frame() {
    // Avoid generating 0xC0 (FEND) inside the payload data
    let frame: Vec<u8> = (0..1000).map(|x| (x % 150) as u8).collect();
    let mut rx = vec![FEND];
    rx.extend(frame.clone());
    rx.push(FEND);

    assert_eq!(make_frame_from_buffer(&mut rx), Some(frame));
    assert_eq!(rx, vec![FEND]);
}

#[test]
fn test_embedded_fend_escape() {
    // [frame_with_embedded_fend_via_escape](ca://s?q=Generate_embedded_fend_escape_test)
    let mut rx = vec![FEND, 0x01, FESC, TFEND, 0x02, FEND];
    assert_eq!(
        make_frame_from_buffer(&mut rx),
        Some(vec![0x01, FEND, 0x02])
    );
    assert_eq!(rx, vec![FEND]);
}

#[test]
fn test_invalid_escape_sequence() {
    let mut rx = vec![FEND, 0x01, FESC, 0x99, 0x02, FEND];
    // The parser drops the invalid escape continuation byte (0x99)
    assert_eq!(make_frame_from_buffer(&mut rx), Some(vec![0x01, 0x02]));
    assert_eq!(rx, vec![FEND]);
}

#[test]
fn test_frame_start_without_fend() {
    // [frame_start_without_fend](ca://s?q=Generate_frame_start_without_fend_test)
    let mut rx = vec![0x01, 0x02, FEND, 0x03, FEND];
    assert_eq!(make_frame_from_buffer(&mut rx), Some(vec![0x03]));
    assert_eq!(rx, vec![FEND]);
}

#[test]
fn test_double_escape_sequence() {
    let mut rx = vec![FEND, 0x01, FESC, FESC, 0x02, FEND];
    // The parser drops the second dangling/invalid escape continuation byte
    assert_eq!(make_frame_from_buffer(&mut rx), Some(vec![0x01, 0x02]));
    assert_eq!(rx, vec![FEND]);
}

#[test]
fn test_multiple_escapes_in_one_frame() {
    let mut rx = vec![FEND, 0x01, FESC, TFEND, FESC, TFESC, 0x02, FEND];
    assert_eq!(
        make_frame_from_buffer(&mut rx),
        Some(vec![0x01, FEND, FESC, 0x02])
    );
    assert_eq!(rx, vec![FEND]);
}

#[test]
fn test_buffer_starting_mid_escape() {
    // Suppose the previous read ended on FESC, and the next chunk starts with TFEND
    let mut rx = vec![FESC, TFEND, 0x01, FEND];
    // Since there's no opening FEND, the state machine is looking for start marker,
    // so FESC/TFESC outside of a frame should be ignored or handled gracefully.
    assert_eq!(make_frame_from_buffer(&mut rx), None);
}

#[test]
fn test_empty_frame_between_valid_frames() {
    let mut rx = vec![FEND, FEND, 0x01, 0x02, FEND];
    // First FEND + FEND is zero-length, should be skipped or return None until the real frame hits
    assert_eq!(make_frame_from_buffer(&mut rx), Some(vec![0x01, 0x02]));
    assert_eq!(rx, vec![FEND]);
}

#[test]
fn test_incremental_buffer_feeding() {
    let mut rx = vec![FEND, 0x01, 0x02]; // Missing closing FEND
    assert_eq!(make_frame_from_buffer(&mut rx), None);

    // Simulate more bytes arriving in the next read loop
    rx.push(0x03);
    rx.push(FEND);
    assert_eq!(
        make_frame_from_buffer(&mut rx),
        Some(vec![0x01, 0x02, 0x03])
    );
    assert_eq!(rx, vec![FEND]);
}
