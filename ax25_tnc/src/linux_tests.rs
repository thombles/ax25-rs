#[cfg(test)]
mod platform_agnostic_linux_tests {
    #[test]
    fn test_receive_frame_null_filtering_edge_cases() {
        // Case 1: All zeros
        let all_zeros = [0, 0, 0, 0];
        let filtered: Vec<u8> = all_zeros.iter().skip_while(|&&c| c == 0).cloned().collect();
        assert!(filtered.is_empty());

        // Case 2: No leading zeros
        let no_zeros = [0x51, 0x52, 0, 0];
        let filtered: Vec<u8> = no_zeros.iter().skip_while(|&&c| c == 0).cloned().collect();
        assert_eq!(filtered, vec![0x51, 0x52, 0, 0]);

        // Case 3: Mixed zeroes with embedded zeroes
        let mixed = [0, 0, 0x41, 0, 0x42];
        let filtered: Vec<u8> = mixed.iter().skip_while(|&&c| c == 0).cloned().collect();
        assert_eq!(filtered, vec![0x41, 0, 0x42]);
    }

    #[test]
    fn test_send_frame_prefixed_buffer_logic() {
        // Replicating the exact packet prefixing logic from socket_send_frame
        let frame = [0xAE, 0xBE, 0xCE];
        let mut prefixed_frame: Vec<u8> = Vec::with_capacity(frame.len() + 1);
        prefixed_frame.push(0);
        prefixed_frame.extend(frame.iter().cloned());

        assert_eq!(prefixed_frame.len(), 4);
        assert_eq!(prefixed_frame[0], 0);
        assert_eq!(&prefixed_frame[1..], &[0xAE, 0xBE, 0xCE]);
    }
}
