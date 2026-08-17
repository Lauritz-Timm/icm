pub(crate) const WORKING_DIRECTORY_HEADER: &str = "x-icm-working-directory";

pub(crate) fn encode_working_directory(directory: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(directory.len() * 2);
    for byte in directory.bytes() {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
