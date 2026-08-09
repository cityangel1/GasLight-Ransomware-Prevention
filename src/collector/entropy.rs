/// Computes the Shannon entropy (bits per byte, range 0.0–8.0) of a byte
/// slice. Plain text and typical office documents usually sit around
/// 2.0–5.5. Encrypted or compressed content pushes close to the 8.0 ceiling
/// because byte values become close to uniformly distributed.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Reads up to `sample_bytes` from the start of a file and returns its
/// Shannon entropy. Sampling (rather than reading whole multi-GB files)
/// keeps the file monitor's overhead predictable.
pub fn entropy_of_file(path: &std::path::Path, sample_bytes: usize) -> std::io::Result<f64> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut buf = vec![0u8; sample_bytes];
    let n = file.read(&mut buf)?;
    buf.truncate(n);
    Ok(shannon_entropy(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_data_has_zero_entropy() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn uniform_repeated_byte_has_zero_entropy() {
        let data = vec![0x41u8; 1000];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn fully_random_looking_data_is_near_max_entropy() {
        // A 256-byte buffer containing each possible byte value exactly
        // once has maximal entropy (exactly 8.0 bits/byte).
        let data: Vec<u8> = (0u8..=255).collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.99 && e <= 8.0);
    }
}
