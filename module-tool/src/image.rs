//! Reading the kernel out of a boot image and the symbol list out of System.map.
use std::io::Read;

pub type Res<T> = Result<T, String>;

fn read_all(mut reader: impl Read) -> Res<Vec<u8>> {
    let mut data = Vec::new();
    reader
        .read_to_end(&mut data)
        .map_err(|error| format!("The boot image payload does not decompress: {error}"))?;
    Ok(data)
}

/// Decompresses a boot image payload; the kernel appends a size word after the stream.
pub fn decompress_payload(data: &[u8]) -> Res<Vec<u8>> {
    if data.starts_with(&[0x1f, 0x8b]) {
        return read_all(flate2::read::GzDecoder::new(data));
    }
    if data.starts_with(b"\xfd7zXZ\x00") {
        return read_all(liblzma::read::XzDecoder::new(data));
    }
    if data.first() == Some(&b']') || data.starts_with(&[0x5d, 0x00, 0x00]) {
        let stream = liblzma::stream::Stream::new_lzma_decoder(u64::MAX)
            .map_err(|error| error.to_string())?;
        return read_all(liblzma::read::XzDecoder::new_stream(data, stream));
    }
    if data.starts_with(b"BZh") {
        return read_all(bzip2::read::BzDecoder::new(data));
    }
    if data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        let decoder = zstd::stream::read::Decoder::new(data)
            .map_err(|error| error.to_string())?
            .single_frame();
        return read_all(decoder);
    }
    Err(
        "Unsupported boot image compression (only gzip, xz, lzma, bzip2 and zstd are handled)"
            .into(),
    )
}

/// The stripped kernel ELF that x86 boot images carry as their compressed payload.
pub fn extract_kernel_elf(image: &[u8]) -> Res<Vec<u8>> {
    if image.len() < 0x250 || &image[0x202..0x206] != b"HdrS" {
        return Err("Not a Linux x86 boot image".into());
    }
    let word = |at: usize| u32::from_le_bytes(image[at..at + 4].try_into().unwrap()) as usize;
    let (offset, length) = (word(0x248), word(0x24c));
    let setup_sectors = if image[0x1f1] == 0 {
        4
    } else {
        image[0x1f1] as usize
    };
    let start = (setup_sectors + 1) * 512 + offset;
    let begin = start.min(image.len());
    let end = start.saturating_add(length).min(image.len());
    let kernel = decompress_payload(&image[begin..end])?;
    if !kernel.starts_with(b"\x7fELF") {
        return Err("The boot image payload is not an ELF kernel".into());
    }
    Ok(kernel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn image(payload: &[u8]) -> Vec<u8> {
        let mut image = vec![0u8; 1024];
        image[0x1f1] = 1;
        image[0x202..0x206].copy_from_slice(b"HdrS");
        image[0x24c..0x250].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        image.extend(payload);
        image
    }

    fn elf() -> Vec<u8> {
        let mut data = b"\x7fELF".to_vec();
        data.extend(0..64u8);
        data
    }

    #[test]
    fn payload_decompression_ignores_the_appended_size_word() {
        let elf = elf();
        let size = (elf.len() as u32).to_le_bytes();
        let gzip = {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(&elf).unwrap();
            encoder.finish().unwrap()
        };
        let xz = {
            let mut encoder = liblzma::write::XzEncoder::new(Vec::new(), 6);
            encoder.write_all(&elf).unwrap();
            encoder.finish().unwrap()
        };
        let lzma = {
            let options = liblzma::stream::LzmaOptions::new_preset(6).unwrap();
            let stream = liblzma::stream::Stream::new_lzma_encoder(&options).unwrap();
            let mut encoder = liblzma::write::XzEncoder::new_stream(Vec::new(), stream);
            encoder.write_all(&elf).unwrap();
            encoder.finish().unwrap()
        };
        let bzip2 = {
            let mut encoder =
                bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
            encoder.write_all(&elf).unwrap();
            encoder.finish().unwrap()
        };
        let zstd = zstd::encode_all(&elf[..], 3).unwrap();
        for (name, mut compressed) in [
            ("gzip", gzip),
            ("xz", xz),
            ("lzma", lzma),
            ("bzip2", bzip2),
            ("zstd", zstd),
        ] {
            compressed.extend(size);
            assert_eq!(
                extract_kernel_elf(&image(&compressed)).unwrap(),
                elf,
                "{name}"
            );
        }
    }

    #[test]
    fn unknown_compression_is_rejected() {
        let mut payload = vec![0x02, 0x21, 0x4c, 0x18];
        payload.extend([0; 32]);
        let error = extract_kernel_elf(&image(&payload)).unwrap_err();
        assert!(
            error.contains("Unsupported boot image compression"),
            "{error}"
        );
    }

    #[test]
    fn non_elf_payload_is_rejected() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"MZ not a kernel").unwrap();
        let error = extract_kernel_elf(&image(&encoder.finish().unwrap())).unwrap_err();
        assert!(error.contains("not an ELF"), "{error}");
    }

    #[test]
    fn non_boot_image_is_rejected() {
        let error = extract_kernel_elf(&vec![0u8; 2048]).unwrap_err();
        assert!(error.contains("boot image"), "{error}");
    }
}
