//! Built-in reader and writer for classic `.pcap` files, so captures can be replayed
//! without libpcap installed. pcapng files are read through libpcap instead.

use std::fs::File;
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::Path;

use super::error::CaptureError;
use super::{Next, Packet, PacketSource};

const MAGIC_MICROS: u32 = 0xA1B2_C3D4;
const MAGIC_NANOS: u32 = 0xA1B2_3C4D;
const MAGIC_PCAPNG: u32 = 0x0A0D_0D0A;
/// Records larger than this are treated as corruption.
const MAX_RECORD: u32 = 1 << 20;

pub struct PcapFile {
    r: BufReader<File>,
    path: String,
    big_endian: bool,
    nanos: bool,
    linktype: i32,
    buf: Vec<u8>,
}

/// Whether `open` failed only because the file is pcapng.
pub fn is_pcapng_error(e: &CaptureError) -> bool {
    matches!(e, CaptureError::BadFile { detail, .. } if detail.starts_with("pcapng"))
}

impl PcapFile {
    pub fn open(path: &Path) -> Result<Self, CaptureError> {
        let shown = path.display().to_string();
        let io = |source| CaptureError::Io { path: shown.clone(), source };
        let mut r = BufReader::with_capacity(1 << 20, File::open(path).map_err(io)?);
        let mut hdr = [0u8; 24];
        r.read_exact(&mut hdr).map_err(|e| {
            if e.kind() == ErrorKind::UnexpectedEof {
                CaptureError::BadFile { path: shown.clone(), detail: "file is too short to be a capture".into() }
            } else {
                io(e)
            }
        })?;

        let magic_le = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let magic_be = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let (big_endian, nanos) = match (magic_le, magic_be) {
            (MAGIC_MICROS, _) => (false, false),
            (MAGIC_NANOS, _) => (false, true),
            (_, MAGIC_MICROS) => (true, false),
            (_, MAGIC_NANOS) => (true, true),
            (MAGIC_PCAPNG, _) => {
                return Err(CaptureError::BadFile {
                    path: shown,
                    detail: "pcapng format needs libpcap to read; install it or convert with `editcap -F pcap`".into(),
                })
            }
            _ => return Err(CaptureError::BadFile { path: shown, detail: "not a pcap capture file".into() }),
        };
        let read32 = |b: &[u8]| {
            let a = [b[0], b[1], b[2], b[3]];
            if big_endian { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) }
        };
        // The upper bits of the link type field carry FCS information.
        let linktype = (read32(&hdr[20..24]) & 0x0FFF_FFFF) as i32;
        Ok(Self { r, path: shown, big_endian, nanos, linktype, buf: Vec::with_capacity(65_536) })
    }

    fn u32_at(&self, b: &[u8]) -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if self.big_endian { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) }
    }
}

impl PacketSource for PcapFile {
    fn next_packet(&mut self) -> Result<Next<'_>, CaptureError> {
        let mut rec = [0u8; 16];
        match self.r.read_exact(&mut rec) {
            Ok(()) => {}
            // A capture cut off mid-record (e.g. tcpdump killed) simply ends there.
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(Next::End),
            Err(e) => return Err(CaptureError::Io { path: self.path.clone(), source: e }),
        }
        let sec = self.u32_at(&rec[0..4]) as i64;
        let frac = self.u32_at(&rec[4..8]) as i64;
        let caplen = self.u32_at(&rec[8..12]);
        let wire_len = self.u32_at(&rec[12..16]);
        if caplen > MAX_RECORD {
            return Err(CaptureError::BadFile { path: self.path.clone(), detail: format!("corrupt record ({caplen} bytes)") });
        }
        self.buf.resize(caplen as usize, 0);
        match self.r.read_exact(&mut self.buf) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(Next::End),
            Err(e) => return Err(CaptureError::Io { path: self.path.clone(), source: e }),
        }
        let ts_us = super::timestamp_us(sec, if self.nanos { frac / 1000 } else { frac });
        Ok(Next::Packet(Packet { ts_us, wire_len: wire_len.max(caplen), data: &self.buf }))
    }

    fn linktype(&self) -> i32 {
        self.linktype
    }

    fn is_live(&self) -> bool {
        false
    }
}

/// Writes classic little-endian microsecond pcap files.
pub struct PcapWriter<W: Write> {
    w: W,
}

impl PcapWriter<BufWriter<File>> {
    pub fn create(path: &Path, linktype: i32) -> std::io::Result<Self> {
        PcapWriter::new(BufWriter::new(File::create(path)?), linktype)
    }
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut w: W, linktype: i32) -> std::io::Result<Self> {
        w.write_all(&MAGIC_MICROS.to_le_bytes())?;
        w.write_all(&2u16.to_le_bytes())?;
        w.write_all(&4u16.to_le_bytes())?;
        w.write_all(&0i32.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        w.write_all(&65_535u32.to_le_bytes())?;
        w.write_all(&(linktype as u32).to_le_bytes())?;
        Ok(Self { w })
    }

    pub fn write(&mut self, ts_us: i64, frame: &[u8]) -> std::io::Result<()> {
        self.write_truncated(ts_us, frame, frame.len() as u32)
    }

    /// Writes a frame that was `wire_len` bytes long on the wire but stored truncated.
    pub fn write_truncated(&mut self, ts_us: i64, frame: &[u8], wire_len: u32) -> std::io::Result<()> {
        self.w.write_all(&(ts_us.div_euclid(1_000_000) as u32).to_le_bytes())?;
        self.w.write_all(&(ts_us.rem_euclid(1_000_000) as u32).to_le_bytes())?;
        self.w.write_all(&(frame.len() as u32).to_le_bytes())?;
        self.w.write_all(&wire_len.max(frame.len() as u32).to_le_bytes())?;
        self.w.write_all(frame)
    }

    pub fn finish(mut self) -> std::io::Result<W> {
        self.w.flush()?;
        Ok(self.w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("netscope-test-{}-{name}", std::process::id()))
    }

    #[test]
    fn roundtrip() {
        let path = temp("roundtrip.pcap");
        let mut w = PcapWriter::create(&path, 1).unwrap();
        w.write(1_760_000_000_123_456, b"frame-one").unwrap();
        w.write(1_760_000_001_000_000, &[7u8; 1500]).unwrap();
        w.finish().unwrap();

        let mut f = PcapFile::open(&path).unwrap();
        assert_eq!(f.linktype(), 1);
        match f.next_packet().unwrap() {
            Next::Packet(p) => assert_eq!((p.ts_us, p.wire_len, p.data), (1_760_000_000_123_456, 9, &b"frame-one"[..])),
            _ => panic!("expected packet"),
        }
        assert!(matches!(f.next_packet().unwrap(), Next::Packet(p) if p.data.len() == 1500));
        assert!(matches!(f.next_packet().unwrap(), Next::End));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn big_endian_nanosecond_files() {
        let path = temp("be.pcap");
        let mut b = Vec::new();
        b.extend_from_slice(&MAGIC_NANOS.to_be_bytes());
        b.extend_from_slice(&[0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]);
        b.extend_from_slice(&101u32.to_be_bytes());
        b.extend_from_slice(&10u32.to_be_bytes());
        b.extend_from_slice(&5_000u32.to_be_bytes());
        b.extend_from_slice(&2u32.to_be_bytes());
        b.extend_from_slice(&60u32.to_be_bytes());
        b.extend_from_slice(&[0xAB, 0xCD]);
        std::fs::write(&path, &b).unwrap();

        let mut f = PcapFile::open(&path).unwrap();
        assert_eq!(f.linktype(), 101);
        assert!(matches!(f.next_packet().unwrap(), Next::Packet(p) if p.ts_us == 10_000_005 && p.wire_len == 60));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn rejects_bad_files_and_tolerates_truncation() {
        let path = temp("bad.pcap");
        std::fs::write(&path, b"hello").unwrap();
        assert!(matches!(PcapFile::open(&path), Err(CaptureError::BadFile { .. })));
        std::fs::write(&path, [0u8; 24]).unwrap();
        assert!(matches!(PcapFile::open(&path), Err(CaptureError::BadFile { .. })));
        let mut ng = MAGIC_PCAPNG.to_le_bytes().to_vec();
        ng.resize(24, 0);
        std::fs::write(&path, &ng).unwrap();
        assert!(is_pcapng_error(&PcapFile::open(&path).err().unwrap()));

        let mut w = PcapWriter::create(&path, 1).unwrap();
        w.write(0, &[1u8; 100]).unwrap();
        w.finish().unwrap();
        let full = std::fs::read(&path).unwrap();
        std::fs::write(&path, &full[..full.len() - 10]).unwrap();
        let mut f = PcapFile::open(&path).unwrap();
        assert!(matches!(f.next_packet().unwrap(), Next::End));
        std::fs::remove_file(&path).ok();
        assert!(matches!(PcapFile::open(&path), Err(CaptureError::Io { .. })));
    }

    /// Reads a whole file: Ok(frames as (ts, wire_len, caplen)) or the error text.
    fn read_all(path: &std::path::Path) -> Result<Vec<(i64, u32, usize)>, String> {
        let mut f = PcapFile::open(path).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        loop {
            match f.next_packet().map_err(|e| e.to_string())? {
                Next::Packet(p) => out.push((p.ts_us, p.wire_len, p.data.len())),
                Next::End => return Ok(out),
                Next::Timeout => unreachable!("files never time out"),
            }
        }
    }

    fn three_frames() -> Vec<u8> {
        let mut w = PcapWriter::new(Vec::new(), 1).unwrap();
        w.write(1_760_000_000_000_001, &[1u8; 60]).unwrap();
        w.write_truncated(1_760_000_000_500_000, &[2u8; 96], 1514).unwrap();
        w.write(1_760_000_001_000_000, &[3u8; 10]).unwrap();
        w.finish().unwrap()
    }

    #[test]
    fn every_prefix_reads_a_prefix_of_the_frames() {
        let full = three_frames();
        let path = temp("prefix.pcap");
        let expect = vec![(1_760_000_000_000_001, 60, 60), (1_760_000_000_500_000, 1514, 96), (1_760_000_001_000_000, 10, 10)];
        std::fs::write(&path, &full).unwrap();
        assert_eq!(read_all(&path).unwrap(), expect, "truncated wire length is reported, stored bytes kept");
        for cut in 0..full.len() {
            std::fs::write(&path, &full[..cut]).unwrap();
            match read_all(&path) {
                Err(e) => assert!(cut < 24 && e.contains("too short"), "cut {cut}: {e}"),
                Ok(frames) => {
                    assert!(cut >= 24, "a header shorter than 24 bytes opened");
                    assert_eq!(frames, expect[..frames.len()], "cut {cut}: frames must be a prefix of the original");
                    // A record is only returned once all of its bytes are there.
                    let complete = [24 + 16 + 60, 24 + 16 + 60 + 16 + 96, full.len()].iter().filter(|&&end| cut >= end).count();
                    assert_eq!(frames.len(), complete, "cut {cut}");
                }
            }
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn random_mutations_never_panic_and_corrupt_lengths_are_errors() {
        let base = three_frames();
        let path = temp("mutate.pcap");
        let mut seed = 0x5851_F42D_4C95_7F2Du64;
        let mut rnd = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as u32
        };
        for _ in 0..400 {
            let mut m = base.clone();
            for _ in 0..1 + rnd() % 3 {
                let i = rnd() as usize % m.len();
                m[i] = rnd() as u8;
            }
            std::fs::write(&path, &m).unwrap();
            if let Ok(frames) = read_all(&path) {
                assert!(frames.len() <= 3);
                for (_, wire, cap) in frames {
                    assert!(wire as usize >= cap && cap <= MAX_RECORD as usize);
                }
            }
        }
        // A record claiming more than MAX_RECORD bytes is corruption, not a huge allocation.
        let mut big = base.clone();
        big[24 + 8..24 + 12].copy_from_slice(&(MAX_RECORD + 1).to_le_bytes());
        std::fs::write(&path, &big).unwrap();
        let e = read_all(&path).unwrap_err();
        assert!(e.contains("corrupt record") && e.contains(&(MAX_RECORD + 1).to_string()), "{e}");
        // Exactly MAX_RECORD is accepted (and then simply runs out of file).
        big[24 + 8..24 + 12].copy_from_slice(&MAX_RECORD.to_le_bytes());
        std::fs::write(&path, &big).unwrap();
        assert_eq!(read_all(&path).unwrap(), vec![]);
        // FCS bits in the link type field are masked; a wire length below caplen is corrected.
        let mut fcs = base.clone();
        fcs[20..24].copy_from_slice(&(0xF000_0000u32 | 101).to_le_bytes());
        fcs[24 + 12..24 + 16].copy_from_slice(&5u32.to_le_bytes());
        std::fs::write(&path, &fcs).unwrap();
        assert_eq!(PcapFile::open(&path).unwrap().linktype(), 101);
        assert_eq!(read_all(&path).unwrap()[0], (1_760_000_000_000_001, 60, 60));
        // Little-endian nanosecond files and a timestamp far in the future are clamped, not overflowed.
        let mut nanos = base.clone();
        nanos[0..4].copy_from_slice(&MAGIC_NANOS.to_le_bytes());
        nanos[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        nanos[28..32].copy_from_slice(&999_999_999u32.to_le_bytes());
        std::fs::write(&path, &nanos).unwrap();
        let frames = read_all(&path).unwrap();
        assert_eq!(frames[0].0, u32::MAX as i64 * 1_000_000 + 999_999);
        assert_eq!(frames[1].0, 1_760_000_000_000_000 + 500_000 / 1000, "the fraction field is read as nanoseconds");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn writer_emits_the_classic_header_and_negative_times_do_not_panic() {
        let bytes = three_frames();
        assert_eq!(&bytes[..4], &MAGIC_MICROS.to_le_bytes());
        assert_eq!(&bytes[4..8], &[2, 0, 4, 0], "version 2.4");
        assert_eq!(&bytes[16..20], &65_535u32.to_le_bytes(), "snaplen");
        assert_eq!(&bytes[20..24], &1u32.to_le_bytes(), "link type");
        assert_eq!(bytes.len(), 24 + 3 * 16 + 60 + 96 + 10);
        let mut w = PcapWriter::new(Vec::new(), 1).unwrap();
        w.write(-1, b"x").unwrap();
        w.write(i64::MAX, b"y").unwrap();
        assert_eq!(w.finish().unwrap().len(), 24 + 2 * 17);
    }
}
