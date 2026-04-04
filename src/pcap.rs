use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use anyhow::Result;
use chrono::{DateTime, Utc};
use memmap2::MmapOptions;

const PCAP_HEADER_LEN: usize = 24;
const PCAP_RECORD_HEADER_LEN: usize = 16;
const PCAP_MAGIC_USEC_LE: [u8; 4] = [0xd4, 0xc3, 0xb2, 0xa1];
const PCAP_MAGIC_USEC_BE: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];
const PCAP_MAGIC_NSEC_LE: [u8; 4] = [0x4d, 0x3c, 0xb2, 0xa1];
const PCAP_MAGIC_NSEC_BE: [u8; 4] = [0xa1, 0xb2, 0x3c, 0x4d];
const PCAPNG_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

const DLT_EN10MB: u32 = 1;
const DLT_RAW: u32 = 101;
const DLT_LINUX_SLL: u32 = 113;

const PCAPNG_BLOCK_INTERFACE_DESC: u32 = 0x0000_0001;
const PCAPNG_BLOCK_PACKET: u32 = 0x0000_0002;
const PCAPNG_BLOCK_SIMPLE_PACKET: u32 = 0x0000_0003;
const PCAPNG_BLOCK_ENHANCED_PACKET: u32 = 0x0000_0006;

const PCAPNG_OPT_ENDOFOPT: u16 = 0;
const PCAPNG_IF_OPT_TSRESOL: u16 = 9;
const PCAPNG_IF_OPT_TSOFFSET: u16 = 14;

#[derive(Debug, Clone, Copy)]
enum ByteOrder {
    Little,
    Big,
}

#[derive(Debug)]
struct PcapHeader {
    byte_order: ByteOrder,
    nanos: bool,
    network: u32,
}

#[derive(Debug, Clone, Copy)]
struct TimestampScale {
    numerator: u64,
    denominator: u64,
    offset_seconds: i64,
}

#[derive(Debug, Clone, Copy)]
struct InterfaceInfo {
    link_type: u32,
    ts_scale: TimestampScale,
}

impl Default for TimestampScale {
    fn default() -> Self {
        // pcapng default timestamp resolution is microseconds.
        Self {
            numerator: 1,
            denominator: 1_000_000,
            offset_seconds: 0,
        }
    }
}

#[derive(Debug)]
pub struct PcapAnalysis {
    pub link_type: String,
    pub time_from: DateTime<Utc>,
    pub time_to: DateTime<Utc>,
    pub packet_count: u64,
    pub ip_packet_count: u64,
    pub unique_source_ip_count: usize,
    pub source_ips: Vec<String>,
    pub truncated_source_ips: bool,
    pub unique_destination_ip_count: usize,
    pub destination_ips: Vec<String>,
    pub truncated_ips: bool,
}

struct IpSets {
    src_ips: HashSet<String>,
    dst_ips: HashSet<String>,
}

pub fn analyze_pcap_bytes(data: &[u8], max_ips: usize) -> Result<PcapAnalysis> {
    if data.len() >= 4 && data[0..4] == PCAPNG_MAGIC {
        return analyze_pcapng_bytes(data, max_ips);
    }
    analyze_classic_pcap_bytes(data, max_ips)
}

pub fn analyze_pcap_file(path: &Path, max_ips: usize) -> Result<PcapAnalysis> {
    let file = File::open(path)
        .map_err(|err| anyhow::anyhow!("failed to open pcap file for analysis: {err}"))?;
    let metadata = file
        .metadata()
        .map_err(|err| anyhow::anyhow!("failed to read pcap metadata: {err}"))?;
    if metadata.len() == 0 {
        anyhow::bail!("pcap file is empty");
    }
    let map = {
        // SAFETY: file is opened read-only and mapping is used as immutable bytes for parse-only analysis.
        unsafe { MmapOptions::new().map(&file) }
            .map_err(|err| anyhow::anyhow!("failed to memory-map pcap file: {err}"))?
    };
    analyze_pcap_bytes(&map, max_ips)
}

fn analyze_classic_pcap_bytes(data: &[u8], max_ips: usize) -> Result<PcapAnalysis> {
    let header = parse_classic_header(data)?;
    if !is_supported_link_type(header.network) {
        anyhow::bail!(
            "unsupported pcap link type {} (supported: ethernet=1, raw=101, linux_sll=113)",
            header.network
        );
    }

    let mut offset = PCAP_HEADER_LEN;
    let mut packet_count = 0u64;
    let mut ip_packet_count = 0u64;
    let mut time_from: Option<DateTime<Utc>> = None;
    let mut time_to: Option<DateTime<Utc>> = None;
    let mut src_ips = HashSet::new();
    let mut dst_ips = HashSet::new();
    let capped_max_ips = max_ips.clamp(1, 5_000);

    while offset + PCAP_RECORD_HEADER_LEN <= data.len() {
        let ts_sec = read_u32(&data[offset..offset + 4], header.byte_order) as i64;
        let ts_frac = read_u32(&data[offset + 4..offset + 8], header.byte_order);
        let incl_len = read_u32(&data[offset + 8..offset + 12], header.byte_order) as usize;
        offset += PCAP_RECORD_HEADER_LEN;

        if offset + incl_len > data.len() {
            anyhow::bail!("pcap record exceeds file bounds");
        }

        packet_count = packet_count.saturating_add(1);
        let mut nanos = if header.nanos {
            ts_frac
        } else {
            ts_frac.saturating_mul(1000)
        };
        let mut sec = ts_sec;
        if nanos >= 1_000_000_000 {
            sec += (nanos / 1_000_000_000) as i64;
            nanos %= 1_000_000_000;
        }
        let ts = DateTime::from_timestamp(sec, nanos)
            .ok_or_else(|| anyhow::anyhow!("invalid packet timestamp in pcap"))?;
        update_time_bounds(ts, &mut time_from, &mut time_to);

        let packet = &data[offset..offset + incl_len];
        offset += incl_len;

        let src_ip = extract_src_ip(header.network, packet);
        let dst_ip = extract_dst_ip(header.network, packet);
        if src_ip.is_some() || dst_ip.is_some() {
            ip_packet_count = ip_packet_count.saturating_add(1);
            if let Some(src_ip) = src_ip {
                src_ips.insert(src_ip);
            }
            if let Some(dst_ip) = dst_ip {
                dst_ips.insert(dst_ip);
            }
        }
    }

    finalize_analysis(
        link_type_name(header.network).to_string(),
        time_from,
        time_to,
        packet_count,
        ip_packet_count,
        IpSets { src_ips, dst_ips },
        capped_max_ips,
    )
}

fn analyze_pcapng_bytes(data: &[u8], max_ips: usize) -> Result<PcapAnalysis> {
    let capped_max_ips = max_ips.clamp(1, 5_000);
    let mut offset = 0usize;
    let mut current_order: Option<ByteOrder> = None;
    let mut interfaces: HashMap<u32, InterfaceInfo> = HashMap::new();

    let mut packet_count = 0u64;
    let mut ip_packet_count = 0u64;
    let mut time_from: Option<DateTime<Utc>> = None;
    let mut time_to: Option<DateTime<Utc>> = None;
    let mut src_ips = HashSet::new();
    let mut dst_ips = HashSet::new();
    let mut used_link_types = HashSet::new();
    let mut malformed_tail = false;

    while offset + 12 <= data.len() {
        if data[offset..offset + 4] == PCAPNG_MAGIC {
            let (order, block_len) = match parse_pcapng_section_header(data, offset) {
                Ok(v) => v,
                Err(err) => {
                    if packet_count > 0 {
                        malformed_tail = true;
                        break;
                    }
                    return Err(err);
                }
            };
            current_order = Some(order);
            interfaces.clear();
            offset += block_len;
            continue;
        }

        let Some(order) = current_order else {
            if packet_count > 0 {
                malformed_tail = true;
                break;
            }
            anyhow::bail!("pcapng is missing a valid section header before data blocks");
        };
        let block_type = read_u32(&data[offset..offset + 4], order);
        let block_len = read_u32(&data[offset + 4..offset + 8], order) as usize;
        if block_type == 0 && block_len == 0 {
            // Some captures have trailing zero padding.
            break;
        }
        if let Err(err) = validate_pcapng_block_bounds(data, offset, block_len, order) {
            if packet_count > 0 {
                malformed_tail = true;
                break;
            }
            return Err(err);
        }
        let body_start = offset + 8;
        let body_end = offset + block_len - 4;
        let body = &data[body_start..body_end];

        match block_type {
            PCAPNG_BLOCK_INTERFACE_DESC => {
                parse_pcapng_interface_block(body, order, &mut interfaces)?;
            }
            PCAPNG_BLOCK_ENHANCED_PACKET => {
                let parsed = parse_pcapng_enhanced_packet_block(body, order)?;
                packet_count = packet_count.saturating_add(1);
                if let Some(iface) = interfaces.get(&parsed.interface_id).copied()
                    && let Some(ts) =
                        pcapng_ticks_to_datetime(parsed.timestamp_ticks, iface.ts_scale)
                {
                    update_time_bounds(ts, &mut time_from, &mut time_to);
                    used_link_types.insert(iface.link_type);
                    let src_ip = extract_src_ip(iface.link_type, parsed.packet);
                    let dst_ip = extract_dst_ip(iface.link_type, parsed.packet);
                    if src_ip.is_some() || dst_ip.is_some() {
                        ip_packet_count = ip_packet_count.saturating_add(1);
                        if let Some(src_ip) = src_ip {
                            src_ips.insert(src_ip);
                        }
                        if let Some(dst_ip) = dst_ip {
                            dst_ips.insert(dst_ip);
                        }
                    }
                }
            }
            PCAPNG_BLOCK_PACKET => {
                let parsed = parse_pcapng_packet_block(body, order)?;
                packet_count = packet_count.saturating_add(1);
                if let Some(iface) = interfaces.get(&(parsed.interface_id as u32)).copied()
                    && let Some(ts) =
                        pcapng_ticks_to_datetime(parsed.timestamp_ticks, iface.ts_scale)
                {
                    update_time_bounds(ts, &mut time_from, &mut time_to);
                    used_link_types.insert(iface.link_type);
                    let src_ip = extract_src_ip(iface.link_type, parsed.packet);
                    let dst_ip = extract_dst_ip(iface.link_type, parsed.packet);
                    if src_ip.is_some() || dst_ip.is_some() {
                        ip_packet_count = ip_packet_count.saturating_add(1);
                        if let Some(src_ip) = src_ip {
                            src_ips.insert(src_ip);
                        }
                        if let Some(dst_ip) = dst_ip {
                            dst_ips.insert(dst_ip);
                        }
                    }
                }
            }
            PCAPNG_BLOCK_SIMPLE_PACKET => {
                let parsed = parse_pcapng_simple_packet_block(body, order)?;
                packet_count = packet_count.saturating_add(1);
                if let Some(iface) = interfaces.get(&0).copied() {
                    used_link_types.insert(iface.link_type);
                    let src_ip = extract_src_ip(iface.link_type, parsed.packet);
                    let dst_ip = extract_dst_ip(iface.link_type, parsed.packet);
                    if src_ip.is_some() || dst_ip.is_some() {
                        ip_packet_count = ip_packet_count.saturating_add(1);
                        if let Some(src_ip) = src_ip {
                            src_ips.insert(src_ip);
                        }
                        if let Some(dst_ip) = dst_ip {
                            dst_ips.insert(dst_ip);
                        }
                    }
                }
            }
            _ => {}
        }

        offset += block_len;
    }

    if malformed_tail && packet_count == 0 {
        anyhow::bail!("pcapng is truncated or corrupt (no valid packets parsed)");
    }

    let link_type = if used_link_types.is_empty() {
        "pcapng".to_string()
    } else {
        let mut names = used_link_types
            .iter()
            .map(|lt| link_type_name(*lt).to_string())
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        if names.len() == 1 {
            format!("pcapng:{}", names[0])
        } else {
            format!("pcapng:{}", names.join("+"))
        }
    };

    finalize_analysis(
        link_type,
        time_from,
        time_to,
        packet_count,
        ip_packet_count,
        IpSets { src_ips, dst_ips },
        capped_max_ips,
    )
}

fn finalize_analysis(
    link_type: String,
    time_from: Option<DateTime<Utc>>,
    time_to: Option<DateTime<Utc>>,
    packet_count: u64,
    ip_packet_count: u64,
    ip_sets: IpSets,
    max_ips: usize,
) -> Result<PcapAnalysis> {
    let Some(time_from) = time_from else {
        anyhow::bail!("capture has no timestamped packets");
    };
    let Some(time_to) = time_to else {
        anyhow::bail!("capture has no timestamped packets");
    };

    let mut source_ips = ip_sets.src_ips.into_iter().collect::<Vec<_>>();
    source_ips.sort_unstable();
    let unique_source_ip_count = source_ips.len();
    let truncated_source_ips = source_ips.len() > max_ips;
    if truncated_source_ips {
        source_ips.truncate(max_ips);
    }

    let mut destination_ips = ip_sets.dst_ips.into_iter().collect::<Vec<_>>();
    destination_ips.sort_unstable();
    let unique_destination_ip_count = destination_ips.len();
    let truncated_ips = destination_ips.len() > max_ips;
    if truncated_ips {
        destination_ips.truncate(max_ips);
    }

    Ok(PcapAnalysis {
        link_type,
        time_from,
        time_to,
        packet_count,
        ip_packet_count,
        unique_source_ip_count,
        source_ips,
        truncated_source_ips,
        unique_destination_ip_count,
        destination_ips,
        truncated_ips,
    })
}

fn update_time_bounds(
    ts: DateTime<Utc>,
    time_from: &mut Option<DateTime<Utc>>,
    time_to: &mut Option<DateTime<Utc>>,
) {
    *time_from = Some(time_from.map_or(ts, |cur| cur.min(ts)));
    *time_to = Some(time_to.map_or(ts, |cur| cur.max(ts)));
}

fn parse_classic_header(data: &[u8]) -> Result<PcapHeader> {
    if data.len() < PCAP_HEADER_LEN {
        anyhow::bail!("pcap file is too small");
    }
    let magic = [data[0], data[1], data[2], data[3]];
    let (byte_order, nanos) = match magic {
        PCAP_MAGIC_USEC_LE => (ByteOrder::Little, false),
        PCAP_MAGIC_USEC_BE => (ByteOrder::Big, false),
        PCAP_MAGIC_NSEC_LE => (ByteOrder::Little, true),
        PCAP_MAGIC_NSEC_BE => (ByteOrder::Big, true),
        PCAPNG_MAGIC => anyhow::bail!("pcapng should be parsed through pcapng parser"),
        _ => anyhow::bail!("invalid pcap magic"),
    };

    let network = read_u32(&data[20..24], byte_order);
    Ok(PcapHeader {
        byte_order,
        nanos,
        network,
    })
}

fn parse_pcapng_section_header(data: &[u8], offset: usize) -> Result<(ByteOrder, usize)> {
    if offset + 28 > data.len() {
        anyhow::bail!("pcapng section header is truncated");
    }
    let bom = &data[offset + 8..offset + 12];
    let order = if bom == [0x4d, 0x3c, 0x2b, 0x1a] {
        ByteOrder::Little
    } else if bom == [0x1a, 0x2b, 0x3c, 0x4d] {
        ByteOrder::Big
    } else {
        anyhow::bail!("pcapng section header has invalid byte-order magic");
    };
    let block_len = read_u32(&data[offset + 4..offset + 8], order) as usize;
    validate_pcapng_block_bounds(data, offset, block_len, order)?;
    Ok((order, block_len))
}

fn validate_pcapng_block_bounds(
    data: &[u8],
    offset: usize,
    block_len: usize,
    order: ByteOrder,
) -> Result<()> {
    if block_len < 12 {
        anyhow::bail!("pcapng block length is invalid");
    }
    let Some(block_end) = offset.checked_add(block_len) else {
        anyhow::bail!("pcapng block length overflows address space");
    };
    if block_end > data.len() {
        anyhow::bail!("pcapng block exceeds file bounds");
    }
    let trailer_off = block_end - 4;
    let trailer_len = read_u32(&data[trailer_off..trailer_off + 4], order) as usize;
    if trailer_len != block_len {
        anyhow::bail!("pcapng block length trailer mismatch");
    }
    Ok(())
}

fn parse_pcapng_interface_block(
    body: &[u8],
    order: ByteOrder,
    interfaces: &mut HashMap<u32, InterfaceInfo>,
) -> Result<()> {
    if body.len() < 8 {
        anyhow::bail!("pcapng interface description block is too short");
    }
    let link_type = read_u16(&body[0..2], order) as u32;
    let mut ts_scale = TimestampScale::default();

    let options = &body[8..];
    let mut off = 0usize;
    while off + 4 <= options.len() {
        let code = read_u16(&options[off..off + 2], order);
        let len = read_u16(&options[off + 2..off + 4], order) as usize;
        off += 4;
        if code == PCAPNG_OPT_ENDOFOPT {
            break;
        }
        if off + len > options.len() {
            anyhow::bail!("pcapng interface option exceeds block bounds");
        }
        let value = &options[off..off + len];

        match code {
            PCAPNG_IF_OPT_TSRESOL if !value.is_empty() => {
                ts_scale = ts_scale_from_resolution(value[0]);
            }
            PCAPNG_IF_OPT_TSOFFSET if len == 8 => {
                let off_sec = read_i64(value, order);
                ts_scale.offset_seconds = off_sec;
            }
            _ => {}
        }

        off += len;
        off += padded_len(len);
    }

    let idx = interfaces.len() as u32;
    interfaces.insert(
        idx,
        InterfaceInfo {
            link_type,
            ts_scale,
        },
    );
    Ok(())
}

struct ParsedEnhancedPacketBlock<'a> {
    interface_id: u32,
    timestamp_ticks: u64,
    packet: &'a [u8],
}

fn parse_pcapng_enhanced_packet_block(
    body: &[u8],
    order: ByteOrder,
) -> Result<ParsedEnhancedPacketBlock<'_>> {
    if body.len() < 20 {
        anyhow::bail!("pcapng enhanced packet block is too short");
    }
    let interface_id = read_u32(&body[0..4], order);
    let ts_high = read_u32(&body[4..8], order) as u64;
    let ts_low = read_u32(&body[8..12], order) as u64;
    let cap_len = read_u32(&body[12..16], order) as usize;
    if body.len() < 20 + cap_len {
        anyhow::bail!("pcapng enhanced packet payload exceeds block bounds");
    }
    let packet = &body[20..20 + cap_len];
    Ok(ParsedEnhancedPacketBlock {
        interface_id,
        timestamp_ticks: (ts_high << 32) | ts_low,
        packet,
    })
}

struct ParsedPacketBlock<'a> {
    interface_id: u16,
    timestamp_ticks: u64,
    packet: &'a [u8],
}

fn parse_pcapng_packet_block(body: &[u8], order: ByteOrder) -> Result<ParsedPacketBlock<'_>> {
    if body.len() < 20 {
        anyhow::bail!("pcapng packet block is too short");
    }
    let interface_id = read_u16(&body[0..2], order);
    let ts_high = read_u32(&body[4..8], order) as u64;
    let ts_low = read_u32(&body[8..12], order) as u64;
    let cap_len = read_u32(&body[12..16], order) as usize;
    if body.len() < 20 + cap_len {
        anyhow::bail!("pcapng packet payload exceeds block bounds");
    }
    let packet = &body[20..20 + cap_len];
    Ok(ParsedPacketBlock {
        interface_id,
        timestamp_ticks: (ts_high << 32) | ts_low,
        packet,
    })
}

struct ParsedSimplePacketBlock<'a> {
    packet: &'a [u8],
}

fn parse_pcapng_simple_packet_block(
    body: &[u8],
    order: ByteOrder,
) -> Result<ParsedSimplePacketBlock<'_>> {
    if body.len() < 4 {
        anyhow::bail!("pcapng simple packet block is too short");
    }
    let original_len = read_u32(&body[0..4], order) as usize;
    let available = body.len() - 4;
    let packet_len = available.min(original_len);
    let packet = &body[4..4 + packet_len];
    Ok(ParsedSimplePacketBlock { packet })
}

fn ts_scale_from_resolution(raw: u8) -> TimestampScale {
    // if_tsresol:
    // - msb 0: units are 10^-value seconds
    // - msb 1: units are 2^-value seconds
    let is_pow2 = (raw & 0x80) != 0;
    let power = (raw & 0x7f) as u32;
    if is_pow2 {
        if power > 60 {
            return TimestampScale::default();
        }
        let denominator = 1u64 << power;
        TimestampScale {
            numerator: 1,
            denominator,
            offset_seconds: 0,
        }
    } else {
        let Some(denominator) = 10u64.checked_pow(power) else {
            return TimestampScale::default();
        };
        TimestampScale {
            numerator: 1,
            denominator,
            offset_seconds: 0,
        }
    }
}

fn pcapng_ticks_to_datetime(ticks: u64, scale: TimestampScale) -> Option<DateTime<Utc>> {
    let den = scale.denominator.max(1) as u128;
    let num = scale.numerator as u128;
    let total_num = (ticks as u128).saturating_mul(num);
    let sec = total_num / den;
    let rem = total_num % den;
    let nanos = rem.saturating_mul(1_000_000_000u128) / den;
    if sec > i64::MAX as u128 {
        return None;
    }
    let sec = (sec as i64).checked_add(scale.offset_seconds)?;
    DateTime::from_timestamp(sec, nanos as u32)
}

fn padded_len(len: usize) -> usize {
    (4 - (len % 4)) % 4
}

fn read_u16(input: &[u8], byte_order: ByteOrder) -> u16 {
    let mut buf = [0u8; 2];
    buf.copy_from_slice(input);
    match byte_order {
        ByteOrder::Little => u16::from_le_bytes(buf),
        ByteOrder::Big => u16::from_be_bytes(buf),
    }
}

fn read_u32(input: &[u8], byte_order: ByteOrder) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(input);
    match byte_order {
        ByteOrder::Little => u32::from_le_bytes(buf),
        ByteOrder::Big => u32::from_be_bytes(buf),
    }
}

fn read_i64(input: &[u8], byte_order: ByteOrder) -> i64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(input);
    match byte_order {
        ByteOrder::Little => i64::from_le_bytes(buf),
        ByteOrder::Big => i64::from_be_bytes(buf),
    }
}

fn be_u16(input: &[u8]) -> u16 {
    u16::from_be_bytes([input[0], input[1]])
}

fn is_supported_link_type(network: u32) -> bool {
    matches!(network, DLT_EN10MB | DLT_RAW | DLT_LINUX_SLL)
}

fn link_type_name(network: u32) -> &'static str {
    match network {
        DLT_EN10MB => "ethernet",
        DLT_RAW => "raw_ip",
        DLT_LINUX_SLL => "linux_sll",
        _ => "unknown",
    }
}

fn extract_dst_ip(link_type: u32, packet: &[u8]) -> Option<String> {
    match link_type {
        DLT_EN10MB => extract_dst_ip_ethernet(packet),
        DLT_RAW => extract_dst_ip_raw_ip(packet),
        DLT_LINUX_SLL => extract_dst_ip_linux_sll(packet),
        _ => None,
    }
}

fn extract_src_ip(link_type: u32, packet: &[u8]) -> Option<String> {
    match link_type {
        DLT_EN10MB => extract_src_ip_ethernet(packet),
        DLT_RAW => extract_src_ip_raw_ip(packet),
        DLT_LINUX_SLL => extract_src_ip_linux_sll(packet),
        _ => None,
    }
}

fn extract_dst_ip_linux_sll(packet: &[u8]) -> Option<String> {
    if packet.len() < 16 {
        return None;
    }
    let proto = be_u16(&packet[14..16]);
    extract_dst_ip_by_ethertype(proto, &packet[16..])
}

fn extract_src_ip_linux_sll(packet: &[u8]) -> Option<String> {
    if packet.len() < 16 {
        return None;
    }
    let proto = be_u16(&packet[14..16]);
    extract_src_ip_by_ethertype(proto, &packet[16..])
}

fn extract_dst_ip_ethernet(packet: &[u8]) -> Option<String> {
    if packet.len() < 14 {
        return None;
    }
    let mut offset = 14usize;
    let mut ethertype = be_u16(&packet[12..14]);

    while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
        if packet.len() < offset + 4 {
            return None;
        }
        ethertype = be_u16(&packet[offset + 2..offset + 4]);
        offset += 4;
    }

    extract_dst_ip_by_ethertype(ethertype, &packet[offset..])
}

fn extract_src_ip_ethernet(packet: &[u8]) -> Option<String> {
    if packet.len() < 14 {
        return None;
    }
    let mut offset = 14usize;
    let mut ethertype = be_u16(&packet[12..14]);

    while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
        if packet.len() < offset + 4 {
            return None;
        }
        ethertype = be_u16(&packet[offset + 2..offset + 4]);
        offset += 4;
    }

    extract_src_ip_by_ethertype(ethertype, &packet[offset..])
}

fn extract_dst_ip_by_ethertype(ethertype: u16, payload: &[u8]) -> Option<String> {
    match ethertype {
        0x0800 => extract_ipv4_dst(payload),
        0x86dd => extract_ipv6_dst(payload),
        _ => None,
    }
}

fn extract_src_ip_by_ethertype(ethertype: u16, payload: &[u8]) -> Option<String> {
    match ethertype {
        0x0800 => extract_ipv4_src(payload),
        0x86dd => extract_ipv6_src(payload),
        _ => None,
    }
}

fn extract_dst_ip_raw_ip(packet: &[u8]) -> Option<String> {
    let version = packet.first().map(|b| b >> 4)?;
    match version {
        4 => extract_ipv4_dst(packet),
        6 => extract_ipv6_dst(packet),
        _ => None,
    }
}

fn extract_src_ip_raw_ip(packet: &[u8]) -> Option<String> {
    let version = packet.first().map(|b| b >> 4)?;
    match version {
        4 => extract_ipv4_src(packet),
        6 => extract_ipv6_src(packet),
        _ => None,
    }
}

fn extract_ipv4_src(payload: &[u8]) -> Option<String> {
    if payload.len() < 20 {
        return None;
    }
    let ihl = ((payload[0] & 0x0f) as usize) * 4;
    if ihl < 20 || payload.len() < ihl {
        return None;
    }
    let ip = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
    Some(ip.to_string())
}

fn extract_ipv4_dst(payload: &[u8]) -> Option<String> {
    if payload.len() < 20 {
        return None;
    }
    let ihl = ((payload[0] & 0x0f) as usize) * 4;
    if ihl < 20 || payload.len() < ihl {
        return None;
    }
    let ip = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
    Some(ip.to_string())
}

fn extract_ipv6_src(payload: &[u8]) -> Option<String> {
    if payload.len() < 40 {
        return None;
    }
    let mut src = [0u8; 16];
    src.copy_from_slice(&payload[8..24]);
    Some(Ipv6Addr::from(src).to_string())
}

fn extract_ipv6_dst(payload: &[u8]) -> Option<String> {
    if payload.len() < 40 {
        return None;
    }
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&payload[24..40]);
    Some(Ipv6Addr::from(dst).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ethernet_ipv4_packet(dst: [u8; 4]) -> Vec<u8> {
        vec![
            0, 1, 2, 3, 4, 5, // dst mac
            6, 7, 8, 9, 10, 11, // src mac
            0x08, 0x00, // ethertype ipv4
            0x45, 0x00, 0x00, 0x14, // v4+ihl, dscp, len
            0x00, 0x00, 0x00, 0x00, // id, flags/frag
            64, 6, 0x00, 0x00, // ttl, proto, checksum
            10, 0, 0, 1, // src
            dst[0], dst[1], dst[2], dst[3], // dst
        ]
    }

    fn sample_ipv4_pcap() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&PCAP_MAGIC_USEC_LE);
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&DLT_EN10MB.to_le_bytes());

        let packet = ethernet_ipv4_packet([1, 2, 3, 4]);
        out.extend_from_slice(&1_712_000_000u32.to_le_bytes());
        out.extend_from_slice(&123_456u32.to_le_bytes());
        out.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        out.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        out.extend_from_slice(&packet);

        out
    }

    fn push_u16_le(buf: &mut Vec<u8>, v: u16) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    fn push_u32_le(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    fn push_u64_le(buf: &mut Vec<u8>, v: u64) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    fn push_pcapng_block_le(out: &mut Vec<u8>, block_type: u32, body: &[u8]) {
        let block_len = (8 + body.len() + 4) as u32;
        push_u32_le(out, block_type);
        push_u32_le(out, block_len);
        out.extend_from_slice(body);
        push_u32_le(out, block_len);
    }

    fn sample_ipv4_pcapng() -> Vec<u8> {
        let mut out = Vec::new();

        // Section Header Block
        let mut shb_body = Vec::new();
        push_u32_le(&mut shb_body, 0x1a2b3c4d); // byte-order magic
        push_u16_le(&mut shb_body, 1); // major
        push_u16_le(&mut shb_body, 0); // minor
        push_u64_le(&mut shb_body, u64::MAX); // section length unknown (-1)
        push_pcapng_block_le(&mut out, PCAPNG_MAGIC_U32, &shb_body);

        // Interface Description Block (Ethernet)
        let mut idb_body = Vec::new();
        push_u16_le(&mut idb_body, DLT_EN10MB as u16);
        push_u16_le(&mut idb_body, 0);
        push_u32_le(&mut idb_body, 65535);
        push_pcapng_block_le(&mut out, PCAPNG_BLOCK_INTERFACE_DESC, &idb_body);

        // Enhanced Packet Block
        let packet = ethernet_ipv4_packet([8, 8, 8, 8]);
        let ts_ticks = 1_712_000_000_123_456u64; // microseconds
        let mut epb_body = Vec::new();
        push_u32_le(&mut epb_body, 0); // interface id
        push_u32_le(&mut epb_body, (ts_ticks >> 32) as u32);
        push_u32_le(&mut epb_body, ts_ticks as u32);
        push_u32_le(&mut epb_body, packet.len() as u32);
        push_u32_le(&mut epb_body, packet.len() as u32);
        epb_body.extend_from_slice(&packet);
        while epb_body.len() % 4 != 0 {
            epb_body.push(0);
        }
        push_pcapng_block_le(&mut out, PCAPNG_BLOCK_ENHANCED_PACKET, &epb_body);

        out
    }

    const PCAPNG_MAGIC_U32: u32 = 0x0A0D0D0A;

    #[test]
    fn parse_basic_ipv4_pcap() {
        let pcap = sample_ipv4_pcap();
        let summary = analyze_pcap_bytes(&pcap, 500).expect("parse pcap");
        assert_eq!(summary.link_type, "ethernet");
        assert_eq!(summary.packet_count, 1);
        assert_eq!(summary.ip_packet_count, 1);
        assert_eq!(summary.unique_source_ip_count, 1);
        assert_eq!(summary.source_ips, vec!["10.0.0.1".to_string()]);
        assert!(!summary.truncated_source_ips);
        assert_eq!(summary.unique_destination_ip_count, 1);
        assert_eq!(summary.destination_ips, vec!["1.2.3.4".to_string()]);
        assert!(!summary.truncated_ips);
    }

    #[test]
    fn parse_basic_ipv4_pcapng() {
        let pcapng = sample_ipv4_pcapng();
        let summary = analyze_pcap_bytes(&pcapng, 500).expect("parse pcapng");
        assert_eq!(summary.link_type, "pcapng:ethernet");
        assert_eq!(summary.packet_count, 1);
        assert_eq!(summary.ip_packet_count, 1);
        assert_eq!(summary.unique_source_ip_count, 1);
        assert_eq!(summary.source_ips, vec!["10.0.0.1".to_string()]);
        assert!(!summary.truncated_source_ips);
        assert_eq!(summary.unique_destination_ip_count, 1);
        assert_eq!(summary.destination_ips, vec!["8.8.8.8".to_string()]);
        assert!(!summary.truncated_ips);
        assert!(summary.time_to >= summary.time_from);
    }

    #[test]
    fn rejects_invalid_pcapng() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&PCAPNG_MAGIC);
        let err = analyze_pcap_bytes(&data, 10).expect_err("must reject malformed pcapng");
        assert!(err.to_string().contains("pcapng"));
    }

    #[test]
    fn parse_pcapng_with_truncated_tail_keeps_valid_packets() {
        let mut pcapng = sample_ipv4_pcapng();
        // Append an incomplete block header with an impossible length to simulate truncated tail.
        push_u32_le(&mut pcapng, PCAPNG_BLOCK_ENHANCED_PACKET);
        push_u32_le(&mut pcapng, 4096);

        let summary = analyze_pcap_bytes(&pcapng, 500).expect("parse pcapng with bad tail");
        assert_eq!(summary.packet_count, 1);
        assert_eq!(summary.ip_packet_count, 1);
        assert_eq!(summary.destination_ips, vec!["8.8.8.8".to_string()]);
    }
}
