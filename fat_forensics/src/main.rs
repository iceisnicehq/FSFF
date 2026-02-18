use std::collections::BTreeMap;
use std::env;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

// --- Windows Imports for Popups ---
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use winapi::um::winuser::{MessageBoxW, MB_ICONINFORMATION, MB_OK};

// --- Structures ---

#[derive(Debug, Clone)]
struct Bpb {
    oem_name: String,
    bytes_per_sec: u16,
    sec_per_clus: u8,
    rsvd_sec_cnt: u16,
    num_fats: u8,
    root_ent_cnt: u16,
    tot_sec16: u16,
    media: u8,
    fatsz16: u16,
    tot_sec32: u32, // Offset 0x20
    vol_id: u32,
    vol_lab_boot: String,
}

#[derive(Default)]
struct Stats {
    sub_directories: usize,
    total_bytes: u64,
    total_used_clusters: usize,
    slack_space: u64,
    fragmented_files: usize,
    deleted_entries: usize,
    hidden_files: usize,
}

// --- Main Entry ---

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    // MODE A: Command Line "-Dump"
    if args.len() >= 3 && args[1].eq_ignore_ascii_case("-Dump") {
        let filename = &args[2];
        println!(">>> CLI Mode. Dumping: {}", filename);
        process_disk_image(filename)?;
        return Ok(());
    }

    // MODE B: Double Click (GUI Popup)
    if args.len() == 1 {
        let mut report =
            String::from("FAT12/16 Ultimate Forensics Tool v11 (LFN Support)\n------------------------------------\n");
        let mut count = 0;

        let paths = fs::read_dir(".")?;
        for path in paths {
            let entry = path?;
            let p = entry.path();
            if let Some(ext) = p.extension() {
                let ext_str = ext.to_string_lossy().to_lowercase();
                if ["vhd", "img", "bin"].contains(&ext_str.as_str()) {
                    let filename = p.file_name().unwrap().to_string_lossy();
                    match process_disk_image(&p.to_string_lossy()) {
                        Ok(vol_label) => {
                            report.push_str(&format!(
                                "[SUCCESS] Dumped: {} (Vol: {})\n",
                                filename, vol_label
                            ));
                            count += 1;
                        }
                        Err(e) => {
                            report.push_str(&format!("[FAILED]  {}: {}\n", filename, e));
                        }
                    }
                }
            }
        }

        if count == 0 {
            report.push_str("\nNo .vhd, .img, or .bin files found.");
        } else {
            report.push_str(&format!("\nTotal Processed: {}", count));
        }
        show_popup("Forensics Complete", &report);
        return Ok(());
    }

    println!("Usage: fat_forensics.exe -Dump <file>");
    Ok(())
}

// --- Core Logic ---

fn process_disk_image(dump_path: &str) -> io::Result<String> {
    let boot_offset: u64 = 0x10000; // Default offset per your script
    let mut file = File::open(dump_path)?;
    let mut stats = Stats::default();
    let disk_name = Path::new(dump_path)
        .file_stem()
        .unwrap()
        .to_string_lossy();

    // 1. Setup Output Directory
    let extract_root = format!("{}_result", disk_name);
    if Path::new(&extract_root).exists() {
        fs::remove_dir_all(&extract_root)?;
    }
    fs::create_dir(&extract_root)?;

    let log_path = Path::new(&extract_root).join(format!("{}_res.txt", disk_name));
    let mut log_file = File::create(&log_path)?;

    // Helper to log to both Console and File
    let mut log = |msg: String, print: bool| {
        if print {
            println!("{}", msg);
        }
        writeln!(log_file, "{}", msg).unwrap();
    };

    log(
        format!("=== ULTIMATE DISK ANALYSIS: {} ===", disk_name),
        true,
    );
    log(format!("Image: {}", dump_path), true);
    log(format!("Boot Offset: 0x{:X}", boot_offset), true);

    // 2. Read BPB
    file.seek(SeekFrom::Start(boot_offset))?;
    let mut boot_sector = vec![0u8; 512];
    file.read_exact(&mut boot_sector)?;

    let bpb = parse_bpb(&boot_sector);

    // Log BPB Table
    log(format!("\n=== Table 1. BPB Parameters ==="), true);
    log(
        format!(
            "{:<20} | {:<10} | {:<10} | {:<10}",
            "Characteristic", "Offset", "Size", "Value"
        ),
        true,
    );
    log("-".repeat(60), true);
    log(
        format!(
            "{:<20} | 0x03       | 8          | {}",
            "BS_OEMName", bpb.oem_name
        ),
        true,
    );
    log(
        format!(
            "{:<20} | 0x0B       | 2          | {}",
            "BPB_BytsPerSec", bpb.bytes_per_sec
        ),
        true,
    );
    log(
        format!(
            "{:<20} | 0x0D       | 1          | {}",
            "BPB_SecPerClus", bpb.sec_per_clus
        ),
        true,
    );
    log(
        format!(
            "{:<20} | 0x0E       | 2          | {}",
            "BPB_RsvdSecCnt", bpb.rsvd_sec_cnt
        ),
        true,
    );
    log(
        format!(
            "{:<20} | 0x10       | 1          | {}",
            "BPB_NumFATs", bpb.num_fats
        ),
        true,
    );
    log(
        format!(
            "{:<20} | 0x11       | 2          | {}",
            "BPB_RootEntCnt", bpb.root_ent_cnt
        ),
        true,
    );
    log(
        format!(
            "{:<20} | 0x13       | 2          | 0x{:04X} ({})",
            "BPB_TotSec16", bpb.tot_sec16, bpb.tot_sec16
        ),
        true,
    );
    log(
        format!(
            "{:<20} | 0x15       | 1          | 0x{:02X}",
            "BPB_Media", bpb.media
        ),
        true,
    );
    log(
        format!(
            "{:<20} | 0x16       | 2          | {}",
            "BPB_FATSz16", bpb.fatsz16
        ),
        true,
    );
    log(
        format!(
            "{:<20} | 0x20       | 4          | 0x{:08X} ({})",
            "BPB_TotSec32", bpb.tot_sec32, bpb.tot_sec32
        ),
        true,
    );
    log(
        format!(
            "{:<20} | 0x2B       | 11         | {}",
            "BS_VolLab", bpb.vol_lab_boot
        ),
        true,
    );

    // 3. Calculations
    let total_sectors = if bpb.tot_sec16 != 0 {
        bpb.tot_sec16 as u32
    } else {
        bpb.tot_sec32
    };

    let root_dir_sectors =
        ((bpb.root_ent_cnt as u32 * 32) + (bpb.bytes_per_sec as u32 - 1)) / bpb.bytes_per_sec as u32;

    let fat_sz_total = bpb.num_fats as u32 * bpb.fatsz16 as u32;
    let data_sectors = total_sectors - (bpb.rsvd_sec_cnt as u32 + fat_sz_total + root_dir_sectors);

    let count_of_clusters = data_sectors / bpb.sec_per_clus as u32;
    let fat_type = if count_of_clusters < 4085 {
        "FAT12"
    } else {
        "FAT16"
    };

    log(format!("\n=== File System Calculations ==="), true);
    log(format!("1) RootDirSectors = ((BPB_RootEntCnt * 32) + (BPB_BytsPerSec - 1)) / BPB_BytsPerSec = {}", root_dir_sectors), true);
    log(format!("2) DataSectors = BPB_TotSec16 - (BPB_RsvdSecCnt + (BPB_NumFATs * BPB_FATSz16) + RootDirSectors) =   {}", data_sectors), true);
    log(format!("3) CountOfClusters = DataSectors / BPB_SecPerClus = {}", count_of_clusters), true);
    log(format!("File System: {}", fat_type), true);

    // 4. Memory Layout
    let bytes_per_sec = bpb.bytes_per_sec as u64;
    let reserved_start = boot_offset;
    let reserved_end = reserved_start + (bpb.rsvd_sec_cnt as u64 * bytes_per_sec) - 1;

    let fat1_start = reserved_end + 1;
    let fat_size_bytes = bpb.fatsz16 as u64 * bytes_per_sec;
    let fat1_end = fat1_start + fat_size_bytes - 1;

    let root_dir_start = fat1_start + (bpb.num_fats as u64 * fat_size_bytes);
    let root_dir_end = root_dir_start + (root_dir_sectors as u64 * bytes_per_sec) - 1;

    let data_start = root_dir_end + 1;
    let data_end = boot_offset + (total_sectors as u64 * bytes_per_sec) - 1;
    let bytes_per_cluster = bytes_per_sec * bpb.sec_per_clus as u64;

    log(format!("\n=== Memory Layout (Hex) ==="), true);
    log(
        format!(" Reserved:       0x{:X} - 0x{:X}", reserved_start, reserved_end),
        true,
    );
    log(
        format!(" FAT1 Table:     0x{:X} - 0x{:X}", fat1_start, fat1_end),
        true,
    );
    if bpb.num_fats > 1 {
        let fat2_start = fat1_end + 1;
        let fat2_end = fat2_start + fat_size_bytes - 1;
        log(
            format!(" FAT2 Table:     0x{:X} - 0x{:X}", fat2_start, fat2_end),
            true,
        );
    }
    log(
        format!(
            " Root Directory: 0x{:X} - 0x{:X}",
            root_dir_start, root_dir_end
        ),
        true,
    );
    log(
        format!(" Data Region:    0x{:X} - 0x{:X}", data_start, data_end),
        true,
    );

    // 5. Load FAT
    file.seek(SeekFrom::Start(fat1_start))?;
    let mut fat_table = vec![0u8; fat_size_bytes as usize];
    file.read_exact(&mut fat_table)?;

    let mut fat_entries_used = 0;
    for i in 2..(count_of_clusters + 2) {
        let val = get_next_cluster(i as u16, fat_type, &fat_table);
        let eof = if fat_type == "FAT16" { 0xFFF8 } else { 0xFF8 };
        let bad = if fat_type == "FAT16" { 0xFFF7 } else { 0xFF7 };
        if val != 0 && val < bad {
            fat_entries_used += 1;
        } else if val >= eof {
            fat_entries_used += 1;
        }
    }
    log(format!("Used FAT Entries: {}", fat_entries_used), true);

    // 6. Walk File System
    log(format!("\n=== Scanning File System ==="), true);

    let temp_path = Path::new(&extract_root).join("DETECTING_VOL");
    fs::create_dir(&temp_path)?;

    let mut vol_label = String::from("NO_NAME");

    parse_directory(
        &mut file,
        &fat_table,
        root_dir_start,
        true,
        bpb.root_ent_cnt as u32,
        fat_type,
        data_start,
        bytes_per_cluster,
        &temp_path,
        "",
        &mut stats,
        &mut log,
        &mut vol_label,
    )?;

    // Rename folder to Volume Label
    let final_path = Path::new(&extract_root).join(&vol_label);
    if final_path.exists() {
        fs::remove_dir_all(&final_path)?;
    }
    if let Err(_) = fs::rename(&temp_path, &final_path) {
        log(
            format!("Warning: Could not rename root folder to {}", vol_label),
            true,
        );
    }

    // 7. Final Statistics
    log(format!("\n=========================================="), true);
    log(format!("       FINAL STATISTICS (ANSWERS)       "), true);
    log(format!("=========================================="), true);
    log(
        format!("1. Total Subdirectories: {}", stats.sub_directories),
        true,
    );
    log(
        format!(
            "2. Total FAT Entries:    {}",
            if fat_type == "FAT16" {
                fat_size_bytes / 2
            } else {
                (fat_size_bytes * 2) / 3
            }
        ),
        true,
    );
    log(format!("3. Used FAT Entries:     {}", fat_entries_used), true);
    log(
        format!("4. Total Logical Size:   {} bytes", stats.total_bytes),
        true,
    );
    log(
        format!("5. Total Clusters Used:  {}", stats.total_used_clusters),
        true,
    );
    log(
        format!("6. Slack Space:          {} bytes", stats.slack_space),
        true,
    );
    log(
        format!("7. Fragmented Files:     {}", stats.fragmented_files),
        true,
    );
    log(
        format!("8. Deleted Entries:      {}", stats.deleted_entries),
        true,
    );
    log(
        format!("9. Addressable Clusters: {}", count_of_clusters),
        true,
    );
    log(format!("10. Reserved Sectors:    {}", bpb.rsvd_sec_cnt), true);

    Ok(vol_label)
}

// --- Parsers ---

fn parse_bpb(raw: &[u8]) -> Bpb {
    let get_u8 = |o| raw[o];
    let get_u16 = |o| u16::from_le_bytes([raw[o], raw[o + 1]]);
    let get_u32 = |o| u32::from_le_bytes([raw[o], raw[o + 1], raw[o + 2], raw[o + 3]]);
    let get_str = |o, l| String::from_utf8_lossy(&raw[o..o + l]).trim().to_string();

    Bpb {
        oem_name: get_str(3, 8),
        bytes_per_sec: get_u16(11),
        sec_per_clus: get_u8(13),
        rsvd_sec_cnt: get_u16(14),
        num_fats: get_u8(16),
        root_ent_cnt: get_u16(17),
        tot_sec16: get_u16(19),
        media: get_u8(21),
        fatsz16: get_u16(22),
        tot_sec32: get_u32(32),
        vol_id: get_u32(39),
        vol_lab_boot: get_str(43, 11),
    }
}

fn get_next_cluster(cluster: u16, fat_type: &str, fat_table: &[u8]) -> u16 {
    if fat_type == "FAT16" {
        let offset = (cluster as usize) * 2;
        if offset >= fat_table.len() - 1 {
            return 0xFFF8;
        }
        u16::from_le_bytes([fat_table[offset], fat_table[offset + 1]])
    } else {
        // FAT12 Logic
        let offset = (cluster as usize) + ((cluster as usize) / 2);
        if offset >= fat_table.len() - 1 {
            return 0xFF8;
        }
        let val = u16::from_le_bytes([fat_table[offset], fat_table[offset + 1]]);
        if cluster % 2 == 0 {
            val & 0x0FFF
        } else {
            val >> 4
        }
    }
}

fn get_cluster_chain(start: u16, fat_type: &str, fat_table: &[u8]) -> Vec<u16> {
    let mut chain = Vec::new();
    let mut curr = start;
    let eof = if fat_type == "FAT16" { 0xFFF8 } else { 0xFF8 };
    while curr >= 2 && curr < eof && chain.len() < 500 {
        chain.push(curr);
        let next = get_next_cluster(curr, fat_type, fat_table);
        if next == curr || next == 0 {
            break;
        }
        curr = next;
    }
    chain
}

// --- Date/Time Decoder ---
fn decode_dos_date_time(date: u16, time: u16) -> String {
    if date == 0 {
        return "N/A".to_string();
    }
    let year = ((date >> 9) & 0x7F) + 1980;
    let month = (date >> 5) & 0x0F;
    let day = date & 0x1F;

    let hour = (time >> 11) & 0x1F;
    let min = (time >> 5) & 0x3F;
    let sec = (time & 0x1F) * 2;

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hour, min, sec
    )
}

// --- LFN & Directory Parser ---

fn parse_directory<F>(
    file: &mut File,
    fat_table: &[u8],
    dir_offset: u64,
    is_root: bool,
    max_entries: u32,
    fat_type: &str,
    data_start: u64,
    bpc: u64,
    parent_path: &Path,
    indent: &str,
    stats: &mut Stats,
    log: &mut F,
    vol_label: &mut String,
) -> io::Result<()>
where
    F: FnMut(String, bool),
{
    let limit = if is_root { max_entries } else { 65535 };
    let mut lfn_parts: BTreeMap<u8, String> = BTreeMap::new(); // Buffer for LFN parts

    for i in 0..limit {
        let off = dir_offset + (i as u64 * 32);
        file.seek(SeekFrom::Start(off))?;
        let mut raw = [0u8; 32];
        file.read_exact(&mut raw)?;

        if raw[0] == 0x00 {
            break;
        } // End of Dir
        if raw[0] == 0xE5 {
            // Deleted Entry
            stats.deleted_entries += 1;
            lfn_parts.clear(); // Clear LFN buffer on deleted entry
            continue;
        }

        let attr = raw[11];

        // --- 1. LFN Entry Handling (Attribute 0x0F) ---
        if attr == 0x0F {
            let seq_num = raw[0] & 0x1F; // Mask out the 0x40 "Last Entry" bit
            
            let mut name_chars = Vec::new();
            
            // Name 1 (Offset 1, 5 chars)
            for j in 0..5 {
                let o = 1 + (j * 2);
                let c = u16::from_le_bytes([raw[o], raw[o+1]]);
                if c != 0 && c != 0xFFFF { name_chars.push(c); }
            }
            // Name 2 (Offset 14, 6 chars)
            for j in 0..6 {
                let o = 14 + (j * 2);
                let c = u16::from_le_bytes([raw[o], raw[o+1]]);
                if c != 0 && c != 0xFFFF { name_chars.push(c); }
            }
            // Name 3 (Offset 28, 2 chars)
            for j in 0..2 {
                let o = 28 + (j * 2);
                let c = u16::from_le_bytes([raw[o], raw[o+1]]);
                if c != 0 && c != 0xFFFF { name_chars.push(c); }
            }

            let part_str = String::from_utf16_lossy(&name_chars);
            lfn_parts.insert(seq_num, part_str);
            continue; // Go to next entry (do not process as file)
        }

        // --- 2. Volume Label Handling ---
        if (attr & 0x08) != 0 && (attr & 0x10) == 0 {
            let label = String::from_utf8_lossy(&raw[0..11]).trim().to_string();
            *vol_label = label.clone();
            log(
                format!(" Found Volume Label: {} (Offset: 0x{:X})", label, off),
                true,
            );
            lfn_parts.clear(); // Reset buffer
            continue;
        }

        // --- 3. Normal File/Directory Handling ---

        // Determine Filename: Try LFN first, fallback to SFN
        let filename: String;
        if !lfn_parts.is_empty() {
            // Combine parts in order: 1, 2, 3...
            // Note: LFN entries are stored in reverse on disk (N, N-1..), but we keyed them by seq_num
            // so iterating the BTreeMap values gives them in correct order (1, 2, 3...).
            filename = lfn_parts.values().cloned().collect::<String>();
            lfn_parts.clear(); // Consumed
        } else {
            // SFN Fallback
            let name_bytes = &raw[0..8];
            let ext_bytes = &raw[8..11];
            let mut name = String::from_utf8_lossy(name_bytes).to_string();
            let mut ext = String::from_utf8_lossy(ext_bytes).to_string();

            // Clean 0x05 Kanji fix if present
            if name.as_bytes()[0] == 0x05 {
                unsafe {
                    name.as_mut_vec()[0] = 0xE5;
                }
            }
            name = name.trim().to_string();
            ext = ext.trim().to_string();
            filename = if !ext.is_empty() {
                format!("{}.{}", name, ext)
            } else {
                name.clone()
            };
        }
        
        // Safety check: if filename came out empty or just dots (rare edge case), skip
        if filename.is_empty() || filename == "." || filename == ".." {
             lfn_parts.clear(); 
             continue; 
        }

        // Metadata
        let crt_time = u16::from_le_bytes([raw[14], raw[15]]);
        let crt_date = u16::from_le_bytes([raw[16], raw[17]]);
        let mod_time = u16::from_le_bytes([raw[22], raw[23]]);
        let mod_date = u16::from_le_bytes([raw[24], raw[25]]);
        let size = u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]);
        let cluster_hi = u16::from_le_bytes([raw[20], raw[21]]); // FAT32 mostly
        let cluster_lo = u16::from_le_bytes([raw[26], raw[27]]);
        let start_cluster = ((cluster_hi as u32) << 16) | (cluster_lo as u32);

        let created_str = decode_dos_date_time(crt_date, crt_time);
        let mod_str = decode_dos_date_time(mod_date, mod_time);

        // Directory
        if (attr & 0x10) != 0 {
            stats.sub_directories += 1;

            log(format!("{}[{}] (DIR)", indent, filename), true);
            log(
                format!(
                    "{}  Entry Offset: 0x{:X} | Start Cluster: {}",
                    indent, off, start_cluster
                ),
                true,
            );
            log(
                format!(
                    "{}  Created: {} | Modified: {}",
                    indent, created_str, mod_str
                ),
                true,
            );

            let new_path = parent_path.join(&filename);
            if !new_path.exists() {
                fs::create_dir(&new_path)?;
            }

            if start_cluster >= 2 {
                let sub_off = data_start + ((start_cluster as u64 - 2) * bpc);
                parse_directory(
                    file,
                    fat_table,
                    sub_off,
                    false,
                    0,
                    fat_type,
                    data_start,
                    bpc,
                    &new_path,
                    &format!("{}  ", indent),
                    stats,
                    log,
                    vol_label,
                )?;
            }
        } else {
            // File
            let chain = get_cluster_chain(start_cluster as u16, fat_type, fat_table);

            stats.total_bytes += size as u64;
            stats.total_used_clusters += chain.len();

            let phys = chain.len() as u64 * bpc;
            if phys > size as u64 {
                stats.slack_space += phys - size as u64;
            }

            let mut is_frag = false;
            for k in 0..chain.len().saturating_sub(1) {
                if chain[k + 1] != chain[k] + 1 {
                    is_frag = true;
                    break;
                }
            }
            if is_frag {
                stats.fragmented_files += 1;
            }
            if (attr & 0x02) != 0 {
                stats.hidden_files += 1;
            }

            log(format!("{}{}", indent, filename), true);
            log(
                format!(
                    "{}  Offset: 0x{:X} | Size: {} | Clusters: {}",
                    indent, off, size, chain.len()
                ),
                true,
            );
            log(
                format!(
                    "{}  Created: {} | Modified: {}",
                    indent, created_str, mod_str
                ),
                true,
            );

            let dest_path = parent_path.join(&filename);
            extract_file(file, &chain, size, data_start, bpc, dest_path)?;
        }
        
        // Crucial: Clear LFN buffer after using it for a file (or if it wasn't used)
        lfn_parts.clear();
    }
    Ok(())
}

fn extract_file(
    file: &mut File,
    chain: &[u16],
    size: u32,
    start: u64,
    bpc: u64,
    dest: PathBuf,
) -> io::Result<()> {
    if chain.is_empty() {
        return Ok(());
    }
    let mut out = File::create(dest)?;
    let mut rem = size as u64;
    for &c in chain {
        if rem == 0 {
            break;
        }
        let off = start + ((c as u64 - 2) * bpc);
        file.seek(SeekFrom::Start(off))?;
        let to_read = std::cmp::min(bpc, rem);
        let mut buf = vec![0u8; to_read as usize];
        file.read_exact(&mut buf)?;
        out.write_all(&buf)?;
        rem -= to_read;
    }
    Ok(())
}

fn show_popup(title: &str, content: &str) {
    #[cfg(windows)]
    unsafe {
        let wide_title: Vec<u16> = OsStr::new(title)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let wide_content: Vec<u16> = OsStr::new(content)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        MessageBoxW(
            std::ptr::null_mut(),
            wide_content.as_ptr(),
            wide_title.as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        );
    }
    #[cfg(not(windows))]
    println!("{}\n{}", title, content);
}
