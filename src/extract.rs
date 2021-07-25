use byteorder::{LittleEndian, ReadBytesExt};
use memmap::Mmap;
use num::NumCast;
use rayon::prelude::*;

use std::fs::{create_dir_all, File, write};
use std::path::Path;

use anyhow::{ensure, Result};

// == Errors ==
#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("Not enough data.")]
    NotEnoughData,

    #[error("Header checksum does not match contents.")]
    InvalidChecksum,

    #[error("Could not write all files successfully: {0:?}")]
    WriteError(Vec<anyhow::Error>),
}

// == Extractfiles ==
/// This struct includes the information of the extracted files as you can see from the attributes.
pub struct ExtractFile {
    /// This attribute holds the filename of the given section in the `.nds` ROM.
    pub name:   &'static str,

    /// This attribute holds the offset of the given section in the `.nds` ROM. In other words:
    /// After how many bytes the actual section starts.
    pub offset: u32,

    /// This attribute holds how long/big the section is.
    pub len:    u32,
}

impl ExtractFile {

    pub const HEADER: Self = Self {
        name: "header.bin",
        offset: 0,
        len: 0x84,
    };

    pub const ARM9: Self = Self {
        name: "arm9.bin",
        offset: 0x20,
        len: 0x2c,
    }

    pub const ARM7: Self = Self {
        name: "arm7.bin",
        offset: 0x30,
        len: 0x3c,
    }

    pub const FNT: Self = Self {
        name: "fnt.bin",
        offset: 0x40,
        len: 0x44,
    }

    pub const FAT: Self = Self {
        name: "fat.bin",
        offset: 0x48,
        len: 0x4c,
    }

}

/// Extracts files from an NDS ROM to a given path.
#[derive(Debug)]
pub struct Extractor {
    /// A memmap of the ROM to allow easy reading for potentially large files.
    data: Mmap,
}

impl Extractor {
    pub fn new<P: AsRef<Path>>(path: P, check_crc: bool) -> Result<Self> {
        let root = path.as_ref();

        let file = File::open(root)?;
        let data = unsafe { Mmap::map(&file)? };

        ensure!(data.len() >= 0x160, ExtractError::NotEnoughData);

        if check_crc {
            let checksum = (&data[0x15E..]).read_u16::<LittleEndian>()?;
            let crc = crate::util::crc::crc16(&data[0..0x15E]);

            ensure!(crc == checksum, ExtractError::InvalidChecksum);
        }

        Ok(Self { data })
    }

    /// Extracts the ROM to the given path. An error is returned
    /// if there are issues with the ROM structure, or if there is
    /// an issue writing files.
    pub fn extract<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        use nitro_fs::FileSystem;

        let root = path.as_ref();

        create_dir_all(root)?;

        self.write(
            root.join("header.bin"),
            0,
            self.read_u32(Header::Size as usize)?,
            )?;
        self.write(
            root.join("arm9.bin"),
            self.read_u32(Header::Arm9Offset as usize)?,
            self.read_u32(Header::Arm9Len as usize)?,
            )?;
        self.write(
            root.join("arm7.bin"),
            self.read_u32(Header::Arm7Offset as usize)?,
            self.read_u32(Header::Arm7Len as usize)?,
            )?;

        let overlay_path = root.join("overlay");
        let file_path = root.join("data");

        create_dir_all(&overlay_path)?;
        create_dir_all(&file_path)?;

        let fs = FileSystem::new(self.fnt()?, self.fat()?)?;

        let errors = fs
            .overlays()
            .par_iter()
            .filter_map(|file| {
                match self.write(
                    &overlay_path.join(&file.path),
                    file.alloc.start,
                    file.alloc.len(),
                    ) {
                    Ok(_) => None,
                    Err(why) => Some(why),
                }
            })
        .collect::<Vec<anyhow::Error>>();

        ensure!(errors.is_empty(), ExtractError::WriteError(errors));

        let errors = fs
            .files()
            .par_iter()
            .filter_map(|file| {
                match self.write(
                    &file_path.join(&file.path),
                    file.alloc.start,
                    file.alloc.len(),
                    ) {
                    Ok(_) => None,
                    Err(why) => Some(why),
                }
            })
        .collect::<Vec<anyhow::Error>>();

        ensure!(errors.is_empty(), ExtractError::WriteError(errors));

        Ok(())
    }

    /// A utility to make it easier to write chunks of the ROM to files.
    /// Copies `len` bytes from the ROM starting from `offset` into the file
    /// denoted by `path`
    fn write<P, N1, N2>(&self, path: P, offset: N1, len: N2) -> Result<()>
        where
            P: AsRef<Path>,
            N1: NumCast,
            N2: NumCast,
            {
                use std::fs::write;

                let offset: usize = NumCast::from(offset).unwrap();
                let len: usize = NumCast::from(len).unwrap();

                ensure!(self.data.len() >= offset + len, ExtractError::NotEnoughData);

                {
                    let parent = path.as_ref().parent().unwrap_or(Path::new(""));

                    if !parent.exists() {
                        create_dir_all(parent)?;
                    }
                }

                write(path, &self.data[offset..offset + len])?;

                Ok(())
            }

    fn write(&self, extract_file: ExtractFile) -> Result<()> {

    }

    /// Reads a u32 from `data` at the given offset.
    fn read_u32(&self, offset: usize) -> Result<u32> {
        let value = (&self.data[offset..]).read_u32::<LittleEndian>()?;
        Ok(value)
    }

    fn fat(&self) -> Result<&[u8]> {
        let fat_start = self.read_u32(Header::FatOffset as usize)? as usize;
        let fat_len = self.read_u32(Header::FatLen as usize)? as usize;

        ensure!(
            self.data.len() > fat_start + fat_len,
            ExtractError::NotEnoughData
            );

        Ok(&self.data[fat_start..fat_start + fat_len])
    }

    fn fnt(&self) -> Result<&[u8]> {
        let fnt_start = self.read_u32(Header::FntOffset as usize)? as usize;
        let fnt_len = self.read_u32(Header::FntLen as usize)? as usize;

        ensure!(
            self.data.len() > fnt_start + fnt_len,
            ExtractError::NotEnoughData
            );

        Ok(&self.data[fnt_start..fnt_start + fnt_len])
    }
}
