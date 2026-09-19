// SPDX-FileCopyrightText: 2025 The vita49-rs Authors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use deku::prelude::*;
use deku::writer::Writer;
use std::io::{Seek, Write};

use crate::packet_header::PacketHeader;
use crate::payload::Payload;

/// Base signal data structure.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, DekuRead, DekuWrite)]
#[deku(
    endian = "endian",
    ctx = "endian: deku::ctx::Endian, _packet_header: &PacketHeader"
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignalData {
    #[deku(
        reader = "Self::read_payload(deku::reader, _packet_header.payload_size_words(), endian)",
        writer = "Self::write_payload(deku::writer, &self.data, endian)"
    )]
    data: Vec<u8>,
}

impl TryFrom<Payload> for SignalData {
    type Error = Payload;

    fn try_from(value: Payload) -> Result<Self, Self::Error> {
        match value {
            Payload::SignalData(c) => Ok(c),
            a => Err(a),
        }
    }
}

impl SignalData {
    /// Create a new, empty signal data packet.
    pub fn new() -> SignalData {
        SignalData::default()
    }

    /// Create a new signal data packet directly from an owned vector (zero-copy).
    ///
    /// # Example
    /// ```
    /// # use std::io;
    /// use vita49::prelude::*;
    /// # fn main() -> Result<(), VitaError> {
    /// let mut packet = Vrt::new_signal_data_packet();
    /// let my_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
    /// *packet.payload_mut() = Payload::SignalData(SignalData::from_owned(my_data));
    /// assert_eq!(packet.signal_payload()?, &[1, 2, 3, 4, 5, 6, 7, 8]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_owned(data: Vec<u8>) -> SignalData {
        SignalData { data }
    }

    /// Create a new signal data packet from an input slice of bytes.
    /// This allocates a new vector under the hood.
    ///
    /// # Example
    /// ```
    /// # use std::io;
    /// use vita49::prelude::*;
    /// # fn main() -> Result<(), VitaError> {
    /// let mut packet = Vrt::new_signal_data_packet();
    /// *packet.payload_mut() = Payload::SignalData(SignalData::from_bytes(&[1, 2, 3, 4, 5, 6, 7, 8]));
    /// assert_eq!(packet.signal_payload()?, &[1, 2, 3, 4, 5, 6, 7, 8]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> SignalData {
        SignalData {
            data: bytes.to_vec(),
        }
    }

    /// Get the data payload as a read-only slice (zero-copy).
    ///
    /// # Example
    /// ```
    /// # use std::io;
    /// use vita49::prelude::*;
    /// # fn main() -> Result<(), VitaError> {
    /// let mut packet = Vrt::new_signal_data_packet();
    /// *packet.payload_mut() = Payload::SignalData(SignalData::from_bytes(&[1, 2, 3, 4, 5, 6, 7, 8]));
    /// let signal_data_payload = packet.payload().signal_data()?;
    /// assert_eq!(signal_data_payload.payload(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn payload(&self) -> &[u8] {
        &self.data
    }

    /// Get the data payload as a mutable slice (zero-copy).
    ///
    /// Use this to edit a payload where it sits, such as byte swapping samples,
    /// rather than building a new vector and calling [`Self::set_payload`]. The
    /// length cannot change, so the packet size stays correct and there is no
    /// need to call [`crate::Vrt::update_packet_size`]. To change the length,
    /// use [`Self::resize_payload`].
    ///
    /// # Example
    /// ```
    /// # use std::io;
    /// use vita49::prelude::*;
    /// # fn main() -> Result<(), VitaError> {
    /// let mut packet = Vrt::new_signal_data_packet();
    /// packet.set_signal_payload(&[1, 2, 3, 4])?;
    /// let sig_data = packet.payload_mut().signal_data_mut()?;
    /// sig_data.payload_mut().reverse();
    /// assert_eq!(packet.signal_payload()?, &[4, 3, 2, 1]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Consume the struct and take ownership of the underlying payload bytes (zero-copy).
    ///
    /// # Example
    /// ```
    /// # use std::io;
    /// use vita49::prelude::*;
    /// # fn main() -> Result<(), VitaError> {
    /// let mut packet = Vrt::new_signal_data_packet();
    /// packet.set_signal_payload(&[1, 2, 3, 4, 5, 6, 7, 8])?;
    /// let signal_data_payload = packet.into_payload().into_signal_data()?;
    /// let payload_vec = signal_data_payload.into_payload();
    /// assert_eq!(payload_vec, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn into_payload(self) -> Vec<u8> {
        self.data
    }

    /// Set the packet payload to some raw bytes.
    /// Accepts either a `Vec<u8>` (zero-copy) or a `&[u8]` slice (allocates).
    ///
    /// # Example
    /// ```
    /// # use std::io;
    /// use vita49::prelude::*;
    /// # fn main() -> Result<(), VitaError> {
    /// let mut packet = Vrt::new_signal_data_packet();
    /// let sig_data = packet.payload_mut().signal_data_mut()?;
    /// sig_data.set_payload(&[1, 2, 3, 4, 5, 6, 7, 8]);
    /// assert_eq!(packet.signal_payload()?, &[1, 2, 3, 4, 5, 6, 7, 8]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_payload(&mut self, bytes: impl Into<Vec<u8>>) {
        self.data = bytes.into()
    }

    /// Resize the payload and get it back as a mutable slice to fill.
    ///
    /// Reuses the vector the packet already holds, so restating one packet per
    /// block of samples does not allocate a payload for every block the way
    /// [`Self::set_payload`] does. Growing the payload zeroes the new bytes,
    /// and shrinking it truncates.
    ///
    /// The packet size field counts the payload, so a caller reaching this
    /// directly must call [`crate::Vrt::update_packet_size`] afterwards.
    /// [`crate::Vrt::resize_signal_payload`] does that for you.
    ///
    /// # Example
    /// ```
    /// # use std::io;
    /// use vita49::prelude::*;
    /// # fn main() -> Result<(), VitaError> {
    /// let mut packet = Vrt::new_signal_data_packet();
    /// packet.set_signal_payload(&[1, 2, 3, 4])?;
    /// let sig_data = packet.payload_mut().signal_data_mut()?;
    /// sig_data.resize_payload(8).copy_from_slice(&[5, 6, 7, 8, 9, 10, 11, 12]);
    /// packet.update_packet_size();
    /// assert_eq!(packet.signal_payload()?, &[5, 6, 7, 8, 9, 10, 11, 12]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn resize_payload(&mut self, len: usize) -> &mut [u8] {
        self.data.resize(len, 0);
        &mut self.data
    }

    /// Gets the size of the payload in 32-bit words.
    pub fn size_words(&self) -> u16 {
        // Ceiling division to make sure we account for padding
        ((self.data.len() + 3) / 4) as u16
    }

    /// Gets the size of the payload in bytes.
    pub fn payload_size_bytes(&self) -> usize {
        self.data.len()
    }

    fn read_payload<R: std::io::Read + std::io::Seek>(
        reader: &mut deku::reader::Reader<R>,
        words: usize,
        endian: deku::ctx::Endian,
    ) -> Result<Vec<u8>, deku::DekuError> {
        let byte_len = words * 4;

        let mut data = vec![0u8; byte_len];

        reader.read_bytes(byte_len, &mut data)?;

        if endian == deku::ctx::Endian::Little {
            for chunk in data.chunks_exact_mut(4) {
                chunk.reverse();
            }
        }

        Ok(data)
    }

    fn write_payload<W: Write + Seek>(
        writer: &mut Writer<W>,
        data: &[u8],
        endian: deku::ctx::Endian,
    ) -> Result<(), deku::DekuError> {
        let remainder = data.len() % 4;
        let pad_len = if remainder != 0 { 4 - remainder } else { 0 };

        if endian == deku::ctx::Endian::Little {
            let mut padded = Vec::with_capacity(data.len() + pad_len);
            padded.extend_from_slice(data);
            padded.resize(data.len() + pad_len, 0u8);
            for chunk in padded.chunks_exact_mut(4) {
                chunk.reverse();
            }
            writer.write_bytes(&padded)?;
        } else {
            writer.write_bytes(data)?;
            if pad_len != 0 {
                let padding = vec![0u8; pad_len];
                writer.write_bytes(&padding)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn little_endian_padded_payload_round_trip() {
        // A 6-byte payload requires 2 bytes of padding to form two 32-bit words (8 bytes).
        let raw_payload = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        // Write in Little Endian
        let mut buf = Vec::new();
        {
            let mut writer = Writer::new(Cursor::new(&mut buf));
            SignalData::write_payload(&mut writer, &raw_payload, deku::ctx::Endian::Little)
                .unwrap();
            writer.finalize().unwrap();
        }
        assert_eq!(buf.len(), 8, "payload must be padded to 8 bytes (2 words)");

        // Word 0 was [0x11, 0x22, 0x33, 0x44] -> in LE wire order: [0x44, 0x33, 0x22, 0x11]
        assert_eq!(&buf[0..4], &[0x44, 0x33, 0x22, 0x11]);
        // Word 1 was [0x55, 0x66, 0x00, 0x00] -> in LE wire order: [0x00, 0x00, 0x66, 0x55]
        assert_eq!(
            &buf[4..8],
            &[0x00, 0x00, 0x66, 0x55],
            "padding must be reversed along with data bytes in LE word"
        );

        // Read back in Little Endian
        let mut cursor = Cursor::new(&buf);
        let mut reader = deku::reader::Reader::new(&mut cursor);
        let read_data =
            SignalData::read_payload(&mut reader, 2, deku::ctx::Endian::Little).unwrap();

        // Data bytes must be restored to their original positions (followed by zero padding)
        assert_eq!(&read_data[0..6], &raw_payload[..]);
        assert_eq!(&read_data[6..8], &[0x00, 0x00]);
    }

    #[test]
    fn resize_payload_keeps_the_same_allocation() {
        let mut sig_data = SignalData::from_owned(vec![0u8; 4096]);
        let first = sig_data.payload().as_ptr();

        sig_data.resize_payload(4096).fill(7);
        assert_eq!(
            sig_data.payload().as_ptr(),
            first,
            "a resize to the same \
            length must not move the buffer"
        );

        // Shrinking and growing back stays inside the capacity already held.
        sig_data.resize_payload(16);
        sig_data.resize_payload(4096);
        assert_eq!(sig_data.payload().as_ptr(), first);
    }

    #[test]
    fn resize_payload_zeroes_growth_and_truncates() {
        let mut sig_data = SignalData::from_bytes(&[1, 2, 3, 4]);

        assert_eq!(sig_data.resize_payload(6), &[1, 2, 3, 4, 0, 0]);
        assert_eq!(sig_data.resize_payload(2), &[1, 2]);
        assert_eq!(sig_data.payload_size_bytes(), 2);
    }

    #[test]
    fn payload_mut_edits_in_place() {
        let mut sig_data = SignalData::from_bytes(&[1, 2, 3, 4]);
        sig_data.payload_mut().reverse();
        assert_eq!(sig_data.payload(), &[4, 3, 2, 1]);
    }
}
