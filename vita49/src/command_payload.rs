// SPDX-FileCopyrightText: 2025 The vita49-rs Authors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{prelude::*, Ack, Cancellation, Control, ControlAckMode, QueryAck};
use deku::prelude::*;

/// Command payload enumeration. Command payloads can take several different forms depending
/// on various header and CAM fields. Basically, here's the breakdown:
///
/// ```text
///                              ┌──────────────────┐                                          
///                              │                  │                                          
///                    ┌─────────┤  Command Packet  ├─────────┐                                
///                    │         │      Types       │         │                                
///                    │         │                  │         │                                
///           ┌────────▼───────┐ └──────────────────┘  ┌──────▼──────┐                         
///           │                │                       │             │                         
///         ┌─┤ Control Packet ├──┐                  ┌─┤  ACK Packet ├──┬──────────────┐       
///         │ │     Types      │  │                  │ │    Types    │  │              │       
///         │ │                │  │                  │ │             │  │              │       
///         │ └────────────────┘  │                  │ └─────────────┘  │              │       
///         │                     │                  │                  │              │       
/// ┌───────▼────────┐   ┌────────▼───────┐    ┌─────▼───────────┐ ┌────▼─────┐  ┌─────▼──────┐
/// │    Control     │   │  Cancellation  │    │  Validation ACK │ │ Exec ACK │  │ Query ACK  │
/// │     Packet     │   │     Packet     │    │      Packet     │ │  Packet  │  │   Packet   │
/// └────────────────┘   └────────────────┘    └─────────────────┘ └──────────┘  └────────────┘
/// ```
///
/// For the actual packet types, here are some attributes:
/// 1. Control Packet
///    - Includes all CIF indicators
///    - In Action Mode 0, will NOT include CIF fields
///    - In other Action Modes, WILL include CIF fields
/// 2. Cancellation Packet
///    - Only includes CIF indicator fields (no real data fields)
/// 3. Validation ACK
///    - Can include warning indicators/fields and error indicators/fields
/// 4. Exec ACK
///    - Can include warning indicators/fields and error indicators/fields
/// 5. Query ACK
///    - Very similar to a context packet, this will include all CIF indicators and fields.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, DekuRead, DekuWrite)]
#[deku(
    endian = "endian",
    ctx = "endian: deku::ctx::Endian, cam: &ControlAckMode, packet_header: &PacketHeader",
    id = "CommandPayload::derive_type(cam, packet_header)?"
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CommandPayload {
    /// Payload for a control packet.
    #[deku(id = "CommandPayload::Control(_)")]
    Control(Control),
    /// Payload for a cancellation packet.
    #[deku(id = "CommandPayload::Cancellation(_)")]
    Cancellation(Cancellation),
    /// Payload for a validation ACK packet.
    #[deku(id = "CommandPayload::ValidationAck(_)")]
    ValidationAck(#[deku(ctx = "cam")] Ack),
    /// Payload for a execution ACK packet.
    #[deku(id = "CommandPayload::ExecAck(_)")]
    ExecAck(#[deku(ctx = "cam")] Ack),
    /// Payload for a query ACK packet.
    #[deku(id = "CommandPayload::QueryAck(_)")]
    QueryAck(QueryAck),
}

impl CommandPayload {
    /// Determine the type of command payload based on CAM field and VRT packet header.
    ///
    /// # Errors
    /// An error is returned when the packet is not a command packet, or when an ACK packet's CAM
    /// field does not select exactly one of validation, execution, or query state.
    fn derive_type(
        cam: &ControlAckMode,
        packet_header: &PacketHeader,
    ) -> Result<CommandPayload, DekuError> {
        if packet_header
            .is_ack_packet()
            .map_err(|err| DekuError::Parse(err.to_string().into()))?
        {
            let selected = [cam.validation(), cam.execution(), cam.state()]
                .iter()
                .filter(|&&x| x)
                .count();
            if selected != 1 {
                return Err(DekuError::Parse(
                    format!(
                        "CAM field in ACK packet selects {selected} of validation, exec, \
                         or query state - exactly one is required"
                    )
                    .into(),
                ));
            }
            if cam.validation() {
                Ok(CommandPayload::ValidationAck(Ack::default()))
            } else if cam.execution() {
                Ok(CommandPayload::ExecAck(Ack::default()))
            } else {
                Ok(CommandPayload::QueryAck(QueryAck::default()))
            }
        } else if packet_header
            .is_cancellation_packet()
            .map_err(|err| DekuError::Parse(err.to_string().into()))?
        {
            Ok(CommandPayload::Cancellation(Cancellation::default()))
        } else {
            Ok(CommandPayload::Control(Control::default()))
        }
    }

    /// Get the size of the command payload (in 32-bit words).
    pub fn size_words(&self) -> u16 {
        match self {
            CommandPayload::Control(p) => p.size_words(),
            CommandPayload::Cancellation(p) => p.size_words(),
            CommandPayload::ValidationAck(p) => p.size_words(),
            CommandPayload::ExecAck(p) => p.size_words(),
            CommandPayload::QueryAck(p) => p.size_words(),
        }
    }

    /// Gets a reference to the control payload. This "unwraps"
    /// the generic `CommandPayload` into a `Control` payload.
    ///
    /// # Errors
    /// This function will return an error if run on a packet other
    /// than a control packet.
    ///
    /// # Example
    /// ```
    /// use vita49::prelude::*;
    /// let packet = Vrt::new_control_packet();
    /// let command = packet.payload().command().unwrap();
    /// let control = command.payload().control().unwrap();
    /// assert_eq!(control.bandwidth_hz(), None);
    /// ```
    pub fn control(&self) -> Result<&Control, VitaError> {
        match self {
            CommandPayload::Control(p) => Ok(p),
            _ => Err(VitaError::ControlOnly),
        }
    }

    /// Gets a mutable reference to the control payload. This "unwraps"
    /// the generic `CommandPayload` into a `Control` payload.
    ///
    /// # Errors
    /// This function will return an error if run on a packet other
    /// than a control packet.
    ///
    /// # Example
    /// ```
    /// use vita49::prelude::*;
    /// let mut packet = Vrt::new_control_packet();
    /// let mut command = packet.payload_mut().command_mut().unwrap();
    /// let mut control = command.payload_mut().control_mut().unwrap();
    /// control.set_bandwidth_hz(Some(64e6));
    /// assert_eq!(control.bandwidth_hz(), Some(64e6));
    /// ```
    pub fn control_mut(&mut self) -> Result<&mut Control, VitaError> {
        match self {
            CommandPayload::Control(p) => Ok(p),
            _ => Err(VitaError::ControlOnly),
        }
    }

    /// Gets a reference to the cancellation payload. This "unwraps"
    /// the generic `CommandPayload` into a `Cancellation` payload.
    ///
    /// # Errors
    /// This function will return an error if run on a packet other
    /// than a cancellation packet.
    ///
    /// # Example
    /// ```
    /// use vita49::prelude::*;
    /// let packet = Vrt::new_cancellation_packet();
    /// let command = packet.payload().command().unwrap();
    /// let cancel = command.payload().cancellation().unwrap();
    /// assert!(!cancel.cif0().bandwidth());
    /// ```
    pub fn cancellation(&self) -> Result<&Cancellation, VitaError> {
        match self {
            CommandPayload::Cancellation(p) => Ok(p),
            _ => Err(VitaError::CancellationOnly),
        }
    }

    /// Gets a reference to the cancellation payload. This "unwraps"
    /// the generic `CommandPayload` into a `Cancellation` payload.
    ///
    /// # Errors
    /// This function will return an error if run on a packet other
    /// than a cancellation packet.
    ///
    /// # Example
    /// ```
    /// use vita49::prelude::*;
    /// let mut packet = Vrt::new_cancellation_packet();
    /// let command = packet.payload_mut().command_mut().unwrap();
    /// let cancel = command.payload_mut().cancellation_mut().unwrap();
    /// cancel.cif0_mut().set_bandwidth();
    /// assert!(cancel.cif0().bandwidth());
    /// ```
    pub fn cancellation_mut(&mut self) -> Result<&mut Cancellation, VitaError> {
        match self {
            CommandPayload::Cancellation(p) => Ok(p),
            _ => Err(VitaError::CancellationOnly),
        }
    }

    /// Gets a reference to the validation ack payload. This "unwraps"
    /// the generic `CommandPayload` into an [`Ack`] payload.
    ///
    /// # Errors
    /// This function will return an error if run on a packet other
    /// than a validation ack packet.
    ///
    /// # Example
    /// ```
    /// use vita49::prelude::*;
    /// use vita49::command_prelude::*;
    /// let packet = Vrt::new_validation_ack_packet();
    /// let command = packet.payload().command().unwrap();
    /// let ack = command.payload().validation_ack().unwrap();
    /// assert!(ack.bandwidth().is_none());
    /// ```
    pub fn validation_ack(&self) -> Result<&Ack, VitaError> {
        match self {
            CommandPayload::ValidationAck(p) => Ok(p),
            _ => Err(VitaError::ValidationAckOnly),
        }
    }

    /// Gets a mutable reference to the validation ack payload. This "unwraps"
    /// the generic `CommandPayload` into an [`Ack`] payload.
    ///
    /// # Errors
    /// This function will return an error if run on a packet other
    /// than a validation ack packet.
    ///
    /// # Example
    /// ```
    /// use vita49::prelude::*;
    /// use vita49::command_prelude::*;
    /// let mut packet = Vrt::new_validation_ack_packet();
    /// let command = packet.payload_mut().command_mut().unwrap();
    /// let ack = command.payload_mut().validation_ack_mut().unwrap();
    /// let mut response = AckResponse::default();
    /// response.set_param_out_of_range();
    /// ack.set_bandwidth(AckLevel::Error, Some(response));
    /// assert!(ack.bandwidth().is_some())
    /// ```
    pub fn validation_ack_mut(&mut self) -> Result<&mut Ack, VitaError> {
        match self {
            CommandPayload::ValidationAck(p) => Ok(p),
            _ => Err(VitaError::ValidationAckOnly),
        }
    }

    /// Gets a reference to the exec ack payload. This "unwraps"
    /// the generic `CommandPayload` into an [`Ack`] payload.
    ///
    /// # Errors
    /// This function will return an error if run on a packet other
    /// than a exec ack packet.
    ///
    /// # Example
    /// ```
    /// use vita49::prelude::*;
    /// use vita49::command_prelude::*;
    /// let packet = Vrt::new_exec_ack_packet();
    /// let command = packet.payload().command().unwrap();
    /// let ack = command.payload().exec_ack().unwrap();
    /// assert!(ack.bandwidth().is_none());
    /// ```
    pub fn exec_ack(&self) -> Result<&Ack, VitaError> {
        match self {
            CommandPayload::ExecAck(p) => Ok(p),
            _ => Err(VitaError::ExecAckOnly),
        }
    }

    /// Gets a mutable reference to the exec ack payload. This "unwraps"
    /// the generic `CommandPayload` into an [`Ack`] payload.
    ///
    /// # Errors
    /// This function will return an error if run on a packet other
    /// than a exec ack packet.
    ///
    /// # Example
    /// ```
    /// use vita49::prelude::*;
    /// use vita49::command_prelude::*;
    /// let mut packet = Vrt::new_exec_ack_packet();
    /// let command = packet.payload_mut().command_mut().unwrap();
    /// let ack = command.payload_mut().exec_ack_mut().unwrap();
    /// let mut response = AckResponse::default();
    /// response.set_param_out_of_range();
    /// ack.set_bandwidth(AckLevel::Error, Some(response));
    /// assert!(ack.bandwidth().is_some())
    /// ```
    pub fn exec_ack_mut(&mut self) -> Result<&mut Ack, VitaError> {
        match self {
            CommandPayload::ExecAck(p) => Ok(p),
            _ => Err(VitaError::ExecAckOnly),
        }
    }

    /// Gets a reference to the query ack payload. This "unwraps"
    /// the generic `CommandPayload` into an [`QueryAck`] payload.
    ///
    /// # Errors
    /// This function will return an error if run on a packet other
    /// than a query ack packet.
    ///
    /// # Example
    /// ```
    /// use vita49::prelude::*;
    /// use vita49::command_prelude::*;
    /// let packet = Vrt::new_query_ack_packet();
    /// let command = packet.payload().command().unwrap();
    /// let ack = command.payload().query_ack().unwrap();
    /// assert!(ack.bandwidth_hz().is_none());
    /// ```
    pub fn query_ack(&self) -> Result<&QueryAck, VitaError> {
        match self {
            CommandPayload::QueryAck(p) => Ok(p),
            _ => Err(VitaError::QueryAckOnly),
        }
    }

    /// Gets a mutable reference to the query ack payload. This "unwraps"
    /// the generic `CommandPayload` into an [`QueryAck`] payload.
    ///
    /// # Errors
    /// This function will return an error if run on a packet other
    /// than a query ack packet.
    ///
    /// # Example
    /// ```
    /// use vita49::prelude::*;
    /// use vita49::command_prelude::*;
    /// let mut packet = Vrt::new_query_ack_packet();
    /// let command = packet.payload_mut().command_mut().unwrap();
    /// let ack = command.payload_mut().query_ack_mut().unwrap();
    /// ack.set_bandwidth_hz(Some(100e6));
    /// assert!(ack.bandwidth_hz().is_some())
    /// ```
    pub fn query_ack_mut(&mut self) -> Result<&mut QueryAck, VitaError> {
        match self {
            CommandPayload::QueryAck(p) => Ok(p),
            _ => Err(VitaError::QueryAckOnly),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Vrt;

    /// A validation ACK packet is a 4-byte header, a 4-byte stream ID, then the CAM word, so the
    /// CAM occupies bytes 8..12, big-endian.
    const CAM_OFFSET: usize = 8;

    /// Serialize a well-formed validation ACK packet and rewrite its CAM word.
    fn ack_bytes_with_cam(patch: impl FnOnce(u32) -> u32) -> Vec<u8> {
        let mut bytes = Vrt::new_validation_ack_packet().to_bytes().unwrap();
        let cam = u32::from_be_bytes(bytes[CAM_OFFSET..CAM_OFFSET + 4].try_into().unwrap());
        // Guard the offset assumption above: the validation bit must be set.
        assert_ne!(cam & (1 << 20), 0, "CAM_OFFSET does not point at the CAM");
        bytes[CAM_OFFSET..CAM_OFFSET + 4].copy_from_slice(&patch(cam).to_be_bytes());
        bytes
    }

    #[test]
    fn well_formed_validation_ack_round_trips() {
        let bytes = ack_bytes_with_cam(|cam| cam);
        let parsed = Vrt::try_from(bytes.as_ref()).unwrap();
        let command = parsed.payload().command().unwrap();
        assert!(command.payload().validation_ack().is_ok());
    }

    #[test]
    fn ack_selecting_no_sub_type_is_a_parse_error() {
        // Clear validation (20), execution (19) and query state (18).
        let bytes = ack_bytes_with_cam(|cam| cam & !(0b111 << 18));
        assert!(Vrt::try_from(bytes.as_ref()).is_err());
    }

    #[test]
    fn ack_selecting_multiple_sub_types_is_a_parse_error() {
        // Set execution (19) alongside the validation bit already set.
        let bytes = ack_bytes_with_cam(|cam| cam | (1 << 19));
        assert!(Vrt::try_from(bytes.as_ref()).is_err());
    }

    #[test]
    fn serializing_an_ack_with_an_ambiguous_cam_is_an_error() {
        let mut packet = Vrt::new_validation_ack_packet();
        let command = packet.payload_mut().command_mut().unwrap();
        let mut cam = command.cam();
        cam.set_execution();
        command.set_cam(cam);
        assert!(packet.to_bytes().is_err());
    }
}
