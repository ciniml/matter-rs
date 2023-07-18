/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

use std::convert::TryInto;

use num_derive::FromPrimitive;

use super::common::*;
use crate::{error::Error, transport::packet::Packet};

#[allow(dead_code)]
#[derive(Debug, Copy, Clone, FromPrimitive, PartialEq)]
pub enum GeneralCode {
    Success = 0,
    Failure = 1,
    BadPrecondition = 2,
    OutOfRange = 3,
    BadRequest = 4,
    Unsupported = 5,
    Unexpected = 6,
    ResourceExhausted = 7,
    Busy = 8,
    Timeout = 9,
    Continue = 10,
    Aborted = 11,
    InvalidArgument = 12,
    NotFound = 13,
    AlreadyExists = 14,
    PermissionDenied = 15,
    DataLoss = 16,
}

#[derive(Debug, Copy, Clone, FromPrimitive, PartialEq)]
pub enum ProtocolCode {
    SessionEstablishmentSuccess = 0,
    NoSharedTrustRoots = 1,
    InvalidParameter = 2,
    CloseSession = 3,
    Busy = 4,
}

pub fn create_status_report(
    proto_tx: &mut Packet,
    general_code: GeneralCode,
    proto_id: u32,
    proto_code: u16,
    proto_data: Option<&[u8]>,
) -> Result<(), Error> {
    proto_tx.set_proto_id(PROTO_ID_SECURE_CHANNEL as u16);
    proto_tx.set_proto_opcode(OpCode::StatusReport as u8);
    let wb = proto_tx.get_writebuf()?;
    wb.le_u16(general_code as u16)?;
    wb.le_u32(proto_id)?;
    wb.le_u16(proto_code)?;
    if let Some(s) = proto_data {
        wb.copy_from_slice(s)?;
    }

    Ok(())
}

#[derive(Debug)]
pub struct StatusReportView<'a> {
    pub general_code: GeneralCode,
    pub proto_id: u32,
    pub proto_code: ProtocolCode,
    pub proto_data: &'a [u8],
}

pub fn parse_status_report(buffer: &[u8]) -> Result<StatusReportView, Error> {
    if buffer.len() < 8 {
        Err(Error::Invalid)
    } else {
        let general_code = num::FromPrimitive::from_u16(u16::from_le_bytes(buffer[0..2].try_into().unwrap()))
            .ok_or(Error::InvalidData)?;
        let proto_id = u32::from_le_bytes(buffer[2..6].try_into().unwrap());
        let proto_code = num::FromPrimitive::from_u16(u16::from_le_bytes(buffer[6..8].try_into().unwrap()))
            .ok_or(Error::InvalidData)?;
        let proto_data = &buffer[8..];
        Ok(StatusReportView {
            general_code,
            proto_id,
            proto_code,
            proto_data,
        })
    }
}