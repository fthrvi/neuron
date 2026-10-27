use agave_feature_set::FeatureSet;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use solana_address::Address;
use solana_precompile_error::PrecompileError;

pub struct Precompile {
    pub program_id: Address,
    pub feature: Option<Address>,
}

impl Precompile {
    pub fn verify(
        &self,
        data: &[u8],
        instruction_datas: &[&[u8]],
        _feature_set: &FeatureSet,
    ) -> Result<(), PrecompileError> {
        verify_ed25519(data, instruction_datas)
    }
}

static PRECOMPILES: [Precompile; 1] = [Precompile {
    program_id: solana_sdk_ids::ed25519_program::ID,
    feature: None,
}];

pub fn get_precompiles() -> &'static [Precompile] {
    &PRECOMPILES
}

pub fn is_precompile(
    program_id: &Address,
    feature_active: impl Fn(&Address) -> bool,
) -> bool {
    get_precompile(program_id, feature_active).is_some()
}

pub fn get_precompile(
    program_id: &Address,
    feature_active: impl Fn(&Address) -> bool,
) -> Option<&'static Precompile> {
    PRECOMPILES.iter().find(|precompile| {
        &precompile.program_id == program_id
            && match precompile.feature.as_ref() {
                Some(feature) => feature_active(feature),
                None => true,
            }
    })
}

fn verify_ed25519(data: &[u8], instruction_datas: &[&[u8]]) -> Result<(), PrecompileError> {
    if data.len() < 2 {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    let signatures = data[0] as usize;
    let header_end = 2usize
        .checked_add(signatures.checked_mul(14).ok_or(PrecompileError::InvalidDataOffsets)?)
        .ok_or(PrecompileError::InvalidDataOffsets)?;
    if signatures == 0 || header_end > data.len() {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    for index in 0..signatures {
        let base = 2 + index * 14;
        let field = |offset: usize| {
            u16::from_le_bytes([data[base + offset], data[base + offset + 1]])
        };
        let signature_offset = field(0) as usize;
        let signature_ix = field(2);
        let public_key_offset = field(4) as usize;
        let public_key_ix = field(6);
        let message_offset = field(8) as usize;
        let message_size = field(10) as usize;
        let message_ix = field(12);
        let select = |instruction_index: u16| -> Result<&[u8], PrecompileError> {
            if instruction_index == u16::MAX {
                Ok(data)
            } else {
                instruction_datas
                    .get(instruction_index as usize)
                    .copied()
                    .ok_or(PrecompileError::InvalidDataOffsets)
            }
        };
        let signature_data = select(signature_ix)?;
        let public_key_data = select(public_key_ix)?;
        let message_data = select(message_ix)?;
        let signature: [u8; 64] = slice(signature_data, signature_offset, 64)?
            .try_into()
            .map_err(|_| PrecompileError::InvalidSignature)?;
        let public_key: [u8; 32] = slice(public_key_data, public_key_offset, 32)?
            .try_into()
            .map_err(|_| PrecompileError::InvalidPublicKey)?;
        let message = slice(message_data, message_offset, message_size)?;
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| PrecompileError::InvalidPublicKey)?;
        verifying_key
            .verify(message, &Signature::from_bytes(&signature))
            .map_err(|_| PrecompileError::InvalidSignature)?;
    }
    Ok(())
}

fn slice(data: &[u8], offset: usize, len: usize) -> Result<&[u8], PrecompileError> {
    let end = offset
        .checked_add(len)
        .ok_or(PrecompileError::InvalidDataOffsets)?;
    data.get(offset..end)
        .ok_or(PrecompileError::InvalidDataOffsets)
}
