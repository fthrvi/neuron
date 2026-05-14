// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{AccountId, BalancesConfig, RuntimeGenesisConfig, SudoConfig};
use alloc::{vec, vec::Vec};
use frame_support::build_struct_json_patch;
use serde_json::Value;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_genesis_builder::{self, PresetId};
use sp_keyring::Sr25519Keyring;

// Returns the genesis config presets populated with given parameters.
fn testnet_genesis(
	initial_authorities: Vec<(AuraId, GrandpaId)>,
	endowed_accounts: Vec<AccountId>,
	root: AccountId,
) -> Value {
	build_struct_json_patch!(RuntimeGenesisConfig {
		balances: BalancesConfig {
			balances: endowed_accounts
				.iter()
				.cloned()
				// Fair launch: validators start with minimal balance (just enough for tx fees)
				// All real NRN comes from emission only — like Bitcoin block 0
				.map(|k| (k, 1_000_000_000_000u128))  // 1 NRN (existential deposit + fees)
				.collect::<Vec<_>>(),
		},
		aura: pallet_aura::GenesisConfig {
			authorities: initial_authorities.iter().map(|x| (x.0.clone())).collect::<Vec<_>>(),
		},
		grandpa: pallet_grandpa::GenesisConfig {
			authorities: initial_authorities.iter().map(|x| (x.1.clone(), 1)).collect::<Vec<_>>(),
		},
		sudo: SudoConfig { key: Some(root) },
	})
}

/// Return the development genesis config.
pub fn development_config_genesis() -> Value {
	testnet_genesis(
		vec![(
			sp_keyring::Sr25519Keyring::Alice.public().into(),
			sp_keyring::Ed25519Keyring::Alice.public().into(),
		)],
		vec![
			Sr25519Keyring::Alice.to_account_id(),
			Sr25519Keyring::Bob.to_account_id(),
			Sr25519Keyring::AliceStash.to_account_id(),
			Sr25519Keyring::BobStash.to_account_id(),
		],
		sp_keyring::Sr25519Keyring::Alice.to_account_id(),
	)
}

/// Return the Neuron Network production genesis config.
/// Two validators: the operator's PC + Raspberry Pi 5 (chain guardian).
pub fn neuron_config_genesis() -> Value {
	// Validator 1: the operator's PC (203.0.113.20) — GPU worker + validator
	let v1_aura: AuraId = sp_core::sr25519::Public::from_raw(
		hex_literal::hex!("8cab4c4a39cb81f8e4126869d52681436ec067a06cf0919cfce2c220b73b9336")
	).into();
	let v1_grandpa: GrandpaId = sp_core::ed25519::Public::from_raw(
		hex_literal::hex!("bba09f4d296c05908830ea89079e05cb2e14b3f8aa29f6fba18654220a4580a1")
	).into();
	let v1_account: AccountId = sp_core::sr25519::Public::from_raw(
		hex_literal::hex!("8cab4c4a39cb81f8e4126869d52681436ec067a06cf0919cfce2c220b73b9336")
	).into();

	// Validator 2: Raspberry Pi 5 (chain guardian) — no GPU, just validates
	let v2_aura: AuraId = sp_core::sr25519::Public::from_raw(
		hex_literal::hex!("ea921cacc588d22f7d0e2f3aecf1a4333625e79a642424343c0c9b15f3bb873f")
	).into();
	let v2_grandpa: GrandpaId = sp_core::ed25519::Public::from_raw(
		hex_literal::hex!("4310e76be949ac13eb61ab24662d9109e7484fa6c132ed4c958b765b55b181e6")
	).into();
	let v2_account: AccountId = sp_core::sr25519::Public::from_raw(
		hex_literal::hex!("ea921cacc588d22f7d0e2f3aecf1a4333625e79a642424343c0c9b15f3bb873f")
	).into();

	testnet_genesis(
		vec![(v1_aura, v1_grandpa), (v2_aura, v2_grandpa)],
		vec![v1_account.clone(), v2_account.clone()],
		v1_account, // the operator is sudo
	)
}

/// Return the local genesis config preset.
pub fn local_config_genesis() -> Value {
	testnet_genesis(
		vec![
			(
				sp_keyring::Sr25519Keyring::Alice.public().into(),
				sp_keyring::Ed25519Keyring::Alice.public().into(),
			),
			(
				sp_keyring::Sr25519Keyring::Bob.public().into(),
				sp_keyring::Ed25519Keyring::Bob.public().into(),
			),
		],
		Sr25519Keyring::iter()
			.filter(|v| v != &Sr25519Keyring::One && v != &Sr25519Keyring::Two)
			.map(|v| v.to_account_id())
			.collect::<Vec<_>>(),
		Sr25519Keyring::Alice.to_account_id(),
	)
}

/// Provides the JSON representation of predefined genesis config for given `id`.
pub fn get_preset(id: &PresetId) -> Option<Vec<u8>> {
	let patch = match id.as_ref() {
		sp_genesis_builder::DEV_RUNTIME_PRESET => development_config_genesis(),
		sp_genesis_builder::LOCAL_TESTNET_RUNTIME_PRESET => local_config_genesis(),
		"neuron" => neuron_config_genesis(),
		_ => return None,
	};
	Some(
		serde_json::to_string(&patch)
			.expect("serialization to json is expected to work. qed.")
			.into_bytes(),
	)
}

/// List of supported presets.
pub fn preset_names() -> Vec<PresetId> {
	vec![
		PresetId::from(sp_genesis_builder::DEV_RUNTIME_PRESET),
		PresetId::from(sp_genesis_builder::LOCAL_TESTNET_RUNTIME_PRESET),
		PresetId::from("neuron"),
	]
}
