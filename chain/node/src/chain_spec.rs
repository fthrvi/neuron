use sc_service::ChainType;
use solochain_template_runtime::WASM_BINARY;

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec;

pub fn development_chain_spec() -> Result<ChainSpec, String> {
	Ok(ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?,
		None,
	)
	.with_name("Development")
	.with_id("dev")
	.with_chain_type(ChainType::Development)
	.with_genesis_config_preset_name(sp_genesis_builder::DEV_RUNTIME_PRESET)
	.build())
}

pub fn local_chain_spec() -> Result<ChainSpec, String> {
	Ok(ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?,
		None,
	)
	.with_name("Local Testnet")
	.with_id("local_testnet")
	.with_chain_type(ChainType::Local)
	.with_genesis_config_preset_name(sp_genesis_builder::LOCAL_TESTNET_RUNTIME_PRESET)
	.build())
}

pub fn neuron_chain_spec() -> Result<ChainSpec, String> {
	let mut properties = sc_service::Properties::new();
	properties.insert("tokenSymbol".into(), "NRN".into());
	properties.insert("tokenDecimals".into(), 12.into());
	properties.insert("ss58Format".into(), 42.into());

	Ok(ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "Neuron wasm not available".to_string())?,
		None,
	)
	.with_name("Neuron Network")
	.with_id("neuron")
	.with_chain_type(ChainType::Live)
	.with_protocol_id("neuron")
	.with_properties(properties)
	.with_genesis_config_preset_name("neuron")
	.build())
}
