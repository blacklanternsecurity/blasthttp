// Thin JSON bridge: Python sends config JSON, Rust returns response JSON.
// The rich Python API (Pydantic models, async, batch) will wrap this.

use std::sync::Arc;
use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;

use crate::client::HttpClient;
use crate::client::hyper::HyperClient;
use crate::config::RequestConfig;
use crate::batch;

#[pyclass]
struct BlastHTTP {
    client: Arc<HyperClient>,
    runtime: Arc<tokio::runtime::Runtime>,
}

#[pymethods]
impl BlastHTTP {
    #[new]
    fn new() -> PyResult<Self> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| PyRuntimeError::new_err(format!("failed to create runtime: {}", e)))?;

        Ok(BlastHTTP {
            client: Arc::new(HyperClient::new()),
            runtime: Arc::new(runtime),
        })
    }

    fn send(&self, config_json: String) -> PyResult<String> {
        let config: RequestConfig = serde_json::from_str(&config_json)
            .map_err(|e| PyRuntimeError::new_err(format!("invalid config JSON: {}", e)))?;

        let response = self.runtime.block_on(self.client.send(&config))
            .map_err(|e| PyRuntimeError::new_err(e.message))?;

        serde_json::to_string(&response)
            .map_err(|e| PyRuntimeError::new_err(format!("failed to serialize response: {}", e)))
    }

    #[pyo3(signature = (configs_json, concurrency=50))]
    fn send_batch(&self, configs_json: String, concurrency: usize) -> PyResult<String> {
        let configs: Vec<RequestConfig> = serde_json::from_str(&configs_json)
            .map_err(|e| PyRuntimeError::new_err(format!("invalid configs JSON: {}", e)))?;

        let results = self.runtime.block_on(
            batch::send_batch(self.client.clone(), configs, concurrency)
        );

        let json_strings: Vec<String> = results.into_iter()
            .filter_map(|r| r.result.ok())
            .filter_map(|resp| serde_json::to_string(&resp).ok())
            .collect();

        Ok(format!("[{}]", json_strings.join(",")))
    }
}

#[pymodule]
fn blasthttp(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<BlastHTTP>()?;
    Ok(())
}
