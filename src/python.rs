// Thin JSON bridge: Python sends config JSON, Rust returns response JSON.
// The rich Python API (Pydantic models, async, batch) will wrap this.

use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;

use crate::client::HttpClient;
use crate::client::hyper::HyperClient;
use crate::config::RequestConfig;

#[pyclass]
struct BlastHTTP {
    client: HyperClient,
}

#[pymethods]
impl BlastHTTP {
    #[new]
    fn new() -> Self {
        BlastHTTP { client: HyperClient::new() }
    }

    fn send(&self, config_json: String) -> PyResult<String> {
        let config: RequestConfig = serde_json::from_str(&config_json)
            .map_err(|e| PyRuntimeError::new_err(format!("invalid config JSON: {}", e)))?;

        // Per-call runtime for now; Phase 2 will use a persistent worker pool
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| PyRuntimeError::new_err(format!("failed to create runtime: {}", e)))?;

        let response = rt.block_on(self.client.send(&config))
            .map_err(|e| PyRuntimeError::new_err(e.message))?;

        serde_json::to_string(&response)
            .map_err(|e| PyRuntimeError::new_err(format!("failed to serialize response: {}", e)))
    }
}

#[pymodule]
fn blasthttp(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<BlastHTTP>()?;
    Ok(())
}
