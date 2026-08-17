pub mod catalog;
mod inputs;
pub mod memory;
mod outputs;
pub mod protocol;
pub mod server;
pub mod service;
pub mod tools;

pub use server::{read_capped_line_with_limit, run_server, run_server_with_io};
pub use service::{ConnectionState, McpService};
pub use tools::AutoConsolidate;
