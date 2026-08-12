pub mod catalog;
mod inputs;
pub mod memory;
mod outputs;
pub mod protocol;
pub mod server;
pub mod service;
pub mod tools;

pub use server::run_server;
pub use tools::AutoConsolidate;
