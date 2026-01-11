//! Command execution configurations for different platforms
//!
//! Provides whitelisted command executors for secure system scanning.

pub mod filesystem;
pub mod k8s;
pub mod tcp_listener;

pub use filesystem::{
    file_exists, get_file_metadata, read_file_content, FileMetadata, FileSystemError,
    FileSystemResult,
};
pub use k8s::create_k8s_command_executor;
pub use tcp_listener::{
    check_port_listening, get_all_listening_ports, TcpListenerError, TcpListenerResult,
};
