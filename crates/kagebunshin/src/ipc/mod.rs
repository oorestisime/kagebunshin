//! The daemon socket: where it lives, how messages are framed, what they say,
//! and the server that answers them.

pub mod client;
pub mod frame;
pub mod paths;
pub mod protocol;
pub mod remote;
pub mod server;
