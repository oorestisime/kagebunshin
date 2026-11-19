//! Kagebunshin: a local secrets broker for developers and coding agents.

pub mod atomic;
pub mod audit;
pub mod cli;
pub mod config;
pub mod daemon;
pub mod ipc;
pub mod repo;
pub mod secret;
pub mod source;
pub mod store;
pub mod sys;
pub mod tailnet;
pub mod types;
pub mod webauthn;

#[doc(hidden)]
pub mod test_support;
