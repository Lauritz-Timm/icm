//! Domain handlers for the MCP tool compatibility layer.

pub(super) mod common;
mod feedback;
mod memoir;
mod memory;
mod transcript;

pub use common::AutoConsolidate;
pub(in crate::tools) use feedback::{
    tool_feedback_record, tool_feedback_search, tool_feedback_stats,
};
pub(in crate::tools) use memoir::{
    tool_memoir_add_concept, tool_memoir_create, tool_memoir_export, tool_memoir_inspect,
    tool_memoir_link, tool_memoir_list, tool_memoir_refine, tool_memoir_search,
    tool_memoir_search_all, tool_memoir_show,
};
pub(in crate::tools) use memory::{
    tool_consolidate, tool_embed_all, tool_extract_patterns, tool_forget, tool_forget_topic,
    tool_health, tool_learn_bounded, tool_list_topics, tool_recall, tool_stats, tool_store,
    tool_update, tool_wake_up,
};
pub(in crate::tools) use transcript::{
    tool_transcript_record, tool_transcript_search, tool_transcript_show,
    tool_transcript_start_session, tool_transcript_stats,
};
