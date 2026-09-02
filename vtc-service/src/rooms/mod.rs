//! Data rooms — this service's Trust-Task surface over [`vti_rooms`].
//!
//! Storage, wire types and authorization live in the `vti-rooms` crate, because none of
//! them needs anything from a community service: a room is authorized by credentials the
//! room itself issued, so the code deciding a room operation cannot need a roster, a policy
//! engine, or a session store. What stays here is [`handlers`] — the dispatch surface, which
//! is this service's spine and therefore not extractable.
//!
//! The re-exports keep `crate::rooms::Room` and friends resolving, so nothing outside this
//! module had to move when the subsystem did.

pub mod handlers;

pub use vti_rooms::{
    ROOM_RECORDS_KEYSPACE, ROOMS_KEYSPACE, Record, RecordStatus, Room, Visibility, authz, storage,
    wire,
};
