//! Push registration — build the DIDComm `set-device-info` message.
//!
//! **Slice 3.** Implements the device side of the push wake-up binding
//! (`https://trusttasks.org/binding/push/0.1`): the engine assembles the
//! `set-device-info` body from a [`PushRegistration`]-shaped input; the native
//! layer obtains the APNs/FCM token and sends the packed message to the
//! mediator over the live DIDComm channel.
//!
//! Planned surface:
//! - `build_set_device_info(platform, token, topic) -> MessageJson`
//! - `build_delete_device_info() -> MessageJson`
