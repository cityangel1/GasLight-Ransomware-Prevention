use crate::telemetry::event::Event;
use crossbeam_channel::{Receiver, Sender};

/// The central telemetry queue. Every collector thread (process, file,
/// registry, network) gets a clone of the `EventSender` and pushes events
/// into it; a single detector worker owns the `EventReceiver` and drains it.
pub type EventSender = Sender<Event>;
pub type EventReceiver = Receiver<Event>;

/// Creates the bounded telemetry channel. A bound (rather than unbounded)
/// gives the agent natural backpressure if the detector ever falls behind a
/// burst of file events, instead of growing memory unboundedly.
pub fn new_queue(capacity: usize) -> (EventSender, EventReceiver) {
    crossbeam_channel::bounded(capacity)
}
