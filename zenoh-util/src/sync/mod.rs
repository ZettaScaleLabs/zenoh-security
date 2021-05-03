//
// Copyright (c) 2017, 2020 ADLINK Technology Inc.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ADLINK zenoh team, <zenoh@adlink-labs.tech>
//
pub mod backoff;
pub use backoff::*;
pub mod condition;
pub use condition::*;
pub mod mvar;
pub use mvar::*;
pub mod signal;
pub use signal::*;

pub fn get_mut_unchecked<T>(arc: &mut std::sync::Arc<T>) -> &mut T {
    unsafe { &mut (*(std::sync::Arc::as_ptr(arc) as *mut T)) }
}
