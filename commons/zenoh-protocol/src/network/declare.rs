//
// Copyright (c) 2022 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
use crate::{
    common::{imsg, ZExtZ64},
    core::{ExprId, Reliability, WireExpr},
    network::Mapping,
    zextz64,
};
pub use keyexpr::*;
pub use queryable::*;
pub use subscriber::*;
pub use token::*;

pub mod flag {
    // pub const X: u8 = 1 << 5; // 0x20 Reserved
    // pub const X: u8 = 1 << 6; // 0x40 Reserved
    pub const Z: u8 = 1 << 7; // 0x80 Extensions    if Z==1 then an extension will follow
}

/// Flags:
/// - X: Reserved
/// - X: Reserved
/// - Z: Extension      If Z==1 then at least one extension is present
///
/// 7 6 5 4 3 2 1 0
/// +-+-+-+-+-+-+-+-+
/// |Z|X|X| DECLARE |
/// +-+-+-+---------+
/// ~  [decl_exts]  ~  if Z==1
/// +---------------+
/// ~  declaration  ~
/// +---------------+
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declare {
    pub ext_qos: ext::QoSType,
    pub ext_tstamp: Option<ext::TimestampType>,
    pub body: DeclareBody,
}

pub mod ext {
    pub type QoS = crate::network::ext::QoS;
    pub type QoSType = crate::network::ext::QoSType;

    pub type Timestamp = crate::network::ext::Timestamp;
    pub type TimestampType = crate::network::ext::TimestampType;
}

pub mod id {
    pub const D_KEYEXPR: u8 = 0x00;
    pub const F_KEYEXPR: u8 = 0x01;

    pub const D_SUBSCRIBER: u8 = 0x02;
    pub const F_SUBSCRIBER: u8 = 0x03;

    pub const D_QUERYABLE: u8 = 0x04;
    pub const F_QUERYABLE: u8 = 0x05;

    pub const D_TOKEN: u8 = 0x06;
    pub const F_TOKEN: u8 = 0x07;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclareBody {
    DeclareKeyExpr(DeclareKeyExpr),
    ForgetKeyExpr(ForgetKeyExpr),
    DeclareSubscriber(DeclareSubscriber),
    ForgetSubscriber(ForgetSubscriber),
    DeclareQueryable(DeclareQueryable),
    ForgetQueryable(ForgetQueryable),
    DeclareToken(DeclareToken),
    ForgetToken(ForgetToken),
}

impl DeclareBody {
    #[cfg(feature = "test")]
    pub fn rand() -> Self {
        use rand::Rng;

        let mut rng = rand::thread_rng();

        match rng.gen_range(0..8) {
            0 => DeclareBody::DeclareKeyExpr(DeclareKeyExpr::rand()),
            1 => DeclareBody::ForgetKeyExpr(ForgetKeyExpr::rand()),
            2 => DeclareBody::DeclareSubscriber(DeclareSubscriber::rand()),
            3 => DeclareBody::ForgetSubscriber(ForgetSubscriber::rand()),
            4 => DeclareBody::DeclareQueryable(DeclareQueryable::rand()),
            5 => DeclareBody::ForgetQueryable(ForgetQueryable::rand()),
            6 => DeclareBody::DeclareToken(DeclareToken::rand()),
            7 => DeclareBody::ForgetToken(ForgetToken::rand()),
            _ => unreachable!(),
        }
    }
}

impl Declare {
    #[cfg(feature = "test")]
    pub fn rand() -> Self {
        use rand::Rng;

        let mut rng = rand::thread_rng();

        let body = DeclareBody::rand();
        let ext_qos = ext::QoSType::rand();
        let ext_tstamp = rng.gen_bool(0.5).then(ext::TimestampType::rand);

        Self {
            body,
            ext_qos,
            ext_tstamp,
        }
    }
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    #[default]
    Push,
    Pull,
}

impl Mode {
    #[cfg(feature = "test")]
    fn rand() -> Self {
        use rand::Rng;

        let mut rng = rand::thread_rng();

        if rng.gen_bool(0.5) {
            Mode::Push
        } else {
            Mode::Pull
        }
    }
}

pub mod keyexpr {
    use super::*;

    pub mod flag {
        pub const N: u8 = 1 << 5; // 0x20 Named         if N==1 then the key expr has name/suffix
                                  // pub const X: u8 = 1 << 6; // 0x40 Reserved
        pub const Z: u8 = 1 << 7; // 0x80 Extensions    if Z==1 then an extension will follow
    }

    /// ```text
    /// Flags:
    /// - N: Named          If N==1 then the key expr has name/suffix
    /// - X: Reserved
    /// - Z: Extension      If Z==1 then at least one extension is present
    ///
    ///  7 6 5 4 3 2 1 0
    /// +-+-+-+-+-+-+-+-+
    /// |Z|X|N| D_KEXPR |
    /// +---------------+
    /// ~  expr_id:z16  ~
    /// +---------------+
    /// ~ key_scope:z16 ~
    /// +---------------+
    /// ~  key_suffix   ~  if N==1 -- <u8;z16>
    /// +---------------+
    /// ~  [decl_exts]  ~  if Z==1
    /// +---------------+
    /// ```
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DeclareKeyExpr {
        pub id: ExprId,
        pub wire_expr: WireExpr<'static>,
    }

    impl DeclareKeyExpr {
        #[cfg(feature = "test")]
        pub fn rand() -> Self {
            use rand::Rng;
            let mut rng = rand::thread_rng();

            let id: ExprId = rng.gen();
            let wire_expr = WireExpr::rand();

            Self { id, wire_expr }
        }
    }

    /// ```text
    /// Flags:
    /// - X: Reserved
    /// - X: Reserved
    /// - Z: Extension      If Z==1 then at least one extension is present
    ///
    /// 7 6 5 4 3 2 1 0
    /// +-+-+-+-+-+-+-+-+
    /// |Z|X|X| F_KEXPR |
    /// +---------------+
    /// ~  expr_id:z16  ~
    /// +---------------+
    /// ~  [decl_exts]  ~  if Z==1
    /// +---------------+
    /// ```
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ForgetKeyExpr {
        pub id: ExprId,
    }

    impl ForgetKeyExpr {
        #[cfg(feature = "test")]
        pub fn rand() -> Self {
            use rand::Rng;
            let mut rng = rand::thread_rng();

            let id: ExprId = rng.gen();

            Self { id }
        }
    }
}

pub mod subscriber {
    use super::*;

    pub type SubscriberId = u32;

    pub mod flag {
        pub const N: u8 = 1 << 5; // 0x20 Named         if N==1 then the key expr has name/suffix
        pub const M: u8 = 1 << 6; // 0x40 Mapping       if M==1 then key expr mapping is the one declared by the sender, else it is the one declared by the receiver
        pub const Z: u8 = 1 << 7; // 0x80 Extensions    if Z==1 then an extension will follow
    }

    /// ```text
    /// Flags:
    /// - N: Named          If N==1 then the key expr has name/suffix
    /// - M: Mapping        if M==1 then key expr mapping is the one declared by the sender, else it is the one declared by the receiver
    /// - Z: Extension      If Z==1 then at least one extension is present
    ///
    /// 7 6 5 4 3 2 1 0
    /// +-+-+-+-+-+-+-+-+
    /// |Z|M|N|  D_SUB  |
    /// +---------------+
    /// ~  subs_id:z32  ~
    /// +---------------+
    /// ~ key_scope:z16 ~
    /// +---------------+
    /// ~  key_suffix   ~  if N==1 -- <u8;z16>
    /// +---------------+
    /// ~  [decl_exts]  ~  if Z==1
    /// +---------------+
    ///
    /// - if R==1 then the subscription is reliable, else it is best effort
    /// - if P==1 then the subscription is pull, else it is push
    ///
    /// ```
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DeclareSubscriber {
        pub id: SubscriberId,
        pub wire_expr: WireExpr<'static>,
        pub mapping: Mapping,
        pub ext_info: ext::SubscriberInfo,
    }

    pub mod ext {
        use super::*;

        pub type Info = zextz64!(0x01, false);

        /// # The subscription mode.
        ///
        /// ```text
        ///  7 6 5 4 3 2 1 0
        /// +-+-+-+-+-+-+-+-+
        /// |Z|0_1|    ID   |
        /// +-+-+-+---------+
        /// % reserved  |P|R%
        /// +---------------+
        ///
        /// - if R==1 then the subscription is reliable, else it is best effort
        /// - if P==1 then the subscription is pull, else it is push
        /// - rsv:  Reserved
        /// ```        
        #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
        pub struct SubscriberInfo {
            pub reliability: Reliability,
            pub mode: Mode,
        }

        impl SubscriberInfo {
            pub const R: u64 = 1;
            pub const P: u64 = 1 << 1;

            #[cfg(feature = "test")]
            pub fn rand() -> Self {
                let reliability = Reliability::rand();
                let mode = Mode::rand();

                Self { reliability, mode }
            }
        }

        impl From<Info> for SubscriberInfo {
            fn from(ext: Info) -> Self {
                let reliability = if imsg::has_option(ext.value, SubscriberInfo::R) {
                    Reliability::Reliable
                } else {
                    Reliability::BestEffort
                };
                let mode = if imsg::has_option(ext.value, SubscriberInfo::P) {
                    Mode::Pull
                } else {
                    Mode::Push
                };
                Self { reliability, mode }
            }
        }

        impl From<SubscriberInfo> for Info {
            fn from(ext: SubscriberInfo) -> Self {
                let mut v: u64 = 0;
                if ext.reliability == Reliability::Reliable {
                    v |= SubscriberInfo::R;
                }
                if ext.mode == Mode::Pull {
                    v |= SubscriberInfo::P;
                }
                Info::new(v)
            }
        }
    }

    impl DeclareSubscriber {
        #[cfg(feature = "test")]
        pub fn rand() -> Self {
            use rand::Rng;
            let mut rng = rand::thread_rng();

            let id: SubscriberId = rng.gen();
            let wire_expr = WireExpr::rand();
            let mapping = Mapping::rand();
            let ext_info = ext::SubscriberInfo::rand();

            Self {
                id,
                wire_expr,
                ext_info,
                mapping,
            }
        }
    }

    /// ```text
    /// Flags:
    /// - X: Reserved
    /// - X: Reserved
    /// - Z: Extension      If Z==1 then at least one extension is present
    ///
    /// 7 6 5 4 3 2 1 0
    /// +-+-+-+-+-+-+-+-+
    /// |Z|X|X|  F_SUB  |
    /// +---------------+
    /// ~  subs_id:z32  ~
    /// +---------------+
    /// ~  [decl_exts]  ~  if Z==1
    /// +---------------+
    /// ```
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ForgetSubscriber {
        pub id: SubscriberId,
    }

    impl ForgetSubscriber {
        #[cfg(feature = "test")]
        pub fn rand() -> Self {
            use rand::Rng;
            let mut rng = rand::thread_rng();

            let id: SubscriberId = rng.gen();

            Self { id }
        }
    }
}

pub mod queryable {
    use super::*;

    pub type QueryableId = u32;

    pub mod flag {
        pub const N: u8 = 1 << 5; // 0x20 Named         if N==1 then the key expr has name/suffix
        pub const M: u8 = 1 << 6; // 0x40 Mapping       if M==1 then key expr mapping is the one declared by the sender, else it is the one declared by the receiver
        pub const Z: u8 = 1 << 7; // 0x80 Extensions    if Z==1 then an extension will follow
    }

    /// ```text
    /// Flags:
    /// - N: Named          If N==1 then the key expr has name/suffix
    /// - M: Mapping        if M==1 then key expr mapping is the one declared by the sender, else it is the one declared by the receiver
    /// - Z: Extension      If Z==1 then at least one extension is present
    ///
    /// 7 6 5 4 3 2 1 0
    /// +-+-+-+-+-+-+-+-+
    /// |Z|M|N|  D_QBL  |
    /// +---------------+
    /// ~  qbls_id:z32  ~
    /// +---------------+
    /// ~ key_scope:z16 ~
    /// +---------------+
    /// ~  key_suffix   ~  if N==1 -- <u8;z16>
    /// +---------------+
    /// ~  [decl_exts]  ~  if Z==1
    /// +---------------+
    ///
    /// - if R==1 then the queryable is reliable, else it is best effort
    /// - if P==1 then the queryable is pull, else it is push
    /// - if C==1 then the queryable is complete and the N parameter is present
    /// - if D==1 then the queryable distance is present
    /// ```
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DeclareQueryable {
        pub id: QueryableId,
        pub wire_expr: WireExpr<'static>,
        pub mapping: Mapping,
        pub ext_info: ext::QueryableInfo,
    }

    pub mod ext {
        use super::*;

        pub type Info = zextz64!(0x01, false);

        ///  7 6 5 4 3 2 1 0
        /// +-+-+-+-+-+-+-+-+
        /// |Z|0_1|    ID   |
        /// +-+-+-+---------+
        /// ~  complete_n   ~
        /// +---------------+
        /// ~   distance    ~
        /// +---------------+
        #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
        pub struct QueryableInfo {
            pub complete: u8,  // Default 0: incomplete // @TODO: maybe a bitflag
            pub distance: u32, // Default 0: no distance
        }

        impl QueryableInfo {
            #[cfg(feature = "test")]
            pub fn rand() -> Self {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                let complete: u8 = rng.gen();
                let distance: u32 = rng.gen();

                Self { complete, distance }
            }
        }

        impl From<Info> for QueryableInfo {
            fn from(ext: Info) -> Self {
                let complete = ext.value as u8;
                let distance = (ext.value >> 8) as u32;

                Self { complete, distance }
            }
        }

        impl From<QueryableInfo> for Info {
            fn from(ext: QueryableInfo) -> Self {
                let mut v: u64 = ext.complete as u64;
                v |= (ext.distance as u64) << 8;
                Info::new(v)
            }
        }
    }

    impl DeclareQueryable {
        #[cfg(feature = "test")]
        pub fn rand() -> Self {
            use rand::Rng;
            let mut rng = rand::thread_rng();

            let id: QueryableId = rng.gen();
            let wire_expr = WireExpr::rand();
            let mapping = Mapping::rand();
            let ext_info = ext::QueryableInfo::rand();

            Self {
                id,
                wire_expr,
                mapping,
                ext_info,
            }
        }
    }

    /// ```text
    /// Flags:
    /// - X: Reserved
    /// - X: Reserved
    /// - Z: Extension      If Z==1 then at least one extension is present
    ///
    /// 7 6 5 4 3 2 1 0
    /// +-+-+-+-+-+-+-+-+
    /// |Z|X|X|  F_QBL  |
    /// +---------------+
    /// ~  qbls_id:z32  ~
    /// +---------------+
    /// ~  [decl_exts]  ~  if Z==1
    /// +---------------+
    /// ```
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ForgetQueryable {
        pub id: QueryableId,
    }

    impl ForgetQueryable {
        #[cfg(feature = "test")]
        pub fn rand() -> Self {
            use rand::Rng;
            let mut rng = rand::thread_rng();

            let id: QueryableId = rng.gen();

            Self { id }
        }
    }
}

pub mod token {
    use super::*;

    pub type TokenId = u32;

    pub mod flag {
        pub const N: u8 = 1 << 5; // 0x20 Named         if N==1 then the key expr has name/suffix
        pub const M: u8 = 1 << 6; // 0x40 Mapping       if M==1 then key expr mapping is the one declared by the sender, else it is the one declared by the receiver
        pub const Z: u8 = 1 << 7; // 0x80 Extensions    if Z==1 then an extension will follow
    }

    /// ```text
    /// Flags:
    /// - N: Named          If N==1 then the key expr has name/suffix
    /// - M: Mapping        if M==1 then key expr mapping is the one declared by the sender, else it is the one declared by the receiver
    /// - Z: Extension      If Z==1 then at least one extension is present
    ///
    /// 7 6 5 4 3 2 1 0
    /// +-+-+-+-+-+-+-+-+
    /// |Z|M|N|  D_TKN  |
    /// +---------------+
    /// ~ token_id:z32  ~  
    /// +---------------+
    /// ~ key_scope:z16 ~
    /// +---------------+
    /// ~  key_suffix   ~  if N==1 -- <u8;z16>
    /// +---------------+
    /// ~  [decl_exts]  ~  if Z==1
    /// +---------------+
    ///
    /// ```
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DeclareToken {
        pub id: TokenId,
        pub wire_expr: WireExpr<'static>,
        pub mapping: Mapping,
    }

    impl DeclareToken {
        #[cfg(feature = "test")]
        pub fn rand() -> Self {
            use rand::Rng;
            let mut rng = rand::thread_rng();

            let id: TokenId = rng.gen();
            let wire_expr = WireExpr::rand();
            let mapping = Mapping::rand();

            Self {
                id,
                wire_expr,
                mapping,
            }
        }
    }

    /// ```text
    /// Flags:
    /// - X: Reserved
    /// - X: Reserved
    /// - Z: Extension      If Z==1 then at least one extension is present
    ///
    /// 7 6 5 4 3 2 1 0
    /// +-+-+-+-+-+-+-+-+
    /// |Z|X|X|  F_TKN  |
    /// +---------------+
    /// ~ token_id:z32  ~  
    /// +---------------+
    /// ~  [decl_exts]  ~  if Z==1
    /// +---------------+
    /// ```
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ForgetToken {
        pub id: TokenId,
    }

    impl ForgetToken {
        #[cfg(feature = "test")]
        pub fn rand() -> Self {
            use rand::Rng;
            let mut rng = rand::thread_rng();

            let id: TokenId = rng.gen();

            Self { id }
        }
    }
}