use std::sync::{Arc, Mutex};
use zenoh::prelude::sync::*;
use zenoh_config::Config;
use zenoh_core::zlock;

#[test]
fn test_acl() {
    env_logger::init();
    test_pub_sub_allow();
    test_pub_sub_deny();
    test_pub_sub_allow_then_deny();
    test_pub_sub_deny_then_allow();
}

fn test_pub_sub_deny() {
    let mut config_router = Config::default();
    config_router.set_mode(Some(WhatAmI::Router)).unwrap();
    config_router
        .listen
        .set_endpoints(vec![
            "tcp/localhost:7447".parse().unwrap(),
            "tcp/localhost:7448".parse().unwrap(),
        ])
        .unwrap();

    config_router
        .scouting
        .multicast
        .set_enabled(Some(false))
        .unwrap();
    config_router
        .insert_json5(
            "transport",
            r#"{
              acl: {
                "enabled": true,
                "default_permission": "deny",
                "rules":
                [
                ]
              }
            }"#,
        )
        .unwrap();

    let mut config_sub = Config::default();
    config_sub.set_mode(Some(WhatAmI::Client)).unwrap();
    config_sub
        .connect
        .set_endpoints(vec!["tcp/localhost:7447".parse().unwrap()])
        .unwrap();
    config_sub
        .scouting
        .multicast
        .set_enabled(Some(false))
        .unwrap();

    let mut config_pub = Config::default();
    config_pub.set_mode(Some(WhatAmI::Client)).unwrap();
    config_pub
        .connect
        .set_endpoints(vec!["tcp/localhost:7448".parse().unwrap()])
        .unwrap();

    config_pub
        .scouting
        .multicast
        .set_enabled(Some(false))
        .unwrap();

    const KEY_EXPR: &str = "test/demo";
    const VALUE: &str = "zenoh";

    let _session = zenoh::open(config_router).res().unwrap();

    let sub_session = zenoh::open(config_sub).res().unwrap();
    let pub_session = zenoh::open(config_pub).res().unwrap();

    let publisher = pub_session.declare_publisher(KEY_EXPR).res().unwrap();

    let received_value = Arc::new(Mutex::new(String::new()));
    let temp_recv_value = received_value.clone();

    let _subscriber = &sub_session
        .declare_subscriber(KEY_EXPR)
        .callback(move |sample| {
            let mut temp_value = zlock!(temp_recv_value);
            *temp_value = sample.value.to_string();
        })
        .res()
        .unwrap();

    std::thread::sleep(std::time::Duration::from_millis(10));
    publisher.put(VALUE).res().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    assert_ne!(*zlock!(received_value), VALUE);
}

fn test_pub_sub_allow() {
    let mut config_router = Config::default();
    config_router.set_mode(Some(WhatAmI::Router)).unwrap();
    config_router
        .listen
        .set_endpoints(vec![
            "tcp/localhost:7447".parse().unwrap(),
            "tcp/localhost:7448".parse().unwrap(),
        ])
        .unwrap();

    config_router
        .scouting
        .multicast
        .set_enabled(Some(false))
        .unwrap();
    config_router
        .insert_json5(
            "transport",
            r#"{
            acl: {
              "enabled": true,
              "default_permission": "allow",
              "rules":
              [
              ]
            }
          }"#,
        )
        .unwrap();

    let mut config_sub = Config::default();
    config_sub.set_mode(Some(WhatAmI::Client)).unwrap();
    config_sub
        .connect
        .set_endpoints(vec!["tcp/localhost:7447".parse().unwrap()])
        .unwrap();
    config_sub
        .scouting
        .multicast
        .set_enabled(Some(false))
        .unwrap();

    let mut config_pub = Config::default();
    config_pub.set_mode(Some(WhatAmI::Client)).unwrap();
    config_pub
        .connect
        .set_endpoints(vec!["tcp/localhost:7448".parse().unwrap()])
        .unwrap();

    config_pub
        .scouting
        .multicast
        .set_enabled(Some(false))
        .unwrap();

    const KEY_EXPR: &str = "test/demo";
    const VALUE: &str = "zenoh";

    let _session = zenoh::open(config_router).res().unwrap();

    let sub_session = zenoh::open(config_sub).res().unwrap();
    let pub_session = zenoh::open(config_pub).res().unwrap();

    let publisher = pub_session.declare_publisher(KEY_EXPR).res().unwrap();

    let received_value = Arc::new(Mutex::new(String::new()));
    let temp_recv_value = received_value.clone();

    let _subscriber = sub_session
        .declare_subscriber(KEY_EXPR)
        .callback(move |sample| {
            let mut temp_value = zlock!(temp_recv_value);
            *temp_value = sample.value.to_string();
        })
        .res()
        .unwrap();

    std::thread::sleep(std::time::Duration::from_millis(10));
    publisher.put(VALUE).res().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    assert_eq!(*zlock!(received_value), VALUE);
}

fn test_pub_sub_allow_then_deny() {
    let mut config_router = Config::default();
    config_router.set_mode(Some(WhatAmI::Router)).unwrap();
    config_router
        .listen
        .set_endpoints(vec![
            "tcp/localhost:7447".parse().unwrap(),
            "tcp/localhost:7448".parse().unwrap(),
        ])
        .unwrap();

    config_router
        .scouting
        .multicast
        .set_enabled(Some(false))
        .unwrap();
    config_router
        .insert_json5(
            "transport",
            r#"{
            acl: {
              "enabled": true,
              "default_permission": "allow",
              "rules":
              [
                {
                  "permission": "deny",
                  "flow": ["egress"],
                  "action": [
                    "put",
                  ],
                  "key_expr": [
                    "test/demo"
                  ],
                  "interface": [
                    "lo0"
                  ]
                },
              ]
            }
          }"#,
        )
        .unwrap();

    let mut config_sub = Config::default();
    config_sub.set_mode(Some(WhatAmI::Client)).unwrap();
    config_sub
        .connect
        .set_endpoints(vec!["tcp/localhost:7447".parse().unwrap()])
        .unwrap();
    config_sub
        .scouting
        .multicast
        .set_enabled(Some(false))
        .unwrap();

    let mut config_pub = Config::default();
    config_pub.set_mode(Some(WhatAmI::Client)).unwrap();
    config_pub
        .connect
        .set_endpoints(vec!["tcp/localhost:7448".parse().unwrap()])
        .unwrap();

    config_pub
        .scouting
        .multicast
        .set_enabled(Some(false))
        .unwrap();

    const KEY_EXPR: &str = "test/demo";
    const VALUE: &str = "zenoh";

    let _session = zenoh::open(config_router).res().unwrap();

    let sub_session = zenoh::open(config_sub).res().unwrap();
    let pub_session = zenoh::open(config_pub).res().unwrap();

    let publisher = pub_session.declare_publisher(KEY_EXPR).res().unwrap();

    let received_value = Arc::new(Mutex::new(String::new()));
    let temp_recv_value = received_value.clone();

    let _subscriber = sub_session
        .declare_subscriber(KEY_EXPR)
        .callback(move |sample| {
            let mut temp_value = zlock!(temp_recv_value);
            *temp_value = sample.value.to_string();
        })
        .res()
        .unwrap();

    std::thread::sleep(std::time::Duration::from_millis(10));
    publisher.put(VALUE).res().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    assert_ne!(*zlock!(received_value), VALUE);
}

fn test_pub_sub_deny_then_allow() {
    let mut config_router = Config::default();
    config_router.set_mode(Some(WhatAmI::Router)).unwrap();
    config_router
        .listen
        .set_endpoints(vec![
            "tcp/localhost:7447".parse().unwrap(),
            "tcp/localhost:7448".parse().unwrap(),
        ])
        .unwrap();

    config_router
        .scouting
        .multicast
        .set_enabled(Some(false))
        .unwrap();
    config_router
        .insert_json5(
            "transport",
            r#"{
          acl: {
            "enabled": true,
            "default_permission": "deny",
            "rules":
            [
              {
                "permission": "allow",
                "flow": ["egress","ingress"],
                "action": [
                  "put",
                  "declare_subscriber"
                ],
                "key_expr": [
                  "test/demo"
                ],
                "interface": [
                  "lo0"
                ]
              },
            ]
          }
        }"#,
        )
        .unwrap();

    let mut config_sub = Config::default();
    config_sub.set_mode(Some(WhatAmI::Client)).unwrap();
    config_sub
        .connect
        .set_endpoints(vec!["tcp/localhost:7447".parse().unwrap()])
        .unwrap();
    config_sub
        .scouting
        .multicast
        .set_enabled(Some(false))
        .unwrap();

    let mut config_pub = Config::default();
    config_pub.set_mode(Some(WhatAmI::Client)).unwrap();
    config_pub
        .connect
        .set_endpoints(vec!["tcp/localhost:7448".parse().unwrap()])
        .unwrap();
    config_pub
        .scouting
        .multicast
        .set_enabled(Some(false))
        .unwrap();

    const KEY_EXPR: &str = "test/demo";
    const VALUE: &str = "zenoh";

    let _session = zenoh::open(config_router).res().unwrap();

    let sub_session = zenoh::open(config_sub).res().unwrap();
    let pub_session = zenoh::open(config_pub).res().unwrap();

    let publisher = pub_session.declare_publisher(KEY_EXPR).res().unwrap();

    let received_value = Arc::new(Mutex::new(String::new()));
    let temp_recv_value = received_value.clone();

    let _subscriber = sub_session
        .declare_subscriber(KEY_EXPR)
        .callback(move |sample| {
            let mut temp_value = zlock!(temp_recv_value);
            *temp_value = sample.value.to_string();
        })
        .res()
        .unwrap();

    std::thread::sleep(std::time::Duration::from_millis(10));
    publisher.put(VALUE).res().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    assert_eq!(*zlock!(received_value), VALUE);
}