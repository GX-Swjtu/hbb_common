
    use super::*;
    use sodiumoxide::crypto::box_;

    fn register(c: &mut Coordinator, id: &str, ip: &str, enabled: bool) -> sign::SecretKey {
        let (key, secret) = sign::gen_keypair();
        let request = protocol::request(id, Action::Advertise { capability: crate::CAPABILITY.into(), enabled }).unwrap();
        c.advertise(Device { id: id.into(), key, signed_key: vec![], address: format!("{ip}:1000").parse().unwrap() },
            &protocol::encode(&request, &secret).unwrap()).unwrap();
        secret
    }
    fn call(c: &mut Coordinator, server: &sign::SecretKey, sk: &sign::SecretKey, id: &str, source: &str, action: Action) -> Result<Reply> {
        let r = protocol::request(id, action)?;
        let out = c.handle(&protocol::encode(&r, sk)?, source.parse()?, server, "admission")?;
        Ok(protocol::decode::<Response>(&out.response, &server.public_key())?.reply)
    }
    fn begin(target: &str) -> Action {
        Action::Begin { target: target.into(), box_pk: box_::gen_keypair().0.as_ref().to_vec(), licence_key: "admission".into() }
    }
    fn candidates(values: &[&str]) -> Candidates {
        Candidates { public: values.iter().map(|s| s.parse().unwrap()).collect(), local: vec![], direct: None }
    }

    #[test]
    fn unavailable_capability_can_recover_after_registration() {
        crate::init().unwrap();
        for age in [None, Some(31), Some(61)] {
            let mut c = Coordinator::default();
            let (_, server) = sign::gen_keypair();
            let caller = register(&mut c, "caller", "192.0.2.1", true);
            if let Some(age) = age {
                let _ = register(&mut c, "target", "198.51.100.1", true);
                c.devices.get_mut("target").unwrap().seen = protocol::now().unwrap() - age;
            }
            let reply = call(&mut c, &server, &caller, "caller", "192.0.2.1:2000", begin("target")).unwrap();
            assert!(matches!(reply, Reply::Error(_)), "unavailable capability is not an explicit refusal");
            let _ = register(&mut c, "target", "198.51.100.1", true);
            assert!(matches!(call(&mut c, &server, &caller, "caller", "192.0.2.1:2000", begin("target")).unwrap(), Reply::Ticket(_)));
        }
    }

    #[test]
    fn only_the_single_capability_enables_attempts_and_explicit_refusal_is_signed() {
        crate::init().unwrap();
        let mut c = Coordinator::default();
        let (_, server) = sign::gen_keypair();
        let caller = register(&mut c, "caller", "192.0.2.1", true);
        let target = register(&mut c, "target", "198.51.100.1", false);
        for peer in ["target", "caller"] {
            let Reply::Error(error) = call(&mut c, &server, &caller, "caller", "192.0.2.1:2000", begin(peer)).unwrap() else { panic!("expected explicit refusal"); };
            assert_eq!(crate::progress::Reason::decode(&error).unwrap().code, "unsupported");
            assert!(c.attempts.is_empty());
        }
        let device = || Device { id: "target".into(), key: target.public_key(), signed_key: vec![], address: "198.51.100.1:1000".parse().unwrap() };
        for old in [serde_json::json!({"Advertise":{"version":1}}), serde_json::json!({"Advertise":{"version":1,"strategies":1}})] {
            assert!(serde_json::from_value::<Action>(old).is_err());
        }
        let request = protocol::request("target", Action::Advertise { capability: "different-capability".into(), enabled: true }).unwrap();
        assert!(c.advertise(device(), &protocol::encode(&request, &target).unwrap()).is_err());
        let request = protocol::request("target", Action::Advertise { capability: crate::CAPABILITY.into(), enabled: true }).unwrap();
        c.advertise(device(), &protocol::encode(&request, &target).unwrap()).unwrap();
        let Reply::Ticket(ticket) = call(&mut c, &server, &caller, "caller", "192.0.2.1:2000", begin("target")).unwrap() else { panic!() };
        assert_eq!(ticket.capability, crate::CAPABILITY);
        let off = protocol::request("target", Action::Advertise { capability: crate::CAPABILITY.into(), enabled: false }).unwrap();
        assert!(c.advertise(device(), &protocol::encode(&off, &caller).unwrap()).is_err());
        let withdrawal = protocol::encode(&off, &target).unwrap();
        c.advertise(device(), &withdrawal).unwrap();
        assert!(c.attempts.is_empty());
        let on = protocol::request("target", Action::Advertise { capability: crate::CAPABILITY.into(), enabled: true }).unwrap();
        c.advertise(device(), &protocol::encode(&on, &target).unwrap()).unwrap();
        assert!(c.advertise(device(), &withdrawal).is_err());
    }

    #[test]
    fn admission_replay_busy_cancel_and_expiry_bound_the_attempt_lifetime() {
        crate::init().unwrap();
        let mut c = Coordinator::default();
        let (_, server) = sign::gen_keypair();
        let caller = register(&mut c, "caller", "192.0.2.1", true);
        let _target = register(&mut c, "target", "198.51.100.1", true);
        let mut action = begin("target");
        if let Action::Begin { licence_key, .. } = &mut action { licence_key.clear(); }
        assert!(matches!(call(&mut c, &server, &caller, "caller", "192.0.2.1:2000", action).unwrap(), Reply::Error(_)));
        assert!(c.attempts.is_empty());
        let request = protocol::request("caller", begin("target")).unwrap();
        let signed = protocol::encode(&request, &caller).unwrap();
        c.handle(&signed, "192.0.2.1:2000".parse().unwrap(), &server, "admission").unwrap();
        assert!(c.handle(&signed, "192.0.2.1:2000".parse().unwrap(), &server, "admission").is_err());
        assert!(matches!(call(&mut c, &server, &caller, "caller", "192.0.2.1:2000", begin("target")).unwrap(), Reply::Error(_)));
        let session = c.attempts.keys().next().unwrap().clone();
        assert!(matches!(call(&mut c, &server, &caller, "caller", "192.0.2.1:2000", Action::Confirm { session: session.clone() }).unwrap(), Reply::Error(_)));
        call(&mut c, &server, &caller, "caller", "192.0.2.1:2000", Action::Cancel { session }).unwrap();
        assert!(c.attempts.is_empty());
        call(&mut c, &server, &caller, "caller", "192.0.2.1:2000", begin("target")).unwrap();
        c.expire(protocol::now().unwrap() + crate::ATTEMPT_SECONDS);
        assert!(c.attempts.is_empty());
    }

    #[test]
    fn tcp_observations_are_signed_session_scoped_bounded_and_filter_unverified_exits() {
        crate::init().unwrap();
        let mut c = Coordinator::default();
        let (_, server) = sign::gen_keypair();
        let caller = register(&mut c, "caller", "192.0.2.1", true);
        let target = register(&mut c, "target", "198.51.100.1", true);
        let outsider = register(&mut c, "outsider", "203.0.113.1", true);
        let Reply::Ticket(t) = call(&mut c, &server, &caller, "caller", "192.0.2.2:2000", begin("target")).unwrap() else { panic!() };
        let session = t.session;
        let observe = || Action::Observe { session: session.clone() };
        assert!(call(&mut c, &server, &target, "caller", "192.0.2.3:2000", observe()).is_err());
        assert!(matches!(call(&mut c, &server, &outsider, "outsider", "203.0.113.1:2000", observe()).unwrap(), Reply::Error(_)));
        assert!(call(&mut c, &server, &caller, "caller", "10.1.2.3:2000", observe()).is_err());
        for _ in 0..4 {
            assert!(matches!(call(&mut c, &server, &caller, "caller", "192.0.2.3:2000", observe()).unwrap(), Reply::Observed(_)));
        }
        assert!(matches!(call(&mut c, &server, &caller, "caller", "192.0.2.3:2000", observe()).unwrap(), Reply::Error(_)));
        let join = Action::Join { session: session.clone(), box_pk: box_::gen_keypair().0.as_ref().to_vec() };
        call(&mut c, &server, &target, "target", "198.51.100.1:2000", join).unwrap();
        let prepare = Action::Prepare { session: session.clone(), candidates: candidates(&["192.0.2.2:5000", "192.0.2.3:5001", "192.0.2.99:5002"]) };
        assert!(matches!(call(&mut c, &server, &caller, "caller", "192.0.2.2:2000", prepare).unwrap(), Reply::Waiting));
        let prepare = Action::Prepare { session: session.clone(), candidates: candidates(&["198.51.100.1:6000", "198.51.100.1:6000"]) };
        let Reply::Plan(first) = call(&mut c, &server, &target, "target", "198.51.100.1:2000", prepare).unwrap() else { panic!() };
        assert_eq!(first.peer.public.len(), 2);
        assert_eq!(first.behavior.mode, Mode::Birthday);
        let confirm = || Action::Confirm { session: session.clone() };
        assert!(matches!(call(&mut c, &server, &target, "target", "198.51.100.1:2000", confirm()).unwrap(), Reply::Error(_)));
        for _ in 0..3 {
            let Reply::Plan(p) = call(&mut c, &server, &caller, "caller", "192.0.2.2:2000", Action::Poll { session: session.clone() }).unwrap() else { panic!() };
            assert_eq!(p.behavior, first.behavior);
            assert_ne!(p.sender, first.sender);
        }
        assert!(matches!(call(&mut c, &server, &caller, "caller", "192.0.2.2:2000", confirm()).unwrap(), Reply::Closed));
        assert!(matches!(call(&mut c, &server, &caller, "caller", "192.0.2.2:2000", observe()).unwrap(), Reply::Error(_)));
        assert!(c.attempts.is_empty());
    }

    #[test]
    fn no_strategy_uses_signed_bounded_error_with_only_verified_candidates() {
        crate::init().unwrap();
        let mut c = Coordinator::default();
        let (_, server) = sign::gen_keypair();
        let caller = register(&mut c, "caller", "192.0.2.1", true);
        let target = register(&mut c, "target", "198.51.100.1", true);
        let Reply::Ticket(ticket) = call(&mut c, &server, &caller, "caller", "192.0.2.1:2000", begin("target")).unwrap() else { panic!() };
        assert_eq!(ticket.expires - protocol::now().unwrap(), 60);
        let id = ticket.session;
        call(&mut c, &server, &target, "target", "198.51.100.1:2000",
            Action::Join { session: id.clone(), box_pk: box_::gen_keypair().0.as_ref().to_vec() }).unwrap();
        for (device, key, source, values) in [
            ("caller", &caller, "192.0.2.1:2000", ["192.0.2.1:5000", "192.0.2.1:17000", "203.0.113.99:99"]),
            ("target", &target, "198.51.100.1:2000", ["198.51.100.1:9000", "198.51.100.1:33000", "203.0.113.99:99"]),
        ] {
            call(&mut c, &server, key, device, source, Action::Prepare { session: id.clone(), candidates: candidates(&values) }).unwrap();
        }
        let Reply::Error(error) = call(&mut c, &server, &caller, "caller", "192.0.2.1:2000", Action::Poll { session: id.clone() }).unwrap() else { panic!() };
        let reason = crate::progress::Reason::decode(&error).unwrap();
        assert_eq!(reason.code, "no_strategy");
        assert_eq!(reason.local.unwrap().public.len(), 2);
        assert!(!error.contains("203.0.113.99"));
        assert!(error.len() < 3072);
        assert!(!error.contains("secret"));
        call(&mut c, &server, &caller, "caller", "192.0.2.1:2000", Action::Cancel { session: id }).unwrap();
        assert!(c.attempts.is_empty());
        assert!(crate::progress::Reason::decode("old plain text reason").is_none());
    }
