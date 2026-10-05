/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

#![allow(dead_code)]
use hibiki_lib::{channel::*, identity::Identity, invitation::AdmissionRequest, random_id};

pub fn root() -> (Identity, MembershipProof) {
    let a = Identity::generate("A".into()).unwrap();
    let genesis = ChannelGenesis::create(&a, random_id(), "work".into()).unwrap();
    (
        a,
        MembershipProof {
            genesis,
            events: vec![],
        },
    )
}

pub fn append(p: &mut MembershipProof, issuer: &Identity, action: MembershipAction) {
    let e = MembershipEvent::create(issuer, &p.verify().unwrap(), action).unwrap();
    p.events.push(e);
    p.verify().unwrap();
}

pub fn admit(p: &mut MembershipProof, issuer: &Identity, subject: &Identity) -> AdmissionRequest {
    let request = AdmissionRequest::create(subject, &p.verify().unwrap(), random_id(), 0).unwrap();
    append(p, issuer, MembershipAction::Accept(request.clone()));
    request
}
