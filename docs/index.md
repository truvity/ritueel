---
title: "ritueel: root keys and root transitions"
description: ritueel keeps the roots of trust. It creates, vouches for, overlaps, supersedes and revokes X.509 and OpenPGP roots. Open source and taught in the open.
template: splash
hero:
  tagline: Keep the roots of trust, and move them without breaking anyone.
  actions:
    - text: Learn the model
      link: /concepts/
      icon: right-arrow
    - text: View on GitHub
      link: https://github.com/truvity/ritueel
      icon: external
      variant: minimal
---

## What it is

A chain of trust has a few keys that almost never change, the roots, and many that do, the intermediates. ritueel is for the roots: the X.509 CA roots and OpenPGP primary keys that other keys depend on. It creates them, vouches for the next one, overlaps the old and the new, supersedes, revokes, and runs the ceremonies where a person is present, in a few commands or with a guided wizard.

ritueel is also a teaching product. The pages explain the model first, then the tools carry it out.

## Status

ritueel is in the **design phase**. There is no release yet. The scope is recorded in [ADR 0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/), the [concepts](/concepts/) are written, and the [roadmap](/roadmap/) lists the milestones of the first version. The first version supports three key stores: software, YubiKey and AWS KMS.

ritueel is a separate product from [sluis](https://sluis.id), which holds intermediates and signs online. The two do not depend on each other and exchange standard formats only.

How to take part is in [Contributing](/contributing/).
