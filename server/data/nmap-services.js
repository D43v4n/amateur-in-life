// data/nmap-services.js — Fallback service/frequency data for ports not in
// the curated Blue Team database (data/ports.js).
//
// Derived from the Nmap Project's `nmap-services` database:
//   https://github.com/nmap/nmap/blob/master/nmap-services
// Copyright (c) 1996-2025 by Nmap Software LLC / Insecure.Com LLC.
// Licensed under the Nmap Public Source License (NPSL) v0.95 — see /LICENSE
// at the repo root. Because BlueWatch reads this data file, the whole
// project is distributed under the NPSL (NPSL §3, "Derivative Works").
//
// `frequency` is the probability (0-1) that Nmap's global scan research
// observed this port/service combination open on a random host. It is a
// rough "how common is this in the wild" signal for the operator to weigh
// during business-justification review — not a curated security verdict.
// Only the highest-frequency entry per port/proto is kept.

const NMAP_SERVICES = require('./nmap-services.json');

module.exports = NMAP_SERVICES;
