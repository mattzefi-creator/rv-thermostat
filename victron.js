// Victron SmartSolar "Instant Readout" over Bluetooth advertisements.
// Shared by solar.html (full view) and battery.html (solar and RV-use numbers).
//
// Format: Victron's published "extra manufacturer data" document, as implemented and tested in
// victron-ble (github.com/keshavdv/victron-ble). Manufacturer data for company 0x02E1:
//   [prefix u16 LE] [model u16 LE] [record type u8] [iv u16 LE] [key check u8] [AES-CTR encrypted ...]
// The key is the 32-character "encryption key" shown in VictronConnect under Instant readout details.
// Nothing connects to the controllers, so VictronConnect keeps working alongside this.
(function (global) {
  'use strict';
  const COMPANY = 0x02e1;
  const TYPE_SOLAR = 0x01;

  const STATES = {
    0: 'Off', 1: 'Low power', 2: 'Fault', 3: 'Bulk', 4: 'Absorption', 5: 'Float', 6: 'Storage',
    7: 'Equalize', 245: 'Starting up', 246: 'Repeated absorption', 247: 'Recondition',
    248: 'Battery safe', 252: 'External control',
  };
  const ERRORS = {
    1: 'Battery too hot', 2: 'Battery voltage too high', 3: 'Remote temperature sensor failure',
    4: 'Remote temperature sensor failure', 5: 'Remote temperature sensor failure',
    6: 'Remote voltage sense failure', 7: 'Remote voltage sense failure', 8: 'Remote voltage sense failure',
    11: 'Battery high ripple voltage', 14: 'Battery too cold to charge', 17: 'Charger too hot',
    18: 'Charger over current', 20: 'Bulk time limit exceeded', 21: 'Current sensor issue',
    22: 'Internal temperature sensor failure', 23: 'Internal temperature sensor failure', 24: 'Fan failure',
    26: 'Terminals overheated', 27: 'Charger short circuit', 28: 'Power stage issue', 29: 'Over-charge protection',
    33: 'Solar panel voltage too high', 34: 'Solar panel current too high', 35: 'Solar panel over-power',
    38: 'Input shut down (battery voltage too high)', 39: 'Input shut down (current while off)',
    40: 'Solar input failed to shut down', 65: 'Lost communication with a device', 66: 'Synchronized charging setup issue',
    67: 'BMS connection lost', 68: 'Network misconfigured', 69: 'Network misconfigured', 70: 'Network misconfigured',
    71: 'Network misconfigured', 114: 'Charger CPU too hot', 116: 'Calibration data lost', 117: 'Incompatible firmware',
    119: 'Settings lost',
  };

  const hexToBytes = h => Uint8Array.from((h.match(/../g) || []), x => parseInt(x, 16));
  const cleanKey = k => String(k || '').toLowerCase().replace(/[^0-9a-f]/g, '');
  const validKey = k => cleanKey(k).length === 32;

  // AES-CTR with a little-endian counter that starts at the advertised IV. Each 16-byte block is
  // decrypted on its own with its own counter block, so the browser's big-endian increment never applies.
  async function decrypt(adv, keyHex) {
    const key = hexToBytes(cleanKey(keyHex));
    if (adv.length < 9) throw new Error('Advertisement too short');
    if (adv[7] !== key[0]) throw new Error('Wrong encryption key');
    const iv = adv[5] | (adv[6] << 8);
    const data = adv.subarray(8);
    const k = await crypto.subtle.importKey('raw', key, 'AES-CTR', false, ['decrypt']);
    const out = new Uint8Array(data.length);
    for (let off = 0, blk = 0; off < data.length; off += 16, blk++) {
      const ctr = new Uint8Array(16);
      let v = iv + blk;
      for (let i = 0; i < 16 && v; i++) { ctr[i] = v & 0xff; v = Math.floor(v / 256); }
      const pt = await crypto.subtle.decrypt({ name: 'AES-CTR', counter: ctr, length: 64 }, k, data.subarray(off, off + 16));
      out.set(new Uint8Array(pt), off);
    }
    return out;
  }

  const s16 = (d, i) => { const v = d[i] | (d[i + 1] << 8); return v & 0x8000 ? v - 0x10000 : v; };
  const u16 = (d, i) => d[i] | (d[i + 1] << 8);

  function parseSolar(d) {
    if (d.length < 10) throw new Error('Solar data too short');
    const state = d[0], err = d[1], v = s16(d, 2), a = s16(d, 4), y = u16(d, 6), pv = u16(d, 8);
    const load = d.length >= 12 ? d[10] | ((d[11] & 1) << 8) : 0x1ff;
    return {
      state: state === 0xff ? null : state,
      stateText: state === 0xff ? 'Unknown' : (STATES[state] || 'State ' + state),
      error: err === 0xff ? null : err,
      errorText: err && err !== 0xff ? (ERRORS[err] || 'Error ' + err) : '',
      batteryV: v === 0x7fff ? null : v / 100,
      chargeA: a === 0x7fff ? null : a / 10,
      yieldWh: y === 0xffff ? null : y * 10,
      solarW: pv === 0xffff ? null : pv,
      loadA: load === 0x1ff ? null : load / 10,
    };
  }

  // Decode one advertisement. Returns a reading, or { type } for Victron devices that aren't solar chargers.
  async function decode(adv, keyHex) {
    const type = adv[4], model = u16(adv, 2);
    if (type !== TYPE_SOLAR) return { type, model, unsupported: true };
    return { type, model, ...parseSolar(await decrypt(adv, keyHex)) };
  }

  // ---------- Saved controllers and live readings ----------
  const store = (k, v) => { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch (e) {} };
  const load = k => { try { return localStorage.getItem(k) || ''; } catch (e) { return ''; } };
  const controllers = () => { try { return JSON.parse(load('vc_ctrls') || '[]'); } catch (e) { return []; } };
  const saveControllers = list => store('vc_ctrls', JSON.stringify(list));
  const lastReadings = () => { try { return JSON.parse(load('vc_last') || '{}'); } catch (e) { return {}; } };
  const FRESH_MS = 2 * 60e3;

  // Sum the fresh readings: solar watts, charger output to the battery, and today's yield.
  function totals(readings = lastReadings()) {
    const now = Date.now();
    const live = controllers().map(c => readings[c.id]).filter(r => r && !r.unsupported && now - r.at < FRESH_MS);
    if (!live.length) return null;
    const sum = f => live.reduce((t, r) => t + (f(r) || 0), 0);
    return {
      count: live.length,
      solarW: sum(r => r.solarW),
      outW: sum(r => (r.chargeA || 0) * (r.batteryV || 0)),
      yieldWh: sum(r => r.yieldWh),
      at: Math.max(...live.map(r => r.at)),
    };
  }

  const supported = () => 'bluetooth' in navigator && !!global.BluetoothDevice && 'watchAdvertisements' in global.BluetoothDevice.prototype;

  // Pick a controller once; the browser remembers it so watching can start later without a tap.
  async function pick(showAll) {
    return navigator.bluetooth.requestDevice(showAll
      ? { acceptAllDevices: true, optionalManufacturerData: [COMPANY] }
      : { filters: [{ manufacturerData: [{ companyIdentifier: COMPANY }] }], optionalManufacturerData: [COMPANY] });
  }

  // Listen to every saved controller. onReading(id, reading) runs for each decoded broadcast.
  function watch(onReading, log = () => {}) {
    const ac = new AbortController();
    const seen = {};
    (async () => {
      if (!supported()) { log('This browser cannot read Bluetooth broadcasts'); return; }
      let devices = [];
      try { devices = navigator.bluetooth.getDevices ? await navigator.bluetooth.getDevices() : []; } catch (e) { log('getDevices failed: ' + e.message); }
      for (const c of controllers()) {
        const d = devices.find(x => x.id === c.id);
        if (!d) { log('Controller "' + c.name + '" not remembered by the browser. Add it again.'); continue; }
        d.addEventListener('advertisementreceived', async e => {
          const md = e.manufacturerData && e.manufacturerData.get(COMPANY);
          if (!md) return;
          const adv = new Uint8Array(md.buffer, md.byteOffset, md.byteLength);
          // Victron repeats the same broadcast until the data changes; the IV changes with it.
          const sig = adv[5] + ',' + adv[6];
          if (seen[c.id] === sig) { onReading(c.id, null, e.rssi); return; }
          seen[c.id] = sig;
          try {
            const r = await decode(adv, c.key);
            r.at = Date.now(); r.rssi = e.rssi;
            const all = lastReadings(); all[c.id] = r; store('vc_last', JSON.stringify(all));
            onReading(c.id, r);
          } catch (err) {
            onReading(c.id, { error: true, message: err.message, at: Date.now() });
          }
        }, { signal: ac.signal });
        try { await d.watchAdvertisements({ signal: ac.signal }); log('Listening to ' + c.name); }
        catch (e) { log('Could not listen to ' + c.name + ': ' + e.message); onReading(c.id, { error: true, message: e.message, at: Date.now() }); }
      }
    })();
    return () => ac.abort();
  }

  global.Victron = { COMPANY, decode, decrypt, parseSolar, validKey, cleanKey, controllers, saveControllers, lastReadings, totals, supported, pick, watch, FRESH_MS };
  if (typeof module !== 'undefined') module.exports = global.Victron;
})(typeof window !== 'undefined' ? window : globalThis);
