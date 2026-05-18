// SPDX-License-Identifier: AGPL-3.0-or-later
// Exports the Crate class — the programmatic / ESM surface other NakliTechie
// tools (Folio, Slate, Bahi, Mahalla, …) bind to. The shape is locked at M5;
// today, M0, the methods throw "not implemented".

export class Crate {
  static async open(_config) {
    throw new Error("Crate.open: not implemented (M0 skeleton)");
  }

  async list(_path) { throw new Error("Crate.list: not implemented (M0 skeleton)"); }
  async read(_path) { throw new Error("Crate.read: not implemented (M0 skeleton)"); }
  async write(_path, _blob) { throw new Error("Crate.write: not implemented (M0 skeleton)"); }
  async remove(_path) { throw new Error("Crate.remove: not implemented (M0 skeleton)"); }
  async move(_from, _to) { throw new Error("Crate.move: not implemented (M0 skeleton)"); }
  async mkdir(_path) { throw new Error("Crate.mkdir: not implemented (M0 skeleton)"); }
  async stat(_path) { throw new Error("Crate.stat: not implemented (M0 skeleton)"); }
  async history(_path) { throw new Error("Crate.history: not implemented (M0 skeleton)"); }
  onChange(_handler) { throw new Error("Crate.onChange: not implemented (M0 skeleton)"); }
}
