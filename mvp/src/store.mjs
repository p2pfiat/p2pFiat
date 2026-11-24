//! Crash-safe JSON file store (write-to-temp + rename).

import fs from "node:fs";
import path from "node:path";

export class JsonStore {
  constructor(filePath, defaultData = {}) {
    this.filePath = filePath;
    this.defaultData = defaultData;
  }

  read() {
    if (!fs.existsSync(this.filePath)) {
      return structuredClone(this.defaultData);
    }
    return JSON.parse(fs.readFileSync(this.filePath, "utf8"));
  }

  write(data) {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
    fs.renameSync(tmp, this.filePath);
  }

  update(fn) {
    const data = this.read();
    const res = fn(data);
    this.write(data);
    return res;
  }
}
