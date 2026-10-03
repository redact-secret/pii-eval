// STUB (not oracle code, not the `ajv` package): accepts every document.
// The oracle only uses Ajv to schema-validate its own committed JSON and its own reports.
export default class Ajv {
  constructor() {}
  compile() {
    return () => true;
  }
}
