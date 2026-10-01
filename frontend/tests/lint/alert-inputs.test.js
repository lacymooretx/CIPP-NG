import { describe, it, expect } from "vitest";
import alerts from "../../src/data/alerts.json";

// The alert wizard (pages/tenant/administration/alert-configuration/alert.jsx) renders and
// saves an alert's `inputs` list only when the entry is flagged `multipleInput: true`;
// without the flag it falls back to top-level inputType/inputName fields, so a list-only
// entry silently shows no inputs and saves none. Four fork alerts shipped that way.
describe("alerts.json input definitions", () => {
  it("flags every alert that defines an inputs list as multipleInput", () => {
    const broken = alerts
      .filter((a) => Array.isArray(a.inputs) && a.inputs.length > 0 && a.multipleInput !== true)
      .map((a) => a.name);
    expect(broken).toEqual([]);
  });

  it("gives every input of a multipleInput alert a type, label and name", () => {
    const incomplete = alerts
      .filter((a) => a.multipleInput)
      .flatMap((a) =>
        (a.inputs || [])
          .filter((i) => !i.inputType || !i.inputLabel || !i.inputName)
          .map((i) => `${a.name}:${i.inputName ?? "?"}`)
      );
    expect(incomplete).toEqual([]);
  });

  it("requires input on every alert that defines inputs", () => {
    const missing = alerts
      .filter((a) => Array.isArray(a.inputs) && a.inputs.length > 0 && a.requiresInput !== true)
      .map((a) => a.name);
    expect(missing).toEqual([]);
  });
});
