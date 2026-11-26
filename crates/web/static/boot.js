import init from "./pkg/bunkr_web.js";
init({ module_or_path: new URL("./pkg/bunkr_web_bg.wasm", import.meta.url) });
