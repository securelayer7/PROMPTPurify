import { defineConfig } from "tsup";

export default defineConfig([
  {
    // Bundler / node consumers: ESM + CJS + types.
    // ./l5 is a separate subpath so the core stays model-free; the browser
    // IIFE below intentionally does NOT include it.
    entry: { index: "src/index.ts", "l5/index": "src/l5/index.ts" },
    format: ["esm", "cjs"],
    dts: true,
    clean: true,
    sourcemap: true,
    treeshake: true,
    target: "es2022",
    // Core is zero runtime deps. The ONLY external is the OPTIONAL peer
    // onnxruntime-node, dynamically imported by ./l5 (L5b). It is never a
    // hard dependency and never enters the core/browser bundle.
    external: ["onnxruntime-node"],
  },
  {
    // Browser drop-in, exactly like DOMPurify's dist/purify.min.js:
    //   <script src="promptpurify.browser.min.js"></script>
    //   PromptPurify.promptpurify.sanitize(userInput)
    entry: { "promptpurify.browser": "src/index.ts" },
    format: ["iife"],
    globalName: "PromptPurify",
    dts: false,
    clean: false,
    sourcemap: true,
    minify: true,
    treeshake: true,
    target: "es2018",
    platform: "browser",
  },
]);
