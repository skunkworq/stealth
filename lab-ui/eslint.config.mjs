import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";
import eslintPluginPrettier from "eslint-plugin-prettier/recommended";

/**
 * Comprehensive ESLint Configuration
 * 
 * This configuration combines:
 * - Next.js Core Web Vitals rules (performance-focused)
 * - Next.js TypeScript rules
 * - Prettier integration for code formatting
 */

const eslintConfig = defineConfig([
  // Base Next.js configurations
  ...nextVitals,
  ...nextTs,
  
  // Prettier integration (must be last to override other formatting rules)
  eslintPluginPrettier,
  
  // Global ignores - files to exclude from linting
  globalIgnores([
    // Build outputs
    ".next/**",
    "out/**",
    "build/**",
    
    // Generated files
    "next-env.d.ts",
    "*.config.{mjs,ts,js}",
    
    // Dependencies
    "node_modules/**",
    
    // Test coverage
    "coverage/**",
  ]),
  
  // AI Guardrails: Rules to make AI code more readable and maintainable
  // Based on: https://medium.com/@albro/eslint-as-ai-guardrails-the-rules-that-make-ai-code-readable-8899c71d3446
  {
    files: ["**/*.{ts,tsx}"],
    rules: {
      // TypeScript-specific rules (no type info required)
      "@typescript-eslint/no-unused-vars": ["error", { 
        argsIgnorePattern: "^_",
        varsIgnorePattern: "^_",
        caughtErrorsIgnorePattern: "^_"
      }],
      "@typescript-eslint/no-explicit-any": "warn",
      
      // React-specific rules
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
      "react/no-array-index-key": "warn",
      "react/self-closing-comp": "error",
      
      // General best practices
      "no-console": ["warn", { allow: ["error", "warn"] }],
      "no-debugger": "error",
      "prefer-const": "error",
      "no-var": "error",
      "object-shorthand": "error",
      "prefer-template": "error",
      
      // AI GUARDRAILS - Complexity & Readability
      // Limit function parameters (max 2) - forces use of config objects
      "max-params": ["error", 2],
      
      // Limit function size (max 50 lines) - encourages single responsibility
      "max-lines-per-function": ["error", { 
        max: 50,
        skipBlankLines: true,
        skipComments: true 
      }],
      
      // Limit file size (max 250 lines) - encourages modular architecture
      "max-lines": ["error", { 
        max: 250,
        skipBlankLines: true,
        skipComments: true 
      }],
      
      // No magic numbers - forces named constants for readability
      "no-magic-numbers": ["error", { 
        ignore: [-1, 0, 1, 2],
        ignoreArrayIndexes: true,
        enforceConst: true,
        detectObjects: false
      }],
      
      // Discourage comments - forces self-documenting code
      // Note: JSDoc/TSDoc comments are still allowed via 'allow` option
      "no-inline-comments": "error",
      "multiline-comment-style": ["error", "starred-block"],
    },
  },
  
  // Relaxed rules for test files - allow longer functions and more parameters in tests
  {
    files: ["**/*.test.{ts,tsx}", "**/*.spec.{ts,tsx}", "**/test/**"],
    rules: {
      "no-console": "off",
      "@typescript-eslint/no-explicit-any": "off",
      "max-lines-per-function": "off",
      "max-lines": "off",
      "max-params": "off",
      "no-magic-numbers": "off",
      "no-inline-comments": "off",
    },
  },
  
  // Relaxed rules for existing complex components that would require major refactoring
  // These components should be refactored over time to meet the stricter standards
  {
    files: [
      "**/components/BuildOutput.tsx",
      "**/components/CaptchaDashboard.tsx",
      "**/components/CaptchaTraceVisualizer.tsx",
      "**/components/CaptchaTrainer.tsx",
      "**/components/CaptureHistory.tsx",
      "**/components/ConfigPanel.tsx",
      "**/components/ControlPanel.tsx",
      "**/components/FingerprintComparison.tsx",
      "**/components/FingerprintProvider.tsx",
      "**/components/FingerprintViewer.tsx",
      "**/components/HTTP2Panel.tsx",
      "**/components/HTTPPanel.tsx",
      "**/components/ManualCaptchaSolver.tsx",
      "**/components/OverviewCard.tsx",
      "**/components/PacketAnalysisPanel.tsx",
      "**/components/SignatureTester.tsx",
      "**/components/TLSPanel.tsx",
      "**/components/TraceTimeline.tsx",
      "**/components/TrainingDataBrowser.tsx",
      "**/hooks/useTrainingData.ts",
      "**/hooks/useWebSocket.ts",
      "**/app/page.tsx",
    ],
    rules: {
      // Gradual adoption: allow larger existing files but still encourage good practices
      "max-lines-per-function": "warn",
      "max-lines": "warn",
      "max-params": "warn",
    },
  },
]);

export default eslintConfig;
