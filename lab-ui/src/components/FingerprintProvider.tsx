"use client";

import React, { createContext, useContext, useState, useEffect, useCallback, useMemo } from "react";

// ---------- Types ----------
export interface CipherInfo {
  value: number;
  name: string;
  position: number;
  is_grease?: boolean;
}

export interface ExtensionInfo {
  type: number;
  name: string;
  position: number;
  is_grease?: boolean;
}

export interface TLSFingerprint {
  version: number;
  version_name: string;
  cipher_suites: CipherInfo[];
  extensions: ExtensionInfo[];
  alpn?: string[];
  alps?: string;
  ja3_hash: string;
  ja3_string: string;
  ja4?: string;
  supported_groups?: number[];
  key_share_groups?: number[];
  raw_client_hello?: string;
}

export interface HTTP2Setting {
  id: number;
  name: string;
  value: number;
  position: number;
}

export interface HTTP2Fingerprint {
  settings: HTTP2Setting[];
  window_updates?: { stream_id: number; increment: number }[];
  pseudo_header_order: string[];
  header_order?: string[];
  frame_sequence?: { type: string; stream_id: number }[];
}

export interface HeaderInfo {
  name: string;
  value: string;
  position: number;
  is_pseudo?: boolean;
}

export interface ClientHints {
  sec_ch_ua?: string;
  sec_ch_ua_mobile?: string;
  sec_ch_ua_platform?: string;
}

export interface HTTPFingerprint {
  method: string;
  path: string;
  protocol: string;
  headers: HeaderInfo[];
  user_agent: string;
  accept: string;
  accept_language: string;
  accept_encoding: string;
  client_hints?: ClientHints;
  cookie_count: number;
}

export interface HTTPResponseFingerprint {
  status_code: number;
  status: string;
  protocol: string;
  headers: HeaderInfo[];
  body_length: number;
}

export interface CompleteFingerprint {
  id: string;
  timestamp: string;
  source_ip: string;
  server_name?: string;
  tls?: TLSFingerprint;
  http2?: HTTP2Fingerprint;
  http?: HTTPFingerprint;
  http_response?: HTTPResponseFingerprint;
  _modifications?: string[];
}

// ---------- Presets ----------
const platformPresets: Record<
  string,
  {
    name: string;
    tls: { version: string; ciphers: string[]; extensions: string[] };
    http2: {
      header_table_size: number;
      initial_window_size: number;
      max_concurrent_streams: number;
    };
  }
> = {
  windows: {
    name: "Windows 10/11",
    tls: {
      version: "1.3",
      ciphers: [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
      ],
      extensions: [
        "server_name",
        "extended_master_secret",
        "supported_groups",
        "ec_point_formats",
        "signature_algorithms",
        "application_layer_protocol_negotiation",
        "status_request",
        "signed_certificate_timestamp",
        "key_share",
        "supported_versions",
        "compress_certificate",
        "application_settings",
        "padding",
      ],
    },
    http2: { header_table_size: 65536, initial_window_size: 6291456, max_concurrent_streams: 1000 },
  },
  macos: {
    name: "macOS",
    tls: {
      version: "1.3",
      ciphers: [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      ],
      extensions: [
        "server_name",
        "extended_master_secret",
        "supported_groups",
        "application_layer_protocol_negotiation",
        "status_request",
        "signature_algorithms",
        "key_share",
        "supported_versions",
      ],
    },
    http2: { header_table_size: 65536, initial_window_size: 6291456, max_concurrent_streams: 100 },
  },
  linux: {
    name: "Linux",
    tls: {
      version: "1.3",
      ciphers: ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
      extensions: [
        "server_name",
        "supported_groups",
        "signature_algorithms",
        "application_layer_protocol_negotiation",
        "key_share",
        "supported_versions",
      ],
    },
    http2: { header_table_size: 4096, initial_window_size: 65535, max_concurrent_streams: 100 },
  },
};

const browserPresets: Record<
  string,
  {
    name: string;
    user_agent: string;
    headers: string[];
    client_hints: boolean;
  }
> = {
  chrome: {
    name: "Google Chrome",
    user_agent:
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
    headers: [
      "sec-ch-ua",
      "sec-ch-ua-mobile",
      "sec-ch-ua-platform",
      "upgrade-insecure-requests",
      "user-agent",
      "accept",
      "sec-fetch-site",
      "sec-fetch-mode",
      "sec-fetch-user",
      "sec-fetch-dest",
      "accept-encoding",
      "accept-language",
    ],
    client_hints: true,
  },
  firefox: {
    name: "Mozilla Firefox",
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0",
    headers: [
      "user-agent",
      "accept",
      "accept-language",
      "accept-encoding",
      "upgrade-insecure-requests",
      "sec-fetch-dest",
      "sec-fetch-mode",
      "sec-fetch-site",
      "sec-fetch-user",
      "te",
    ],
    client_hints: false,
  },
  safari: {
    name: "Apple Safari",
    user_agent:
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
    headers: ["user-agent", "accept", "accept-language", "accept-encoding"],
    client_hints: false,
  },
  edge: {
    name: "Microsoft Edge",
    user_agent:
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.1938.54",
    headers: [
      "sec-ch-ua",
      "sec-ch-ua-mobile",
      "sec-ch-ua-platform",
      "upgrade-insecure-requests",
      "user-agent",
      "accept",
      "sec-fetch-site",
      "sec-fetch-mode",
      "sec-fetch-user",
      "sec-fetch-dest",
      "accept-encoding",
      "accept-language",
    ],
    client_hints: true,
  },
};

// ---------- YAML Serializer ----------
function toYAML(obj: unknown, indent = 0): string {
  const pad = "  ".repeat(indent);
  if (obj === null || obj === undefined) return `${pad}null\n`;
  if (typeof obj === "string")
    return obj.includes("\n")
      ? `|\n${obj
          .split("\n")
          .map(l => `${pad}  ${l}`)
          .join("\n")}\n`
      : `"${obj}"\n`;
  if (typeof obj === "number" || typeof obj === "boolean") return `${obj}\n`;
  if (Array.isArray(obj)) {
    if (obj.length === 0) return "[]\n";
    return obj
      .map(item => {
        if (typeof item === "object" && item !== null) {
          const lines = toYAML(item, indent + 1)
            .trimEnd()
            .split("\n");
          return `${pad}- ${lines[0].trim()}\n${lines
            .slice(1)
            .map(l => `${pad}  ${l.trim() ? `  ${l.trim()}` : ""}\n`)
            .join("")}`;
        }
        return `${pad}- ${toYAML(item, 0).trim()}\n`;
      })
      .join("");
  }
  if (typeof obj === "object") {
    const entries = Object.entries(obj as Record<string, unknown>).filter(
      ([, v]) => v !== undefined && v !== null
    );
    if (entries.length === 0) return `${pad}{}\n`;
    return entries
      .map(([key, value]) => {
        if (typeof value === "object" && value !== null) {
          return `${pad}${key}:\n${toYAML(value, indent + 1)}`;
        }
        return `${pad}${key}: ${toYAML(value, 0).trim()}\n`;
      })
      .join("");
  }
  return `${obj}\n`;
}

function fingerprintToYAML(fp: CompleteFingerprint): string {
  const doc: Record<string, unknown> = {
    name: `captured_${fp.id}`,
    timestamp: fp.timestamp,
    source_ip: fp.source_ip,
  };

  if (fp.tls) {
    doc.tls = {
      version: fp.tls.version_name,
      ja3_hash: fp.tls.ja3_hash,
      ...(fp.tls.ja4 ? { ja4: fp.tls.ja4 } : {}),
      ...(fp.tls.alpn ? { alpn: fp.tls.alpn } : {}),
      ...(fp.tls.alps ? { alps: fp.tls.alps } : {}),
      cipher_suites: fp.tls.cipher_suites?.map(c => c.name) ?? [],
      extensions: fp.tls.extensions?.map(e => e.name) ?? [],
    };
  }

  if (fp.http2) {
    doc.http2 = {
      settings: Object.fromEntries(fp.http2.settings?.map(s => [s.name, s.value]) ?? []),
      pseudo_header_order: fp.http2.pseudo_header_order ?? [],
    };
  }

  if (fp.http) {
    doc.http = {
      method: fp.http.method,
      path: fp.http.path,
      protocol: fp.http.protocol,
      user_agent: fp.http.user_agent,
      header_count: fp.http.headers?.filter(h => !h.is_pseudo).length ?? 0,
    };
  }

  return toYAML(doc);
}

// ---------- Context Types ----------
interface FingerprintStateContextValue {
  fingerprint: CompleteFingerprint | null;
  originalFingerprint: CompleteFingerprint | null;
  loading: boolean;
  error: string | null;
  modifications: string[];
  jsonOutput: string;
  yamlOutput: string;
  selectedCaptureId: string | undefined;
  platformPresets: typeof platformPresets;
  browserPresets: typeof browserPresets;
  refresh: () => void;
  selectCapture: (id: string) => void;
  applyPlatformPreset: (key: string) => void;
  applyBrowserPreset: (key: string) => void;
  resetToOriginal: () => void;
}

// ---------- Contexts ----------
const FingerprintContext = createContext<FingerprintStateContextValue | null>(null);

// ---------- Public Hooks ----------
export function useFingerprint() {
  const ctx = useContext(FingerprintContext);
  if (!ctx) throw new Error("useFingerprint must be used within FingerprintProvider");
  return ctx;
}

export function useFingerprintRefresh() {
  const ctx = useContext(FingerprintContext);
  if (!ctx) throw new Error("useFingerprintRefresh must be used within FingerprintProvider");
  return ctx.refresh;
}

// ---------- Extracted Hooks ----------
function usePresets() {
  return useMemo(() => ({ platformPresets, browserPresets }), []);
}

function useFingerprintOutputs(fingerprint: CompleteFingerprint | null) {
  return useMemo(() => {
    if (!fingerprint) return { jsonOutput: "", yamlOutput: "" };
    try {
      return {
        jsonOutput: JSON.stringify(fingerprint, null, 2),
        yamlOutput: fingerprintToYAML(fingerprint),
      };
    } catch {
      return { jsonOutput: "// Error serializing JSON", yamlOutput: "# Error serializing YAML" };
    }
  }, [fingerprint]);
}

interface FetchFingerprintState {
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  setFingerprint: React.Dispatch<React.SetStateAction<CompleteFingerprint | null>>;
  setOriginalFingerprint: React.Dispatch<React.SetStateAction<CompleteFingerprint | null>>;
}

function useFetchFingerprint({
  setLoading,
  setError,
  setFingerprint,
  setOriginalFingerprint,
}: FetchFingerprintState) {
  return useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/capture/json");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setFingerprint(data);
      setOriginalFingerprint(JSON.parse(JSON.stringify(data)));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  }, [setLoading, setError, setFingerprint, setOriginalFingerprint]);
}

interface SelectCaptureState {
  selectedCaptureId: string | undefined;
  setSelectedCaptureId: React.Dispatch<React.SetStateAction<string | undefined>>;
  fetchFingerprint: () => Promise<void>;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  setFingerprint: React.Dispatch<React.SetStateAction<CompleteFingerprint | null>>;
  setOriginalFingerprint: React.Dispatch<React.SetStateAction<CompleteFingerprint | null>>;
}

function useSelectCapture({
  selectedCaptureId,
  setSelectedCaptureId,
  fetchFingerprint,
  setLoading,
  setError,
  setFingerprint,
  setOriginalFingerprint,
}: SelectCaptureState) {
  return useCallback(
    async (id: string) => {
      if (selectedCaptureId === id) {
        setSelectedCaptureId(undefined);
        fetchFingerprint();
        return;
      }
      setSelectedCaptureId(id);
      setLoading(true);
      setError(null);
      try {
        const res = await fetch(`/captures/${id}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        setFingerprint(data);
        setOriginalFingerprint(JSON.parse(JSON.stringify(data)));
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load capture");
      } finally {
        setLoading(false);
      }
    },
    [
      selectedCaptureId,
      setSelectedCaptureId,
      fetchFingerprint,
      setLoading,
      setError,
      setFingerprint,
      setOriginalFingerprint,
    ]
  );
}

interface FingerprintDataState {
  fingerprint: CompleteFingerprint | null;
  originalFingerprint: CompleteFingerprint | null;
  loading: boolean;
  error: string | null;
  selectedCaptureId: string | undefined;
  fetchFingerprint: () => void;
  selectCapture: (id: string) => void;
  setFingerprint: React.Dispatch<React.SetStateAction<CompleteFingerprint | null>>;
}

function useFingerprintData(): FingerprintDataState {
  const [fingerprint, setFingerprint] = useState<CompleteFingerprint | null>(null);
  const [originalFingerprint, setOriginalFingerprint] = useState<CompleteFingerprint | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedCaptureId, setSelectedCaptureId] = useState<string | undefined>(undefined);

  const fetchFingerprint = useFetchFingerprint({
    setLoading,
    setError,
    setFingerprint,
    setOriginalFingerprint,
  });

  useEffect(() => {
    fetchFingerprint();
  }, [fetchFingerprint]);

  const selectCapture = useSelectCapture({
    selectedCaptureId,
    setSelectedCaptureId,
    fetchFingerprint,
    setLoading,
    setError,
    setFingerprint,
    setOriginalFingerprint,
  });

  return {
    fingerprint,
    originalFingerprint,
    loading,
    error,
    selectedCaptureId,
    fetchFingerprint,
    selectCapture,
    setFingerprint,
  };
}

interface FingerprintModifiersConfig {
  fingerprint: CompleteFingerprint | null;
  originalFingerprint: CompleteFingerprint | null;
  setFingerprint: React.Dispatch<React.SetStateAction<CompleteFingerprint | null>>;
}

interface FingerprintModifiersState {
  modifications: string[];
  applyPlatformPreset: (key: string) => void;
  applyBrowserPreset: (key: string) => void;
  resetToOriginal: () => void;
}

interface ApplyPresetConfig {
  preset: (typeof platformPresets)[string];
  updated: CompleteFingerprint;
}

function applyPlatformPresetToFingerprint({ preset, updated }: ApplyPresetConfig): void {
  if (updated.tls) {
    updated.tls.version_name = preset.tls.version;
    updated.tls.cipher_suites = preset.tls.ciphers.map((name, i) => ({
      name,
      value: 0,
      position: i + 1,
      is_grease: false,
    }));
    updated.tls.extensions = preset.tls.extensions.map((name, i) => ({
      name,
      type: 0,
      position: i + 1,
      is_grease: false,
    }));
  }
  if (updated.http2) {
    updated.http2.settings = [
      { id: 1, name: "HEADER_TABLE_SIZE", value: preset.http2.header_table_size, position: 1 },
      { id: 2, name: "ENABLE_PUSH", value: 0, position: 2 },
      {
        id: 3,
        name: "MAX_CONCURRENT_STREAMS",
        value: preset.http2.max_concurrent_streams,
        position: 3,
      },
      {
        id: 4,
        name: "INITIAL_WINDOW_SIZE",
        value: preset.http2.initial_window_size,
        position: 4,
      },
    ];
  }
}

interface ApplyBrowserPresetConfig {
  preset: (typeof browserPresets)[string];
  updated: CompleteFingerprint;
}

function applyBrowserPresetToFingerprint({ preset, updated }: ApplyBrowserPresetConfig): void {
  if (updated.http) {
    updated.http.user_agent = preset.user_agent;
    updated.http.headers = preset.headers.map((name, i) => ({
      name,
      value: "",
      position: i + 1,
      is_pseudo: name.startsWith(":"),
    }));
    if (preset.client_hints) {
      updated.http.client_hints = {
        sec_ch_ua: '"Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"',
        sec_ch_ua_mobile: "?0",
        sec_ch_ua_platform: '"Windows"',
      };
    } else {
      updated.http.client_hints = undefined;
    }
  }
}

function useFingerprintModifiers({
  fingerprint,
  originalFingerprint,
  setFingerprint,
}: FingerprintModifiersConfig): FingerprintModifiersState {
  const [modifications, setModifications] = useState<string[]>([]);

  const applyPlatformPreset = useCallback(
    (key: string) => {
      if (!fingerprint) return;
      const preset = platformPresets[key];
      if (!preset) return;

      const updated = JSON.parse(JSON.stringify(fingerprint));
      applyPlatformPresetToFingerprint({ preset, updated });
      setFingerprint(updated);
      setModifications(prev => [...prev, `Platform: ${preset.name}`]);
    },
    [fingerprint, setFingerprint]
  );

  const applyBrowserPreset = useCallback(
    (key: string) => {
      if (!fingerprint) return;
      const preset = browserPresets[key];
      if (!preset) return;

      const updated = JSON.parse(JSON.stringify(fingerprint));
      applyBrowserPresetToFingerprint({ preset, updated });
      setFingerprint(updated);
      setModifications(prev => [...prev, `Browser: ${preset.name}`]);
    },
    [fingerprint, setFingerprint]
  );

  const resetToOriginal = useCallback(() => {
    if (originalFingerprint) {
      setFingerprint(JSON.parse(JSON.stringify(originalFingerprint)));
      setModifications([]);
    }
  }, [originalFingerprint, setFingerprint]);

  return { modifications, applyPlatformPreset, applyBrowserPreset, resetToOriginal };
}

// ---------- Context Providers Setup ----------
interface CreateStateValueConfig {
  data: ReturnType<typeof useFingerprintData>;
  modifiers: ReturnType<typeof useFingerprintModifiers>;
  outputs: ReturnType<typeof useFingerprintOutputs>;
  presets: ReturnType<typeof usePresets>;
}

function createStateValue({
  data,
  modifiers,
  outputs,
  presets,
}: CreateStateValueConfig): FingerprintStateContextValue {
  return {
    fingerprint: data.fingerprint,
    originalFingerprint: data.originalFingerprint,
    loading: data.loading,
    error: data.error,
    modifications: modifiers.modifications,
    jsonOutput: outputs.jsonOutput,
    yamlOutput: outputs.yamlOutput,
    selectedCaptureId: data.selectedCaptureId,
    platformPresets: presets.platformPresets,
    browserPresets: presets.browserPresets,
    refresh: data.fetchFingerprint,
    selectCapture: data.selectCapture,
    applyPlatformPreset: modifiers.applyPlatformPreset,
    applyBrowserPreset: modifiers.applyBrowserPreset,
    resetToOriginal: modifiers.resetToOriginal,
  };
}

interface FingerprintContextsProps {
  children: React.ReactNode;
  state: FingerprintStateContextValue;
}

function FingerprintContexts({ children, state }: FingerprintContextsProps) {
  return <FingerprintContext.Provider value={state}>{children}</FingerprintContext.Provider>;
}

// ---------- Provider Component ----------
export function FingerprintProvider({ children }: { children: React.ReactNode }) {
  const data = useFingerprintData();
  const presets = usePresets();
  const modifiers = useFingerprintModifiers({
    fingerprint: data.fingerprint,
    originalFingerprint: data.originalFingerprint,
    setFingerprint: data.setFingerprint,
  });
  const outputs = useFingerprintOutputs(data.fingerprint);

  const state = useMemo(
    () => createStateValue({ data, modifiers, outputs, presets }),
    [data, modifiers, outputs, presets]
  );

  return <FingerprintContexts state={state}>{children}</FingerprintContexts>;
}
