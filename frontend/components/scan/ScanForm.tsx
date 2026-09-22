"use client";

import { useState, type FormEvent } from "react";

import type { ScanModality } from "@/types/scan-result";
import type { ScanSubmissionDraft } from "@/types/scan-submission";

import { FileScanInput } from "./FileScanInput";
import { ScanTypeSelector } from "./ScanTypeSelector";
import { TextScanInput } from "./TextScanInput";
import { UrlScanInput } from "./UrlScanInput";

type FileModality = Exclude<ScanModality, "text" | "url">;

const mimePrefixes: Record<FileModality, string> = {
  image: "image/",
  audio: "audio/",
  video: "video/",
};

function isValidUrlOrDomain(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{1,5})?(?:[/?#].*)?$/i.test(
      value,
    );
  }
}

function buildDraft(
  modality: ScanModality,
  text: string,
  url: string,
  file: File | null,
): ScanSubmissionDraft | string {
  if (modality === "text") {
    return text.trim() ? { modality, content: text.trim() } : "Enter text to analyze.";
  }

  if (modality === "url") {
    const value = url.trim();
    return value && isValidUrlOrDomain(value)
      ? { modality, content: value }
      : "Enter a valid HTTP(S) URL or domain.";
  }

  if (!file) {
    return `Select a ${modality} file before starting a scan.`;
  }

  if (!file.type.startsWith(mimePrefixes[modality])) {
    return `Select a valid ${modality} file.`;
  }

  return { modality, file };
}

export function ScanForm() {
  const [modality, setModality] = useState<ScanModality>("text");
  const [text, setText] = useState("");
  const [url, setUrl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submissionNotice, setSubmissionNotice] = useState<string | null>(null);

  function handleModalityChange(nextModality: ScanModality) {
    setModality(nextModality);
    setFile(null);
    clearFeedback();
  }

  function clearFeedback() {
    setError(null);
    setSubmissionNotice(null);
  }

  function handleTextChange(value: string) {
    setText(value);
    clearFeedback();
  }

  function handleUrlChange(value: string) {
    setUrl(value);
    clearFeedback();
  }

  function handleFileChange(nextFile: File | null) {
    setFile(nextFile);
    clearFeedback();
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const draft = buildDraft(modality, text, url, file);

    if (typeof draft === "string") {
      setError(draft);
      setSubmissionNotice(null);
      return;
    }

    setError(null);
    setSubmissionNotice(
      "Module 1 scan submission is not configured yet. Your input has not been sent or analyzed.",
    );
  }

  const inputError = submissionNotice ? undefined : error ?? undefined;

  return (
    <form onSubmit={handleSubmit} className="mx-auto max-w-4xl space-y-8">
      <div>
        <h2 className="text-2xl font-semibold tracking-tight text-slate-950">New Scan</h2>
        <p className="mt-2 text-sm text-slate-600">
          Select an input type and provide content for future TruthLensAI analysis.
        </p>
      </div>

      <ScanTypeSelector value={modality} onChange={handleModalityChange} />

      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm sm:p-6">
        {modality === "text" ? (
          <TextScanInput value={text} onChange={handleTextChange} error={inputError} />
        ) : null}
        {modality === "url" ? (
          <UrlScanInput value={url} onChange={handleUrlChange} error={inputError} />
        ) : null}
        {modality === "image" || modality === "audio" || modality === "video" ? (
          <FileScanInput
            modality={modality}
            file={file}
            onChange={handleFileChange}
            error={inputError}
          />
        ) : null}
      </div>

      {submissionNotice ? (
        <p className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900" role="status">
          {submissionNotice}
        </p>
      ) : null}

      <button
        type="submit"
        className="rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-cyan-700 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:ring-offset-2"
      >
        Start scan
      </button>
    </form>
  );
}
