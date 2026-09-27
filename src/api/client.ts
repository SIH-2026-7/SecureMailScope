export async function responseJson(response: Response) {
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
  return body;
}

export function uploadCapture(file: File, progress: (percent: number) => void): Promise<{job_id: string}> {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open('POST', '/api/upload');
    request.timeout = 120000;
    request.upload.onprogress = event => { if (event.lengthComputable) progress(Math.round(event.loaded / event.total * 100)); };
    request.onerror = () => reject(new Error('Cannot reach the analysis service. Start the FastAPI backend on port 8000.'));
    request.ontimeout = () => reject(new Error('Upload timed out. Please retry.'));
    request.onload = () => {
      let body;
      try { body = JSON.parse(request.responseText); } catch { reject(new Error('Analysis service unavailable. Start the FastAPI backend on port 8000.')); return; }
      if (request.status >= 200 && request.status < 300) resolve(body);
      else reject(new Error(body.detail || 'Capture upload failed.'));
    };
    const data = new FormData(); data.append('file', file); request.send(data);
  });
}

export const getAnalysis = (job: string, signal?: AbortSignal) => fetch(`/api/analysis/${encodeURIComponent(job)}`, {signal}).then(responseJson);
export type AnalysisHistoryEntry = {job_id: string; filename: string; status: string; created_at: string; capture_available: boolean};
export const getAnalysisHistory = (signal?: AbortSignal): Promise<{analyses: AnalysisHistoryEntry[]}> => fetch('/api/analysis', {signal}).then(responseJson);
export const captureUrl = (job: string) => `/api/analysis/${encodeURIComponent(job)}/capture`;
export const exportUrl = (job: string, format: string) => `/api/report/${encodeURIComponent(job)}/export?format=${format}`;
